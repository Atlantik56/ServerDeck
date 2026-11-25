"""TLS for panel connections authenticated independently over trusted SSH.

Normal certificate validation is preferred. An expired upstream certificate
can be used only when its exact leaf DER matches the certificate read over SSH.
No HTTP request or credentials are sent before that check. Public browser TLS
is not affected by this internal connection policy.
"""
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import ssl
import subprocess


def _valid_panel_dns_name(name):
    if not isinstance(name, str) or not name or len(name) > 253 or name.replace('.', '').isdigit():
        return False
    label = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?')
    return all(label.fullmatch(part) for part in name.split('.'))


def _local_panel_address(hostname):
    if not isinstance(hostname, str):
        return None
    try:
        address = str(ipaddress.ip_address(hostname))
        result = subprocess.run(
            ['ip', '-j', 'route', 'get', address],
            capture_output=True, text=True, check=True, timeout=3,
        )
        routes = json.loads(result.stdout)
    except (ValueError, OSError, subprocess.SubprocessError):
        return None
    if isinstance(routes, list) and routes and isinstance(routes[0], dict) and routes[0].get('type') == 'local':
        return address
    return None


class _PanelSNIConnection(http.client.HTTPSConnection):
    def __init__(self,host,port,*,context,timeout,server_name):
        super().__init__(host,port,context=context,timeout=timeout)
        self._panel_server_name=server_name

    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock=self._context.wrap_socket(self.sock,server_hostname=self._panel_server_name)


def _open_panel_https(host,port,context,timeout,server_name=None):
    if server_name is None:
        conn=http.client.HTTPSConnection(host,port,context=context,timeout=timeout)
    else:
        conn=_PanelSNIConnection(host,port,context=context,timeout=timeout,server_name=server_name)
    try:
        conn.connect()
        return conn
    except Exception:
        conn.close()
        raise


def _require_exact_panel_certificate(conn,certificate):
    try:
        leaf=re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',certificate,re.S)
        if not leaf:raise ValueError('Не удалось прочитать доверенный сертификат панели')
        expected=hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.group())).digest()
        actual=hashlib.sha256(conn.sock.getpeercert(binary_form=True)).digest()
        if not hmac.compare_digest(actual,expected):
            raise ssl.SSLCertVerificationError('Сертификат панели не совпадает с полученным по SSH')
        return conn
    except Exception:
        conn.close()
        raise


def pinned_https_connection(host,port,certificate,timeout=60,*,server_name=None):
    context=ssl.create_default_context(cadata=certificate)
    context.check_hostname=False
    context.verify_flags|=getattr(ssl,'VERIFY_X509_PARTIAL_CHAIN',0x80000)
    try:
        return _open_panel_https(host,port,context,timeout)
    except ssl.SSLCertVerificationError as error:
        if error.verify_code in (18,19):
            # The panel may serve a different certificate for its own IP or its configured SNI.
            if _valid_panel_dns_name(server_name):
                conn=_open_panel_https(host,port,context,timeout,server_name)
                return _require_exact_panel_certificate(conn,certificate)
            local_address=_local_panel_address(server_name)
            if local_address and local_address!=host:
                conn=_open_panel_https(local_address,port,context,timeout)
                return _require_exact_panel_certificate(conn,certificate)
        if error.verify_code!=10:
            raise

    # Only expiry permits a connection verified against the exact SSH-authenticated leaf.
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname=False
    context.verify_mode=ssl.CERT_NONE  # Replaced below by an exact SSH-authenticated pin.
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    conn=_open_panel_https(host,port,context,timeout)
    return _require_exact_panel_certificate(conn,certificate)
