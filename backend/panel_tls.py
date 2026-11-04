"""TLS for panel connections authenticated independently over trusted SSH.

Normal certificate validation is preferred. An expired upstream certificate
can be used only when its exact leaf DER matches the certificate read over SSH.
No HTTP request or credentials are sent before that check. Public browser TLS
is not affected by this internal connection policy.
"""
import hashlib,hmac,http.client,re,ssl

def pinned_https_connection(host,port,certificate,timeout=60):
    context=ssl.create_default_context(cadata=certificate)
    context.check_hostname=False
    context.verify_flags|=getattr(ssl,'VERIFY_X509_PARTIAL_CHAIN',0x80000)
    conn=http.client.HTTPSConnection(host,port,context=context,timeout=timeout)
    try:
        conn.connect()
        return conn
    except ssl.SSLCertVerificationError as error:
        conn.close()
        if error.verify_code!=10:raise  # Certificate expiry only.
    leaf=re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',certificate,re.S)
    if not leaf:raise ValueError('Не удалось прочитать доверенный сертификат панели')
    expected=hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.group())).digest()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname=False
    context.verify_mode=ssl.CERT_NONE  # Replaced below by an exact SSH-authenticated pin.
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    conn=http.client.HTTPSConnection(host,port,context=context,timeout=timeout)
    try:
        conn.connect()
        actual=hashlib.sha256(conn.sock.getpeercert(binary_form=True)).digest()
        if not hmac.compare_digest(actual,expected):
            raise ssl.SSLCertVerificationError('Сертификат панели не совпадает с полученным по SSH')
        return conn
    except Exception:
        conn.close()
        raise
