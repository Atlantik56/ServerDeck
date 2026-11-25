import http.client,json,ssl,unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from panel_tls import _PanelSNIConnection,pinned_https_connection

class TLSChecks(unittest.TestCase):
    def verification_error(self,code):
        error=ssl.SSLCertVerificationError('certificate rejected')
        error.verify_code=code
        return error

    def connection(self,code=10,actual=b'trusted-leaf',strict_ok=False,retry_code=None,
                   server_name=None,named_actual=b'trusted-leaf',route_type='local'):
        first=Mock();second=Mock();second.sock.getpeercert.return_value=actual
        named=Mock()
        named.sock.getpeercert.return_value=named_actual
        if not strict_ok:
            first.connect.side_effect=self.verification_error(code)
        if retry_code is not None:
            named.connect.side_effect=self.verification_error(retry_code)
        context=SimpleNamespace(check_hostname=True,verify_flags=0,verify_mode=ssl.CERT_REQUIRED)
        factory=Mock(side_effect=[first,second])
        sni_factory=Mock(return_value=named)
        self.factory=factory;self.first=first;self.second=second
        self.named=named;self.sni_factory=sni_factory
        self.context=context
        with (
            patch('panel_tls.ssl.create_default_context',return_value=context),
            patch('panel_tls.ssl.SSLContext',return_value=SimpleNamespace()) as expiry_factory,
            patch('panel_tls.ssl.PEM_cert_to_DER_cert',return_value=b'trusted-leaf'),
            patch('panel_tls.subprocess.run',return_value=SimpleNamespace(stdout=json.dumps([{'type':route_type}]))) as route,
            patch('panel_tls.http.client.HTTPSConnection',factory),
            patch('panel_tls._PanelSNIConnection',sni_factory),
        ):
            self.route=route
            self.expiry_factory=expiry_factory
            return pinned_https_connection(
                '127.0.0.1',1234,'-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----',
                server_name=server_name,
            )

    def test_normal_validation_remains_preferred(self):
        result=self.connection(strict_ok=True)
        self.assertIs(result,self.first);self.assertEqual(self.factory.call_count,1)
        self.first.request.assert_not_called()

    def test_expired_certificate_requires_exact_ssh_authenticated_pin(self):
        self.assertIs(self.connection(),self.second)
        self.second.sock.getpeercert.assert_called_once_with(binary_form=True)
        self.first.close.assert_called_once();self.second.request.assert_not_called()

    def test_mismatched_certificate_closed_before_any_http_request(self):
        with self.assertRaises(ssl.SSLCertVerificationError):self.connection(actual=b'other-server')
        self.second.close.assert_called_once();self.second.request.assert_not_called()

    def test_other_verification_failures_never_fall_back(self):
        for code in (9,18,20,62):
            with self.assertRaises(ssl.SSLCertVerificationError):self.connection(code=code)
            self.assertEqual(self.factory.call_count,1)

    def test_default_certificate_retries_with_authenticated_name_and_verification(self):
        result=self.connection(code=18,server_name='panel.example.test')
        self.assertIs(result,self.named)
        self.first.close.assert_called_once()
        self.named.request.assert_not_called()
        self.sni_factory.assert_called_once_with(
            '127.0.0.1',1234,context=self.context,timeout=60,server_name='panel.example.test',
        )
        self.assertEqual(self.context.verify_mode,ssl.CERT_REQUIRED)
        self.named.sock.getpeercert.assert_called_once_with(binary_form=True)
        self.route.assert_not_called()

    def test_verified_named_connection_requires_exact_leaf(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connection(code=18,server_name='configured.example.test',named_actual=b'other-valid-leaf')
        self.named.close.assert_called_once()
        self.named.request.assert_not_called()
        self.assertEqual(self.sni_factory.call_count,1)

    def test_wrong_named_certificate_is_rejected_without_expiry_fallback(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connection(code=18,server_name='panel.example.test',retry_code=18)
        self.named.close.assert_called_once()
        self.assertEqual(self.sni_factory.call_count,1)
        self.second.connect.assert_not_called()

    def test_expired_named_certificate_does_not_use_unverified_retry(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connection(code=18,server_name='panel.example.test',retry_code=10)
        self.named.close.assert_called_once()
        self.expiry_factory.assert_not_called()

    def test_default_certificate_retries_against_the_locally_routed_ip(self):
        result=self.connection(code=18,server_name='192.0.2.20')
        self.assertIs(result,self.second)
        self.first.close.assert_called_once()
        self.route.assert_called_once()
        self.assertEqual(self.route.call_args.args[0],['ip','-j','route','get','192.0.2.20'])
        self.factory.assert_called_with('192.0.2.20',1234,context=self.context,timeout=60)
        self.sni_factory.assert_not_called()
        self.assertEqual(self.context.verify_mode,ssl.CERT_REQUIRED)
        self.second.sock.getpeercert.assert_called_once_with(binary_form=True)

    def test_verified_local_ip_connection_requires_exact_leaf(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connection(code=18,server_name='192.0.2.20',actual=b'other-valid-leaf')
        self.second.close.assert_called_once()
        self.second.request.assert_not_called()
        self.expiry_factory.assert_not_called()

    def test_nonlocal_routes_do_not_open_an_alternate_connection(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connection(code=18,server_name='192.0.2.20',route_type='unicast')
        self.assertEqual(self.factory.call_count,1)
        self.sni_factory.assert_not_called()

    def test_invalid_configured_host_is_not_used(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connection(code=18,server_name='*.example.test')
        self.assertEqual(self.factory.call_count,1)
        self.route.assert_not_called()
        self.sni_factory.assert_not_called()

    def test_sni_uses_the_existing_socket_and_does_not_change_http_host(self):
        context=ssl.create_default_context()
        conn=_PanelSNIConnection('127.0.0.1',1234,context=context,timeout=60,server_name='panel.example.test')
        socket=Mock()
        with (
            patch.object(http.client.HTTPConnection,'connect',side_effect=lambda target:setattr(target,'sock',socket)) as tcp,
            patch.object(context,'wrap_socket') as tls,
        ):
            conn.connect()
        self.assertEqual(conn.host,'127.0.0.1')
        tcp.assert_called_once()
        tls.assert_called_once_with(socket,server_hostname='panel.example.test')

if __name__=='__main__':unittest.main()
