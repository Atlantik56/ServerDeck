import ssl,unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from panel_tls import pinned_https_connection

class TLSChecks(unittest.TestCase):
    def connection(self,code=10,actual=b'trusted-leaf',strict_ok=False):
        first=Mock();second=Mock();second.sock.getpeercert.return_value=actual
        if not strict_ok:
            error=ssl.SSLCertVerificationError('certificate rejected');error.verify_code=code
            first.connect.side_effect=error
        context=SimpleNamespace(check_hostname=True,verify_flags=0)
        factory=Mock(side_effect=[first,second])
        self.factory=factory;self.first=first;self.second=second
        with patch('panel_tls.ssl.create_default_context',return_value=context),patch('panel_tls.ssl.SSLContext',return_value=SimpleNamespace()),patch('panel_tls.ssl.PEM_cert_to_DER_cert',return_value=b'trusted-leaf'),patch('panel_tls.http.client.HTTPSConnection',factory):
            return pinned_https_connection('127.0.0.1',1234,'-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----')

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

if __name__=='__main__':unittest.main()
