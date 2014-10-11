from sys import version_info

import pytest

import _ssl

from service_identity._common import DNSPattern, URIPattern
from service_identity.stdlib import extract_ids, verify_hostname
from .util import PEM_CN_ONLY, PEM_DNS_ONLY, PEM_OTHER_NAME


class TestVerifyHostname(object):
    def test_verify_hostname(self, tmpdir):
        class FakeConnection(object):
            def getpeercert(self):
                dns_cert = tmpdir.join("dns_cert.pem")
                dns_cert.write(PEM_DNS_ONLY)
                return _ssl._test_decode_cert(str(dns_cert))

        verify_hostname(FakeConnection(), u"twistedmatrix.com")


class TestExtractIDs(object):
    def test_dns(self, tmpdir):
        """
        Returns the correct DNSPattern from a certificate.
        """
        dns_cert = tmpdir.join("dns_cert.pem")
        dns_cert.write(PEM_DNS_ONLY)
        rv = extract_ids(_ssl._test_decode_cert(str(dns_cert)))
        assert rv == [
            DNSPattern(b'www.twistedmatrix.com'),
            DNSPattern(b'twistedmatrix.com')
        ]

    def test_cn_ids_are_used_as_fallback(self, tmpdir):
        """
        CNs are returned as DNSPattern if no other IDs are present.
        """
        cn_cert = tmpdir.join("cn_cert.pem")
        cn_cert.write(PEM_CN_ONLY)
        rv = extract_ids(_ssl._test_decode_cert(str(cn_cert)))
        assert rv == [DNSPattern(b'www.microsoft.com')]

    @pytest.mark.skipif(version_info[0] == 2 and version_info[1] == 6,
                        reason="Python 2.6")
    def test_uri(self, tmpdir):
        """
        Returns the correct URIPattern from a certificate.
        """
        uri_cert = tmpdir.join("uri_cert.pem")
        uri_cert.write(PEM_OTHER_NAME)
        rv = extract_ids(_ssl._test_decode_cert(str(uri_cert)))
        assert (
            [id for id in rv if isinstance(id, URIPattern)] ==
            [URIPattern(b'http://example.com/')]
        )
