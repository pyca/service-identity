from __future__ import absolute_import, division, print_function

from OpenSSL.test.util import TestCase

from service_identity._common import DNSPattern, URIPattern
from service_identity.pyopenssl import extract_ids, verify_hostname
from .util import CERT_CN_ONLY, CERT_DNS_ONLY, CERT_OTHER_NAME


class VerifyHostnameTestCase(TestCase):
    def test_verify_hostname(self):
        """
        It's just a convenience one-liner.  Let's check it doesn't explode b/c
        of some typo.
        """
        class FakeConnection(object):
            def get_peer_certificate(self):
                return CERT_DNS_ONLY

        verify_hostname(FakeConnection(), u"twistedmatrix.com")


class ExtractIDsTestCase(TestCase):
    def test_dns(self):
        """
        Returns the correct DNSPattern from a certificate.
        """
        rv = extract_ids(CERT_DNS_ONLY)
        self.assertEqual(
            [DNSPattern(b'www.twistedmatrix.com'),
             DNSPattern(b'twistedmatrix.com')],
            rv
        )

    def test_cn_ids_are_used_as_fallback(self):
        """
        CNs are returned as DNSPattern if no other IDs are present.
        """
        rv = extract_ids(CERT_CN_ONLY)
        self.assertEqual(
            [DNSPattern(b'www.microsoft.com')], rv
        )

    def test_uri(self):
        """
        Returns the correct URIPattern from a certificate.
        """
        rv = extract_ids(CERT_OTHER_NAME)
        self.assertEqual(
            [URIPattern(b'http://example.com/')],
            [id for id in rv if isinstance(id, URIPattern)]
        )
