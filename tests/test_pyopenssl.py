from __future__ import absolute_import, division, print_function

import pytest

from service_identity._common import DNSPattern, URIPattern
from service_identity import SubjectAltNameWarning
from service_identity.pyopenssl import extract_ids, verify_hostname

from .util import CERT_CN_ONLY, CERT_DNS_ONLY, CERT_OTHER_NAME


class TestVerifyHostname(object):
    def test_verify_hostname(self):
        """
        It's just a convenience one-liner.  Let's check it doesn't explode b/c
        of some typo.
        """
        class FakeConnection(object):
            def get_peer_certificate(self):
                return CERT_DNS_ONLY

        verify_hostname(FakeConnection(), u"twistedmatrix.com")


class TestExtractIDs(object):
    def test_dns(self):
        """
        Returns the correct DNSPattern from a certificate.
        """
        rv = extract_ids(CERT_DNS_ONLY)
        assert [
            DNSPattern(b"www.twistedmatrix.com"),
            DNSPattern(b"twistedmatrix.com")
        ] == rv

    def test_cn_ids_are_used_as_fallback(self):
        """
        CNs are returned as DNSPattern if no other IDs are present
        and a warning is raised.
        """
        with pytest.warns(SubjectAltNameWarning) as ws:
            rv = extract_ids(CERT_CN_ONLY)
        assert [
            DNSPattern(b"www.microsoft.com")
        ] == rv
        assert 'www.microsoft.com' in ws[0].message.args[0]

    def test_uri(self):
        """
        Returns the correct URIPattern from a certificate.
        """
        rv = extract_ids(CERT_OTHER_NAME)
        assert [
            URIPattern(b"http://example.com/")
        ] == [id for id in rv if isinstance(id, URIPattern)]
