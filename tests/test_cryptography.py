from __future__ import absolute_import, division, print_function

import pytest

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

from service_identity._common import DNSPattern, URIPattern
from service_identity import SubjectAltNameWarning
from service_identity.cryptography import extract_ids, verify_hostname

from .util import PEM_CN_ONLY, PEM_DNS_ONLY, PEM_OTHER_NAME


backend = default_backend()
X509_DNS_ONLY = load_pem_x509_certificate(PEM_DNS_ONLY, backend)
X509_CN_ONLY = load_pem_x509_certificate(PEM_CN_ONLY, backend)
X509_OTHER_NAME = load_pem_x509_certificate(PEM_OTHER_NAME, backend)


class TestVerifyHostname(object):
    def test_verify_hostname(self):
        """
        It's just a convenience one-liner.  Let's check it doesn't explode b/c
        of some typo.
        """
        verify_hostname(X509_DNS_ONLY, u"twistedmatrix.com")


class TestExtractIDs(object):
    def test_dns(self):
        """
        Returns the correct DNSPattern from a certificate.
        """
        rv = extract_ids(X509_DNS_ONLY)
        assert [
            DNSPattern(b"www.twistedmatrix.com"),
            DNSPattern(b"twistedmatrix.com")
        ] == rv

    def test_cn_ids_are_used_as_fallback(self):
        """
        CNs are returned as DNSPattern if no other IDs are present
        and a warning is raised.
        """
        with pytest.warns(SubjectAltNameWarning):
            rv = extract_ids(X509_CN_ONLY)
        assert [
            DNSPattern(b"www.microsoft.com")
        ] == rv

    def test_uri(self):
        """
        Returns the correct URIPattern from a certificate.
        """
        rv = extract_ids(X509_OTHER_NAME)
        assert [
            URIPattern(b"http://example.com/")
        ] == [id for id in rv if isinstance(id, URIPattern)]
