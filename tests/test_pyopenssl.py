from __future__ import absolute_import, division, print_function

import ipaddress

import pytest

from OpenSSL.crypto import FILETYPE_PEM, load_certificate

from service_identity import SubjectAltNameWarning
from service_identity._common import DNSPattern, IPAddressPattern, URIPattern
from service_identity.pyopenssl import extract_ids, verify_hostname

from .util import PEM_CN_ONLY, PEM_DNS_ONLY, PEM_EVERYTHING, PEM_OTHER_NAME


CERT_DNS_ONLY = load_certificate(FILETYPE_PEM, PEM_DNS_ONLY)
CERT_CN_ONLY = load_certificate(FILETYPE_PEM, PEM_CN_ONLY)
CERT_OTHER_NAME = load_certificate(FILETYPE_PEM, PEM_OTHER_NAME)
CERT_EVERYTHING = load_certificate(FILETYPE_PEM, PEM_EVERYTHING)


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

        msg = ws[0].message.args[0]

        assert [
            DNSPattern(b"www.microsoft.com")
        ] == rv
        assert msg.startswith(
            "Certificate with CN 'www.microsoft.com' has no `subjectAltName`"
        )
        assert msg.endswith(
            "service_identity will remove the support for it in mid-2018."
        )

    def test_uri(self):
        """
        Returns the correct URIPattern from a certificate.
        """
        rv = extract_ids(CERT_OTHER_NAME)
        assert [
            URIPattern(b"http://example.com/")
        ] == [id for id in rv if isinstance(id, URIPattern)]

    def test_ip(self):
        """
        Returns IP patterns.
        """
        rv = extract_ids(CERT_EVERYTHING)

        assert [
            DNSPattern(pattern=b"service.identity.invalid"),
            DNSPattern(pattern=b"*.wildcard.service.identity.invalid"),
            DNSPattern(pattern=b"service.identity.invalid"),
            DNSPattern(pattern=b"single.service.identity.invalid"),
            IPAddressPattern(pattern=ipaddress.IPv4Address(u"1.1.1.1")),
            IPAddressPattern(pattern=ipaddress.IPv6Address(u"::1")),
            IPAddressPattern(pattern=ipaddress.IPv4Address(u"2.2.2.2")),
            IPAddressPattern(pattern=ipaddress.IPv6Address(u"2a00:1c38::53")),
        ] == rv
