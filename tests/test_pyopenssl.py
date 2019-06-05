from __future__ import absolute_import, division, print_function

import ipaddress

import pytest

from OpenSSL.crypto import FILETYPE_PEM, load_certificate

from service_identity import SubjectAltNameWarning
from service_identity._common import (
    DNS_ID,
    DNSPattern,
    IPAddress_ID,
    IPAddressPattern,
    URIPattern,
)
from service_identity.exceptions import (
    DNSMismatch,
    IPAddressMismatch,
    VerificationError,
)
from service_identity.pyopenssl import (
    extract_ids,
    verify_hostname,
    verify_ip_address,
)

from .util import PEM_CN_ONLY, PEM_DNS_ONLY, PEM_EVERYTHING, PEM_OTHER_NAME


CERT_DNS_ONLY = load_certificate(FILETYPE_PEM, PEM_DNS_ONLY)
CERT_CN_ONLY = load_certificate(FILETYPE_PEM, PEM_CN_ONLY)
CERT_OTHER_NAME = load_certificate(FILETYPE_PEM, PEM_OTHER_NAME)
CERT_EVERYTHING = load_certificate(FILETYPE_PEM, PEM_EVERYTHING)


class TestPublicAPI(object):
    def test_verify_hostname_ok(self):
        """
        verify_hostname succeeds if the hostnames match.
        """

        class FakeConnection(object):
            def get_peer_certificate(self):
                return CERT_DNS_ONLY

        verify_hostname(FakeConnection(), u"twistedmatrix.com")

    def test_verify_hostname_fail(self):
        """
        verify_hostname fails if the hostnames don't match and provides the
        user with helpful information.
        """

        class FakeConnection(object):
            def get_peer_certificate(self):
                return CERT_DNS_ONLY

        with pytest.raises(VerificationError) as ei:
            verify_hostname(FakeConnection(), u"google.com")

        assert [
            DNSMismatch(mismatched_id=DNS_ID(u"google.com"))
        ] == ei.value.errors

    @pytest.mark.parametrize("ip", [u"1.1.1.1", u"::1"])
    def test_verify_ip_address_ok(self, ip):
        """
        verify_ip_address succeeds if the addresses match. Works both with IPv4
        and IPv6.
        """

        class FakeConnection(object):
            def get_peer_certificate(self):
                return CERT_EVERYTHING

        verify_ip_address(FakeConnection(), ip)

    @pytest.mark.parametrize("ip", [u"1.1.1.2", u"::2"])
    def test_verify_ip_address_fail(self, ip):
        """
        verify_ip_address fails if the addresses don't match and provides the
        user with helpful information. Works both with IPv4 and IPv6.
        """

        class FakeConnection(object):
            def get_peer_certificate(self):
                return CERT_EVERYTHING

        with pytest.raises(VerificationError) as ei:
            verify_ip_address(FakeConnection(), ip)

        assert [
            IPAddressMismatch(mismatched_id=IPAddress_ID(ip))
        ] == ei.value.errors


class TestExtractIDs(object):
    def test_dns(self):
        """
        Returns the correct DNSPattern from a certificate.
        """
        rv = extract_ids(CERT_DNS_ONLY)
        assert [
            DNSPattern(b"www.twistedmatrix.com"),
            DNSPattern(b"twistedmatrix.com"),
        ] == rv

    def test_cn_ids_are_used_as_fallback(self):
        """
        CNs are returned as DNSPattern if no other IDs are present
        and a warning is raised.
        """
        with pytest.warns(SubjectAltNameWarning) as ws:
            rv = extract_ids(CERT_CN_ONLY)

        msg = ws[0].message.args[0]

        assert [DNSPattern(b"www.microsoft.com")] == rv
        assert msg.startswith(
            "Certificate with CN 'www.microsoft.com' has no `subjectAltName`"
        )
        assert msg.endswith(
            "service-identity will remove the support for it in mid-2018."
        )

    def test_uri(self):
        """
        Returns the correct URIPattern from a certificate.
        """
        rv = extract_ids(CERT_OTHER_NAME)
        assert [URIPattern(b"http://example.com/")] == [
            id for id in rv if isinstance(id, URIPattern)
        ]

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
