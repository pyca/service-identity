import ipaddress

import pytest

from OpenSSL.crypto import FILETYPE_PEM, load_certificate

from service_identity.common import (
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


class TestPublicAPI:
    def test_verify_hostname_ok(self):
        """
        verify_hostname succeeds if the hostnames match.
        """

        class FakeConnection:
            def get_peer_certificate(self):
                return CERT_DNS_ONLY

        verify_hostname(FakeConnection(), "twistedmatrix.com")

    def test_verify_hostname_fail(self):
        """
        verify_hostname fails if the hostnames don't match and provides the
        user with helpful information.
        """

        class FakeConnection:
            def get_peer_certificate(self):
                return CERT_DNS_ONLY

        with pytest.raises(VerificationError) as ei:
            verify_hostname(FakeConnection(), "google.com")

        assert [
            DNSMismatch(mismatched_id=DNS_ID("google.com"))
        ] == ei.value.errors

    @pytest.mark.parametrize("ip", ["1.1.1.1", "::1"])
    def test_verify_ip_address_ok(self, ip):
        """
        verify_ip_address succeeds if the addresses match. Works both with IPv4
        and IPv6.
        """

        class FakeConnection:
            def get_peer_certificate(self):
                return CERT_EVERYTHING

        verify_ip_address(FakeConnection(), ip)

    @pytest.mark.parametrize("ip", ["1.1.1.2", "::2"])
    def test_verify_ip_address_fail(self, ip):
        """
        verify_ip_address fails if the addresses don't match and provides the
        user with helpful information. Works both with IPv4 and IPv6.
        """

        class FakeConnection:
            def get_peer_certificate(self):
                return CERT_EVERYTHING

        with pytest.raises(VerificationError) as ei:
            verify_ip_address(FakeConnection(), ip)

        assert [
            IPAddressMismatch(mismatched_id=IPAddress_ID(ip))
        ] == ei.value.errors


class TestExtractIDs:
    def test_dns(self):
        """
        Returns the correct DNSPattern from a certificate.
        """
        rv = extract_ids(CERT_DNS_ONLY)
        assert [
            DNSPattern(b"www.twistedmatrix.com"),
            DNSPattern(b"twistedmatrix.com"),
        ] == rv

    def test_cn_ids_are_ignored(self):
        """
        commonName is not supported anymore and therefore ignored.
        """
        assert [] == extract_ids(CERT_CN_ONLY)

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
            IPAddressPattern(pattern=ipaddress.IPv4Address("1.1.1.1")),
            IPAddressPattern(pattern=ipaddress.IPv6Address("::1")),
            IPAddressPattern(pattern=ipaddress.IPv4Address("2.2.2.2")),
            IPAddressPattern(pattern=ipaddress.IPv6Address("2a00:1c38::53")),
        ] == rv
