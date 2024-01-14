import ipaddress

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

from service_identity.cryptography import (
    extract_ids,
    extract_patterns,
    verify_certificate_hostname,
    verify_certificate_ip_address,
)
from service_identity.exceptions import (
    CertificateError,
    DNSMismatch,
    IPAddressMismatch,
    VerificationError,
)
from service_identity.hazmat import (
    DNS_ID,
    DNSPattern,
    IPAddress_ID,
    IPAddressPattern,
    URIPattern,
)

from .certificates import (
    PEM_CN_ONLY,
    PEM_DNS_ONLY,
    PEM_EVERYTHING,
    PEM_OTHER_NAME,
)


backend = default_backend()
X509_DNS_ONLY = load_pem_x509_certificate(PEM_DNS_ONLY, backend)
X509_CN_ONLY = load_pem_x509_certificate(PEM_CN_ONLY, backend)
X509_OTHER_NAME = load_pem_x509_certificate(PEM_OTHER_NAME, backend)
CERT_EVERYTHING = load_pem_x509_certificate(PEM_EVERYTHING, backend)


class TestPublicAPI:
    def test_no_cert_patterns_hostname(self):
        """
        A certificate without subjectAltNames raises a helpful
        CertificateError.
        """
        with pytest.raises(
            CertificateError,
            match="Certificate does not contain any `subjectAltName`s.",
        ):
            verify_certificate_hostname(X509_CN_ONLY, "example.com")

    @pytest.mark.parametrize("ip", ["203.0.113.0", "2001:db8::"])
    def test_no_cert_patterns_ip_address(self, ip):
        """
        A certificate without subjectAltNames raises a helpful
        CertificateError.
        """
        with pytest.raises(
            CertificateError,
            match="Certificate does not contain any `subjectAltName`s.",
        ):
            verify_certificate_ip_address(X509_CN_ONLY, ip)

    def test_certificate_verify_hostname_ok(self):
        """
        verify_certificate_hostname succeeds if the hostnames match.
        """
        verify_certificate_hostname(X509_DNS_ONLY, "twistedmatrix.com")

    def test_certificate_verify_hostname_fail(self):
        """
        verify_certificate_hostname fails if the hostnames don't match and
        provides the user with helpful information.
        """
        with pytest.raises(VerificationError) as ei:
            verify_certificate_hostname(X509_DNS_ONLY, "google.com")

        assert [
            DNSMismatch(mismatched_id=DNS_ID("google.com"))
        ] == ei.value.errors

    @pytest.mark.parametrize("ip", ["1.1.1.1", "::1"])
    def test_verify_certificate_ip_address_ok(self, ip):
        """
        verify_certificate_ip_address succeeds if the addresses match. Works
        both with IPv4 and IPv6.
        """
        verify_certificate_ip_address(CERT_EVERYTHING, ip)

    @pytest.mark.parametrize("ip", ["1.1.1.2", "::2"])
    def test_verify_ip_address_fail(self, ip):
        """
        verify_ip_address fails if the addresses don't match and provides the
        user with helpful information.  Works both with IPv4 and IPv6.
        """
        with pytest.raises(VerificationError) as ei:
            verify_certificate_ip_address(CERT_EVERYTHING, ip)

        assert [
            IPAddressMismatch(mismatched_id=IPAddress_ID(ip))
        ] == ei.value.errors


class TestExtractPatterns:
    def test_dns(self):
        """
        Returns the correct DNSPattern from a certificate.
        """
        rv = extract_patterns(X509_DNS_ONLY)
        assert [
            DNSPattern.from_bytes(b"www.twistedmatrix.com"),
            DNSPattern.from_bytes(b"twistedmatrix.com"),
        ] == rv

    def test_cn_ids_are_ignored(self):
        """
        commonName is not supported anymore and therefore ignored.
        """
        assert [] == extract_patterns(X509_CN_ONLY)

    def test_uri(self):
        """
        Returns the correct URIPattern from a certificate.
        """
        rv = extract_patterns(X509_OTHER_NAME)
        assert [URIPattern.from_bytes(b"http://example.com/")] == [
            id for id in rv if isinstance(id, URIPattern)
        ]

    def test_ip(self):
        """
        Returns IP patterns.
        """
        rv = extract_patterns(CERT_EVERYTHING)

        assert [
            DNSPattern.from_bytes(pattern=b"service.identity.invalid"),
            DNSPattern.from_bytes(
                pattern=b"*.wildcard.service.identity.invalid"
            ),
            DNSPattern.from_bytes(pattern=b"service.identity.invalid"),
            DNSPattern.from_bytes(pattern=b"single.service.identity.invalid"),
            IPAddressPattern(pattern=ipaddress.IPv4Address("1.1.1.1")),
            IPAddressPattern(pattern=ipaddress.IPv6Address("::1")),
            IPAddressPattern(pattern=ipaddress.IPv4Address("2.2.2.2")),
            IPAddressPattern(pattern=ipaddress.IPv6Address("2a00:1c38::53")),
        ] == rv

    def test_extract_ids_deprecated(self):
        """
        `extract_ids` raises a DeprecationWarning with correct stacklevel.
        """
        with pytest.deprecated_call() as wr:
            extract_ids(CERT_EVERYTHING)

        w = wr.pop()

        assert (
            "`extract_ids()` is deprecated, please use `extract_patterns()`."
            == w.message.args[0]
        )
        assert __file__ == w.filename
