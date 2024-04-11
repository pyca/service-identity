import ipaddress
import pickle

import pytest

import service_identity.hazmat

from service_identity.cryptography import extract_patterns
from service_identity.exceptions import (
    CertificateError,
    DNSMismatch,
    SRVMismatch,
    VerificationError,
)
from service_identity.hazmat import (
    DNS_ID,
    SRV_ID,
    URI_ID,
    DNSPattern,
    IPAddress_ID,
    IPAddressPattern,
    ServiceMatch,
    SRVPattern,
    URIPattern,
    _contains_instance_of,
    _find_matches,
    _hostname_matches,
    _is_ip_address,
    _validate_pattern,
    verify_service_identity,
)

from .certificates import DNS_IDS
from .test_cryptography import CERT_EVERYTHING


try:
    import idna
except ImportError:
    idna = None


class TestVerifyServiceIdentity:
    """
    Simple integration tests for verify_service_identity.
    """

    def test_no_cert_patterns(self):
        """
        Empty cert patterns raise a helpful CertificateError.
        """
        with pytest.raises(
            CertificateError,
            match="Certificate does not contain any `subjectAltName`s.",
        ):
            verify_service_identity(
                cert_patterns=[], obligatory_ids=[], optional_ids=[]
            )

    def test_dns_id_success(self):
        """
        Return pairs of certificate ids and service ids on matches.
        """
        rv = verify_service_identity(
            DNS_IDS, [DNS_ID("twistedmatrix.com")], []
        )
        assert [
            ServiceMatch(
                cert_pattern=DNSPattern.from_bytes(b"twistedmatrix.com"),
                service_id=DNS_ID("twistedmatrix.com"),
            )
        ] == rv

    def test_integration_dns_id_fail(self):
        """
        Raise VerificationError if no certificate id matches the supplied
        service ids.
        """
        i = DNS_ID("wrong.host")
        with pytest.raises(VerificationError) as e:
            verify_service_identity(
                DNS_IDS, obligatory_ids=[i], optional_ids=[]
            )
        assert [DNSMismatch(mismatched_id=i)] == e.value.errors

    def test_ip_address_success(self):
        """
        IP addresses patterns are matched against IP address IDs.
        """
        ip4 = ipaddress.ip_address("2.2.2.2")
        ip6 = ipaddress.ip_address("2a00:1c38::53")
        id4 = IPAddress_ID(str(ip4))
        id6 = IPAddress_ID(str(ip6))
        rv = verify_service_identity(
            extract_patterns(CERT_EVERYTHING), [id4, id6], []
        )

        assert [
            ServiceMatch(id4, IPAddressPattern(ip4)),
            ServiceMatch(id6, IPAddressPattern(ip6)),
        ] == rv

    def test_obligatory_missing(self):
        """
        Raise if everything matches but one of the obligatory IDs is missing.
        """
        i = DNS_ID("example.net")
        with pytest.raises(VerificationError) as e:
            verify_service_identity(
                [SRVPattern.from_bytes(b"_mail.example.net")],
                obligatory_ids=[SRV_ID("_mail.example.net"), i],
                optional_ids=[],
            )
        assert [DNSMismatch(mismatched_id=i)] == e.value.errors

    def test_obligatory_mismatch(self):
        """
        Raise if one of the obligatory IDs doesn't match.
        """
        i = DNS_ID("example.net")
        with pytest.raises(VerificationError) as e:
            verify_service_identity(
                [
                    SRVPattern.from_bytes(b"_mail.example.net"),
                    DNSPattern.from_bytes(b"example.com"),
                ],
                obligatory_ids=[SRV_ID("_mail.example.net"), i],
                optional_ids=[],
            )
        assert [DNSMismatch(mismatched_id=i)] == e.value.errors

    def test_optional_missing(self):
        """
        Optional IDs may miss as long as they don't conflict with an existing
        pattern.
        """
        p = DNSPattern.from_bytes(b"mail.foo.com")
        i = DNS_ID("mail.foo.com")
        rv = verify_service_identity(
            [p], obligatory_ids=[i], optional_ids=[SRV_ID("_mail.foo.com")]
        )
        assert [ServiceMatch(cert_pattern=p, service_id=i)] == rv

    def test_optional_mismatch(self):
        """
        Raise VerificationError if an ID from optional_ids does not match
        a pattern of respective type even if obligatory IDs match.
        """
        i = SRV_ID("_xmpp.example.com")
        with pytest.raises(VerificationError) as e:
            verify_service_identity(
                [
                    DNSPattern.from_bytes(b"example.net"),
                    SRVPattern.from_bytes(b"_mail.example.com"),
                ],
                obligatory_ids=[DNS_ID("example.net")],
                optional_ids=[i],
            )
        assert [SRVMismatch(mismatched_id=i)] == e.value.errors

    def test_contains_optional_and_matches(self):
        """
        If an optional ID is found, return the match within the returned
        list and don't raise an error.
        """
        p = SRVPattern.from_bytes(b"_mail.example.net")
        i = SRV_ID("_mail.example.net")
        rv = verify_service_identity(
            [DNSPattern.from_bytes(b"example.net"), p],
            obligatory_ids=[DNS_ID("example.net")],
            optional_ids=[i],
        )
        assert ServiceMatch(cert_pattern=p, service_id=i) == rv[1]


class TestContainsInstance:
    def test_positive(self):
        """
        If the list contains an object of the type, return True.
        """
        assert _contains_instance_of([object(), (), object()], tuple)

    def test_negative(self):
        """
        If the list does not contain an object of the type, return False.
        """
        assert not _contains_instance_of([object(), [], {}], tuple)


class TestDNS_ID:
    def test_enforces_unicode(self):
        """
        Raise TypeError if pass DNS-ID is not unicode.
        """
        with pytest.raises(TypeError):
            DNS_ID(b"foo.com")

    def test_handles_missing_idna(self, monkeypatch):
        """
        Raise ImportError if idna is missing and a non-ASCII DNS-ID is passed.
        """
        monkeypatch.setattr(service_identity.hazmat, "idna", None)
        with pytest.raises(ImportError):
            DNS_ID("f\xf8\xf8.com")

    def test_ascii_works_without_idna(self, monkeypatch):
        """
        7bit-ASCII DNS-IDs work no matter whether idna is present or not.
        """
        monkeypatch.setattr(service_identity.hazmat, "idna", None)
        dns = DNS_ID("foo.com")
        assert b"foo.com" == dns.hostname

    @pytest.mark.skipif(idna is None, reason="idna not installed")
    def test_idna_used_if_available_on_non_ascii(self):
        """
        If idna is installed and a non-ASCII DNS-ID is passed, encode it to
        ASCII.
        """
        dns = DNS_ID("f\xf8\xf8.com")
        assert b"xn--f-5gaa.com" == dns.hostname

    @pytest.mark.parametrize(
        "invalid_id",
        [
            " ",
            "",  # empty strings
            "host,name",  # invalid chars
            "192.168.0.0",
            "::1",
            "1234",  # IP addresses
        ],
    )
    def test_catches_invalid_dns_ids(self, invalid_id):
        """
        Raise ValueError on invalid DNS-IDs.
        """
        with pytest.raises(ValueError):
            DNS_ID(invalid_id)

    def test_lowercases(self):
        """
        The hostname is lowercased so it can be compared case-insensitively.
        """
        dns_id = DNS_ID("hOsTnAmE")
        assert b"hostname" == dns_id.hostname

    def test_verifies_only_dns(self):
        """
        If anything else than DNSPattern is passed to verify, return False.
        """
        assert not DNS_ID("foo.com").verify(object())

    def test_simple_match(self):
        """
        Simple integration test with _hostname_matches with a match.
        """
        assert DNS_ID("foo.com").verify(DNSPattern.from_bytes(b"foo.com"))

    def test_simple_mismatch(self):
        """
        Simple integration test with _hostname_matches with a mismatch.
        """
        assert not DNS_ID("foo.com").verify(DNSPattern.from_bytes(b"bar.com"))

    def test_matches(self):
        """
        Valid matches return `True`.
        """
        for cert, actual in [
            (b"www.example.com", b"www.example.com"),
            (b"*.example.com", b"www.example.com"),
        ]:
            assert _hostname_matches(cert, actual)

    def test_mismatches(self):
        """
        Invalid matches return `False`.
        """
        for cert, actual in [
            (b"xxx.example.com", b"www.example.com"),
            (b"*.example.com", b"baa.foo.example.com"),
            (b"f*.example.com", b"baa.example.com"),
            (b"*.bar.com", b"foo.baz.com"),
            (b"*.bar.com", b"bar.com"),
            (b"x*.example.com", b"xn--gtter-jua.example.com"),
            (b"xxx*.example.com", b"xxxwww.example.com"),
            (b"f*.example.com", b"foo.example.com"),
            (b"*oo.bar.com", b"foo.bar.com"),
            (b"fo*oo.bar.com", b"fooooo.bar.com"),
        ]:
            assert not _hostname_matches(cert, actual)


class TestURI_ID:
    def test_enforces_unicode(self):
        """
        Raise TypeError if pass URI-ID is not unicode.
        """
        with pytest.raises(TypeError):
            URI_ID(b"sip:foo.com")

    def test_create_DNS_ID(self):
        """
        The hostname is converted into a DNS_ID object.
        """
        uri_id = URI_ID("sip:foo.com")
        assert DNS_ID("foo.com") == uri_id.dns_id
        assert b"sip" == uri_id.protocol

    def test_lowercases(self):
        """
        The protocol is lowercased so it can be compared case-insensitively.
        """
        uri_id = URI_ID("sIp:foo.com")
        assert b"sip" == uri_id.protocol

    def test_catches_missing_colon(self):
        """
        Raise ValueError if there's no colon within a URI-ID.
        """
        with pytest.raises(ValueError):
            URI_ID("sip;foo.com")

    def test_is_only_valid_for_uri(self):
        """
        If anything else than an URIPattern is passed to verify, return
        False.
        """
        assert not URI_ID("sip:foo.com").verify(object())

    def test_protocol_mismatch(self):
        """
        If protocol doesn't match, verify returns False.
        """
        assert not URI_ID("sip:foo.com").verify(
            URIPattern.from_bytes(b"xmpp:foo.com")
        )

    def test_dns_mismatch(self):
        """
        If the hostname doesn't match, verify returns False.
        """
        assert not URI_ID("sip:bar.com").verify(
            URIPattern.from_bytes(b"sip:foo.com")
        )

    def test_match(self):
        """
        Accept legal matches.
        """
        assert URI_ID("sip:foo.com").verify(
            URIPattern.from_bytes(b"sip:foo.com")
        )


class TestSRV_ID:
    def test_enforces_unicode(self):
        """
        Raise TypeError if pass srv-ID is not unicode.
        """
        with pytest.raises(TypeError):
            SRV_ID(b"_mail.example.com")

    def test_create_DNS_ID(self):
        """
        The hostname is converted into a DNS_ID object.
        """
        srv_id = SRV_ID("_mail.example.com")
        assert DNS_ID("example.com") == srv_id.dns_id

    def test_lowercases(self):
        """
        The service name is lowercased so it can be compared
        case-insensitively.
        """
        srv_id = SRV_ID("_MaIl.foo.com")
        assert b"mail" == srv_id.name

    def test_catches_missing_dot(self):
        """
        Raise ValueError if there's no dot within a SRV-ID.
        """
        with pytest.raises(ValueError):
            SRV_ID("_imapsfoocom")

    def test_catches_missing_underscore(self):
        """
        Raise ValueError if the service is doesn't start with an underscore.
        """
        with pytest.raises(ValueError):
            SRV_ID("imaps.foo.com")

    def test_is_only_valid_for_SRV(self):
        """
        If anything else than an SRVPattern is passed to verify, return False.
        """
        assert not SRV_ID("_mail.foo.com").verify(object())

    def test_match(self):
        """
        Accept legal matches.
        """
        assert SRV_ID("_mail.foo.com").verify(
            SRVPattern.from_bytes(b"_mail.foo.com")
        )

    @pytest.mark.skipif(idna is None, reason="idna not installed")
    def test_match_idna(self):
        """
        IDNAs are handled properly.
        """
        assert SRV_ID("_mail.f\xf8\xf8.com").verify(
            SRVPattern.from_bytes(b"_mail.xn--f-5gaa.com")
        )

    def test_mismatch_service_name(self):
        """
        If the service name doesn't match, verify returns False.
        """
        assert not (
            SRV_ID("_mail.foo.com").verify(
                SRVPattern.from_bytes(b"_xmpp.foo.com")
            )
        )

    def test_mismatch_dns(self):
        """
        If the dns_id doesn't match, verify returns False.
        """
        assert not (
            SRV_ID("_mail.foo.com").verify(
                SRVPattern.from_bytes(b"_mail.bar.com")
            )
        )


class TestDNSPattern:
    def test_enforces_bytes(self):
        """
        Raise TypeError if unicode is passed.
        """
        with pytest.raises(TypeError):
            DNSPattern.from_bytes("foo.com")

    def test_catches_empty(self):
        """
        Empty DNS-IDs raise a :class:`CertificateError`.
        """
        with pytest.raises(CertificateError):
            DNSPattern.from_bytes(b" ")

    def test_catches_NULL_bytes(self):
        """
        Raise :class:`CertificateError` if a NULL byte is in the hostname.
        """
        with pytest.raises(CertificateError):
            DNSPattern.from_bytes(b"www.google.com\0nasty.h4x0r.com")

    def test_catches_ip_address(self):
        """
        IP addresses are invalid and raise a :class:`CertificateError`.
        """
        with pytest.raises(CertificateError):
            DNSPattern.from_bytes(b"192.168.0.0")

    def test_invalid_wildcard(self):
        """
        Integration test with _validate_pattern: catches double wildcards thus
        is used if an wildward is present.
        """
        with pytest.raises(CertificateError):
            DNSPattern.from_bytes(b"*.foo.*")


class TestURIPattern:
    def test_enforces_bytes(self):
        """
        Raise TypeError if unicode is passed.
        """
        with pytest.raises(TypeError):
            URIPattern.from_bytes("sip:foo.com")

    def test_catches_missing_colon(self):
        """
        Raise CertificateError if URI doesn't contain a `:`.
        """
        with pytest.raises(CertificateError):
            URIPattern.from_bytes(b"sip;foo.com")

    def test_catches_wildcards(self):
        """
        Raise CertificateError if URI contains a *.
        """
        with pytest.raises(CertificateError):
            URIPattern.from_bytes(b"sip:*.foo.com")


class TestSRVPattern:
    def test_enforces_bytes(self):
        """
        Raise TypeError if unicode is passed.
        """
        with pytest.raises(TypeError):
            SRVPattern.from_bytes("_mail.example.com")

    def test_catches_missing_underscore(self):
        """
        Raise CertificateError if SRV doesn't start with a `_`.
        """
        with pytest.raises(CertificateError):
            SRVPattern.from_bytes(b"foo.com")

    def test_catches_wildcards(self):
        """
        Raise CertificateError if SRV contains a *.
        """
        with pytest.raises(CertificateError):
            SRVPattern.from_bytes(b"sip:*.foo.com")


class TestValidateDNSWildcardPattern:
    def test_allows_only_one_wildcard(self):
        """
        Raise CertificateError on multiple wildcards.
        """
        with pytest.raises(CertificateError):
            _validate_pattern(b"*.*.com")

    def test_wildcard_must_be_left_most(self):
        """
        Raise CertificateError if wildcard is not in the left-most part.
        """
        for hn in [b"foo.b*r.com", b"foo.bar.c*m", b"foo.*", b"foo.*.com"]:
            with pytest.raises(CertificateError):
                _validate_pattern(hn)

    def test_must_have_at_least_three_parts(self):
        """
        Raise CertificateError if host consists of less than three parts.
        """
        for hn in [
            b"*",
            b"*.com",
            b"*fail.com",
            b"*foo",
            b"foo*",
            b"f*o",
            b"*.example.",
        ]:
            with pytest.raises(CertificateError):
                _validate_pattern(hn)

    def test_valid_patterns(self):
        """
        Does not throw CertificateError on valid patterns.
        """
        for pattern in [
            b"*.bar.com",
            b"*oo.bar.com",
            b"f*.bar.com",
            b"f*o.bar.com",
        ]:
            _validate_pattern(pattern)


class TestIPAddressPattern:
    def test_invalid_ip(self):
        """
        Raises CertificateError on invalid IP addresses.
        """
        with pytest.raises(CertificateError):
            IPAddressPattern.from_bytes(b"127.o.o.1")

    @pytest.mark.parametrize("ip_s", ["1.1.1.1", "::1"])
    def test_verify_equal(self, ip_s):
        """
        Return True if IP addresses are identical.
        """
        ip = ipaddress.ip_address(ip_s)

        assert IPAddress_ID(ip).verify(IPAddressPattern(ip)) is True


class FakeCertID:
    pass


class Fake_ID:
    """
    An ID that accepts exactly on object as pattern.
    """

    def __init__(self, pattern):
        self._pattern = pattern

    def verify(self, other):
        """
        True iff other is the same object as pattern.
        """
        return other is self._pattern


class TestFindMatches:
    def test_one_match(self):
        """
        If there's a match, return a tuple of the certificate id and the
        service id.
        """
        valid_cert_id = FakeCertID()
        valid_id = Fake_ID(valid_cert_id)
        rv = _find_matches(
            [FakeCertID(), valid_cert_id, FakeCertID()], [valid_id]
        )

        assert [
            ServiceMatch(cert_pattern=valid_cert_id, service_id=valid_id)
        ] == rv

    def test_no_match(self):
        """
        If no valid certificate ids are found, return an empty list.
        """
        rv = _find_matches(
            [FakeCertID(), FakeCertID(), FakeCertID()], [Fake_ID(object())]
        )

        assert [] == rv

    def test_multiple_matches(self):
        """
        Return all matches.
        """
        valid_cert_id_1 = FakeCertID()
        valid_cert_id_2 = FakeCertID()
        valid_cert_id_3 = FakeCertID()
        valid_id_1 = Fake_ID(valid_cert_id_1)
        valid_id_2 = Fake_ID(valid_cert_id_2)
        valid_id_3 = Fake_ID(valid_cert_id_3)
        rv = _find_matches(
            [
                FakeCertID(),
                valid_cert_id_1,
                FakeCertID(),
                valid_cert_id_3,
                FakeCertID(),
                valid_cert_id_2,
            ],
            [valid_id_1, valid_id_2, valid_id_3],
        )

        assert [
            ServiceMatch(cert_pattern=valid_cert_id_1, service_id=valid_id_1),
            ServiceMatch(cert_pattern=valid_cert_id_2, service_id=valid_id_2),
            ServiceMatch(cert_pattern=valid_cert_id_3, service_id=valid_id_3),
        ] == rv


class TestIsIPAddress:
    @pytest.mark.parametrize(
        "ip",
        [
            b"127.0.0.1",
            "127.0.0.1",
            "172.16.254.12",
            "*.0.0.1",
            "::1",
            "*::1",
            "2001:0db8:0000:0000:0000:ff00:0042:8329",
            "2001:0db8::ff00:0042:8329",
        ],
    )
    def test_ips(self, ip):
        """
        Returns True for patterns and hosts that could match IP addresses.
        """
        assert _is_ip_address(ip) is True

    @pytest.mark.parametrize(
        "not_ip",
        [
            b"*.twistedmatrix.com",
            b"twistedmatrix.com",
            b"mail.google.com",
            b"omega7.de",
            b"omega7",
            b"127.\xff.0.1",
        ],
    )
    def test_not_ips(self, not_ip):
        """
        Return False for patterns and hosts that aren't IP addresses.
        """
        assert _is_ip_address(not_ip) is False


class TestVerificationError:
    def test_repr_str(self):
        """
        The __str__ and __repr__ methods return something helpful.
        """
        with pytest.raises(VerificationError) as ei:
            raise VerificationError(errors=["foo"])

        assert repr(ei.value) == str(ei.value)
        assert str(ei.value) != ""

    @pytest.mark.parametrize("proto", range(pickle.HIGHEST_PROTOCOL + 1))
    @pytest.mark.parametrize(
        "exc",
        [
            VerificationError(errors=[]),
            VerificationError(errors=[DNSMismatch("example.com")]),
            VerificationError([]),
            VerificationError([DNSMismatch("example.com")]),
        ],
    )
    def test_pickle(self, exc, proto):
        """
        Exceptions can be pickled and unpickled.
        """
        new_exc = pickle.loads(pickle.dumps(exc, proto))

        # Exceptions can't be compared.
        assert exc.__class__ == new_exc.__class__
        assert exc.__dict__ == new_exc.__dict__
