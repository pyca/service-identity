from __future__ import absolute_import, division, print_function

import unittest

from contextlib import contextmanager

from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from OpenSSL.test.util import TestCase

import service_identity

from service_identity import (
    CertificateError,
    DNSPattern,
    DNS_ID,
    SRVMismatchError,
    SRVPattern,
    SRV_ID,
    URIMismatchError,
    URIPattern,
    URI_ID,
    VerificationError,
    _contains_instance_of,
    _find_matches,
    _hostname_matches,
    _validate_pattern,
    eq_attrs,
    extract_ids,
    repr_attrs,
    u,
    verify_service_identity,
)


@contextmanager
def hidden(obj, name):
    """
    Patches away *name* from *obj* and restores it on exit.
    """
    try:
        orig = getattr(obj, name)
        setattr(obj, name, None)
        yield
    finally:
        setattr(obj, name, orig)


class IntegrationTestCase(TestCase):
    """
    Simple integration tests for :func:`verify_hostname` and
    :func:`verify_service_identity`.
    """
    def test_verify_hostname(self):
        """
        It's just a convenience one-liner.  Let's check it doesn't explode b/c
        of some typo.
        """
        service_identity.verify_hostname(CERT_DNS_ONLY, u("twistedmatrix.com"))

    def test_vsi_dns_id_success(self):
        """
        Return pairs of certificate ids and service ids on matches.
        """
        rv = verify_service_identity(extract_ids(CERT_DNS_ONLY),
                                     [DNS_ID(u("twistedmatrix.com"))])
        self.assertEqual(
            [
                (DNSPattern(b"twistedmatrix.com"),
                 DNS_ID(u("twistedmatrix.com")),),
            ], rv
        )

    def test_vsi_integration_dns_id_fail(self):
        """
        Raise VerificationError if no certificate id matches the supplied
        service ids.
        """
        self.assertRaises(
            VerificationError,
            verify_service_identity,
            extract_ids(CERT_DNS_ONLY), [DNS_ID(u("wrong.host"))],
        )

    def test_vsi_contains_srvs_but_does_not_match_one(self):
        """
        Raise if both cert_patterns and service_ids contain at least one SRV-ID
        but none match.  Even if other IDs matched.
        """
        self.assertRaises(
            SRVMismatchError,
            verify_service_identity,
            [DNSPattern(b"example.net"), SRVPattern(b"_mail.example.com")],
            [DNS_ID(u("example.net")), SRV_ID(u("_mail.example.net"))],
        )

    def test_vsi_contains_srvs_and_matches(self):
        """
        If a matching SRV-ID is found, return the tuple within the returned
        list and don't raise an error.
        """
        p = SRVPattern(b"_mail.example.net")
        i = SRV_ID(u("_mail.example.net"))
        rv = verify_service_identity(
            [DNSPattern(b"example.net"), p],
            [DNS_ID(u("example.net")), i],
        )
        self.assertEqual((p, i), rv[1])

    def test_vsi_contains_uris_but_does_not_match_one(self):
        """
        Raise if both cert_patterns and service_ids contain at least one URI-ID
        but none match.  Even if other IDs matched.
        """
        self.assertRaises(
            URIMismatchError,
            verify_service_identity,
            [DNSPattern(b"example.net"), URIPattern(b"http://example.com")],
            [DNS_ID(u("example.net")), URI_ID(u("http://example.net"))],
        )

    def test_vsi_contains_uris_and_matches(self):
        """
        If a matching URI-ID is found, return the tuple within the returned
        list and don't raise an error.
        """
        p = URIPattern(b"sip:example.net")
        uri_id = URI_ID(u("sip:example.net"))
        rv = verify_service_identity(
            [DNSPattern(b"example.net"), p],
            [DNS_ID(u("example.net")), uri_id],
        )
        self.assertEqual((p, uri_id), rv[1])


class ContainsInstanceTestCase(TestCase):
    def test_positive(self):
        """
        If the list contains an object of the type, return True.
        """
        self.assertTrue(
            _contains_instance_of([object(), tuple(), object()], tuple)
        )

    def test_negative(self):
        """
        If the list contains an object of the type, return False.
        """
        self.assertFalse(
            _contains_instance_of([object(), list(), {}], tuple)
        )


class DNS_IDTestCase(TestCase):
    def test_enforces_unicode(self):
        """
        Raise TypeError if pass DNS-ID is not unicode.
        """
        self.assertRaises(TypeError, DNS_ID, b"foo.com")

    def test_handles_missing_idna(self):
        """
        Raise ImportError if idna is missing and a non-ASCII DNS-ID is passed.
        """
        with hidden(service_identity, "idna"):
            self.assertRaises(ImportError, DNS_ID, u("f\xf8\xf8.com"))

    def test_ascii_works_without_idna(self):
        """
        7bit-ASCII DNS-IDs work no matter whether idna is present or not.
        """
        with hidden(service_identity, "idna"):
            dns = DNS_ID(u("foo.com"))
        self.assertEqual(b"foo.com", dns.hostname)

    def test_idna_used_if_available_on_non_ascii(self):
        """
        If idna is installed and a non-ASCII DNS-ID is passed, encode it to
        ASCII.
        """
        # Skip if idna is not present.  E.g. on Python 3.2.
        if not service_identity.idna:
            raise unittest.SkipTest("Missing idna package.")
        dns = DNS_ID(u("f\xf8\xf8.com"))
        self.assertEqual(b'xn--f-5gaa.com', dns.hostname)

    def test_catches_empty(self):
        """
        Empty DNS-IDs raise a :class:`ValueError`.
        """
        self.assertRaises(ValueError, DNS_ID, u(" "))

    def test_catches_ipv4_address(self):
        """
        IP addresses are invalid and raise a :class:`ValueError`.
        """
        self.assertRaises(ValueError, DNS_ID, u("192.168.0.0"))

    def test_catches_ipv6_address(self):
        """
        IP addresses are invalid and raise a :class:`ValueError`.
        """
        self.assertRaises(ValueError, DNS_ID, u("::1"))

    def test_lowercases(self):
        """
        The hostname is lowercased so it can be compared case-insensitively.
        """
        dns_id = DNS_ID(u("hOsTnAmE"))
        self.assertEqual(b"hostname", dns_id.hostname)

    def test_verifies_only_dns(self):
        """
        If anything else than DNSPattern is passed to verify, return False.
        """
        self.assertFalse(
            DNS_ID(u("foo.com")).verify(object())
        )

    def test_simple_match(self):
        """
        Simple integration test with _hostname_matches with a match.
        """
        self.assertTrue(
            DNS_ID(u("foo.com")).verify(DNSPattern(b"foo.com"))
        )

    def test_simple_mismatch(self):
        """
        Simple integration test with _hostname_matches with a mismatch.
        """
        self.assertFalse(
            DNS_ID(u("foo.com")).verify(DNSPattern(b"bar.com"))
        )

    def test_matches(self):
        """
        Valid matches return `True`.
        """
        for cert, actual in [
            (b"www.example.com", b"www.example.com"),
            (b"*.example.com", b"www.example.com"),
            (b"xxx*.example.com", b"xxxwww.example.com"),
            (b"f*.example.com", b"foo.example.com"),
            (b"*oo.bar.com", b"foo.bar.com"),
            (b"fo*oo.bar.com", b"fooooo.bar.com"),
        ]:
            self.assertTrue(
                _hostname_matches(cert, actual)
            )

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
        ]:
            self.assertFalse(
                _hostname_matches(cert, actual)
            )


class URI_IDTestCase(TestCase):
    def test_enforces_unicode(self):
        """
        Raise TypeError if pass URI-ID is not unicode.
        """
        self.assertRaises(TypeError, URI_ID, b"sip:foo.com")

    def test_create_DNS_ID(self):
        """
        The hostname is converted into a DNS_ID object.
        """
        uri_id = URI_ID(u("sip:foo.com"))
        self.assertEqual(DNS_ID(u("foo.com")), uri_id.dns_id)
        self.assertEqual(b"sip", uri_id.protocol)

    def test_lowercases(self):
        """
        The protocol is lowercased so it can be compared case-insensitively.
        """
        uri_id = URI_ID(u("sIp:foo.com"))
        self.assertEqual(b"sip", uri_id.protocol)

    def test_catches_missing_colon(self):
        """
        Raise ValueError if there's no colon within a URI-ID.
        """
        self.assertRaises(ValueError, URI_ID, u("sip;foo.com"))

    def test_is_only_valid_for_uri(self):
        """
        If anything else than an URIPattern is passed to verify, return
        False.
        """
        self.assertFalse(URI_ID(u("sip:foo.com")).verify(object()))

    def test_protocol_mismatch(self):
        """
        If protocol doesn't match, verify returns False.
        """
        self.assertFalse(
            URI_ID(u("sip:foo.com")).verify(URIPattern(b"xmpp:foo.com"))
        )

    def test_dns_mismatch(self):
        """
        If the hostname doesn't match, verify returns False.
        """
        self.assertFalse(
            URI_ID(u("sip:bar.com")).verify(URIPattern(b"sip:foo.com"))
        )

    def test_match(self):
        """
        Accept legal matches.
        """
        for cert, actual in [
            (b"sip:foo.com", u("sip:foo.com")),
        ]:
            self.assertTrue(URI_ID(actual).verify(URIPattern(cert)))


class SRV_IDTestCase(TestCase):
    def test_enforces_unicode(self):
        """
        Raise TypeError if pass srv-ID is not unicode.
        """
        self.assertRaises(TypeError, SRV_ID, b"_mail.example.com")

    def test_create_DNS_ID(self):
        """
        The hostname is converted into a DNS_ID object.
        """
        srv_id = SRV_ID(u("_mail.example.com"))
        self.assertEqual(DNS_ID(u("example.com")), srv_id.dns_id)

    def test_lowercases(self):
        """
        The service name is lowercased so it can be compared
        case-insensitively.
        """
        srv_id = SRV_ID(u("_MaIl.foo.com"))
        self.assertEqual(b"mail", srv_id.name)

    def test_catches_missing_dot(self):
        """
        Raise ValueError if there's no dot within a SRV-ID.
        """
        self.assertRaises(ValueError, SRV_ID, u("_imapsfoocom"))

    def test_catches_missing_underscore(self):
        """
        Raise ValueError if the service is doesn't start with an underscore.
        """
        self.assertRaises(ValueError, SRV_ID, u("imaps.foo.com"))

    def test_is_only_valid_for_SRV(self):
        """
        If anything else than an SRVPattern is passed to verify, return False.
        """
        self.assertFalse(SRV_ID(u("_mail.foo.com")).verify(object()))

    def test_match(self):
        """
        Accept legal matches.
        """
        for cert, actual in [
            (b"_mail.foo.com", u("_mail.foo.com")),
        ]:
            self.assertTrue(SRV_ID(actual).verify(SRVPattern(cert)))

    def test_match_idna(self):
        """
        IDNAs are handled properly.
        """
        # Skip if idna is not present.  E.g. on Python 3.2.
        if not service_identity.idna:
            raise unittest.SkipTest("Missing idna package.")
        self.assertTrue(
            SRV_ID(u("_mail.f\xf8\xf8.com")).verify(
                SRVPattern(b'_mail.xn--f-5gaa.com')
            )
        )

    def test_mismatch_service_name(self):
        """
        If the service name doesn't match, verify returns False.
        """
        self.assertFalse(
            SRV_ID(u("_mail.foo.com")).verify(SRVPattern(b"_xmpp.foo.com"))
        )

    def test_mismatch_dns(self):
        """
        If the dns_id doesn't match, verify returns False.
        """
        self.assertFalse(
            SRV_ID(u("_mail.foo.com")).verify(SRVPattern(b"_mail.bar.com"))
        )


class DNSPatternTestCase(TestCase):
    def test_enforces_bytes(self):
        """
        Raise TypeError if unicode is passed.
        """
        self.assertRaises(TypeError, DNSPattern, u("foo.com"))

    def test_catches_empty(self):
        """
        Empty DNS-IDs raise a :class:`CertificateError`.
        """
        self.assertRaises(
            CertificateError,
            DNSPattern, b" ",
        )

    def test_catches_NULL_bytes(self):
        """
        Raise :class:`CertificateError` if a NULL byte is in the hostname.
        """
        self.assertRaises(
            CertificateError,
            DNSPattern, b"www.google.com\0nasty.h4x0r.com",
        )

    def test_catches_ip_address(self):
        """
        IP addresses are invalid and raise a :class:`CertificateError`.
        """
        self.assertRaises(
            CertificateError,
            DNSPattern, b"192.168.0.0",
        )


class URIPatternTestCase(TestCase):
    def test_enforces_bytes(self):
        """
        Raise TypeError if unicode is passed.
        """
        self.assertRaises(TypeError, URIPattern, u("sip:foo.com"))

    def test_catches_missing_colon(self):
        """
        Raise CertificateError if URI doesn't contain a `:`.
        """
        self.assertRaises(CertificateError, URIPattern, b"sip;foo.com")

    def test_catches_wildcards(self):
        """
        Raise CertificateError if URI contains a *.
        """
        self.assertRaises(CertificateError, URIPattern, b"sip:*.foo.com")


class SRVPatternTestCase(TestCase):
    def test_enforces_bytes(self):
        """
        Raise TypeError if unicode is passed.
        """
        self.assertRaises(TypeError, SRVPattern, u("_mail.example.com"))

    def test_catches_missing_underscore(self):
        """
        Raise CertificateError if SRV doesn't start with a `_`.
        """
        self.assertRaises(CertificateError, SRVPattern, b"foo.com")

    def test_catches_wildcards(self):
        """
        Raise CertificateError if SRV contains a *.
        """
        self.assertRaises(CertificateError, SRVPattern, b"sip:*.foo.com")


class ValidateDNSWildcardPatternTestCase(TestCase):
    def test_allows_only_one_wildcard(self):
        """
        Raise CertificateError on multiple wildcards.
        """
        self.assertRaises(
            CertificateError,
            _validate_pattern,
            b"*.*.com",
        )

    def test_wildcard_must_be_left_most(self):
        """
        Raise CertificateError if wildcard is not in the left-most part.
        """
        for hn in [
            b"foo.b*r.com",
            b"foo.bar.c*m",
            b"foo.*",
            b"foo.*.com",
        ]:
            self.assertRaises(
                CertificateError,
                _validate_pattern,
                hn,
            )

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
            self.assertRaises(
                CertificateError,
                _validate_pattern,
                hn,
            )

    def test_valid_patterns(self):
        """
        Does not throw CertificateError on valid patterns.
        """
        for pattern in [
            b"*.bar.com",
            b"*oo.bar.com",
            b"f*.bar.com",
            b"f*o.bar.com"
        ]:
            _validate_pattern(pattern)


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


class FakeCertID(object):
    pass


class Fake_ID(object):
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


class FindMatchesTestCase(TestCase):
    def test_one_match(self):
        """
        If there's a match, return a tuple of the certificate id and the
        service id.
        """
        valid_cert_id = FakeCertID()
        valid_id = Fake_ID(valid_cert_id)
        rv = _find_matches([
            FakeCertID(),
            valid_cert_id,
            FakeCertID(),
        ], [valid_id])

        self.assertEqual(
            [(valid_cert_id, valid_id,)], rv
        )

    def test_no_match(self):
        """
        If no valid certificate ids are found, return an empty list.
        """
        rv = _find_matches([
            FakeCertID(),
            FakeCertID(),
            FakeCertID(),
        ], [Fake_ID(object())])

        self.assertEqual([], rv)

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
        rv = _find_matches([
            FakeCertID(),
            valid_cert_id_1,
            FakeCertID(),
            valid_cert_id_3,
            FakeCertID(),
            valid_cert_id_2,
        ], [valid_id_1, valid_id_2, valid_id_3])

        self.assertEqual(
            [
                (valid_cert_id_1, valid_id_1,),
                (valid_cert_id_2, valid_id_2,),
                (valid_cert_id_3, valid_id_3,),
            ], rv
        )


@eq_attrs(["a", "b"])
class EqC(object):
    def __init__(self, a, b):
        self.a = a
        self.b = b


class EqAttrsTestCase(TestCase):
    def test_equal(self):
        """
        Equal objects are detected as equal.
        """
        self.assertTrue(EqC(1, 2) == EqC(1, 2))
        self.assertFalse(EqC(1, 2) != EqC(1, 2))

    def test_unequal_same_class(self):
        """
        Unequal objects of correct type are detected as unequal.
        """
        self.assertTrue(EqC(1, 2) != EqC(2, 1))
        self.assertFalse(EqC(1, 2) == EqC(2, 1))

    def test_unequal_different_class(self):
        """
        Unequal objects of differnt type are detected even if their attributes
        match.
        """
        class NotEqC(object):
            a = 1
            b = 2
        self.assertTrue(EqC(1, 2) != NotEqC())
        self.assertFalse(EqC(1, 2) == NotEqC())

    def test_lt(self):
        """
        __lt__ compares objects as tuples of attribute values.
        """
        for a, b in [
            ((1, 2),  (2, 1)),
            ((1, 2),  (1, 3)),
            (("a", "b"), ("b", "a")),
        ]:
            self.assertTrue(EqC(*a) < EqC(*b))

    def test_le(self):
        """
        __le__ compares objects as tuples of attribute values.
        """
        for a, b in [
            ((1, 2),  (2, 1)),
            ((1, 2),  (1, 3)),
            ((1, 1),  (1, 1)),
            (("a", "b"), ("b", "a")),
            (("a", "b"), ("a", "b")),
        ]:
            self.assertTrue(EqC(*a) <= EqC(*b))

    def test_gt(self):
        """
        __gt__ compares objects as tuples of attribute values.
        """
        for a, b in [
            ((2, 1), (1, 2)),
            ((1, 3), (1, 2)),
            (("b", "a"), ("a", "b")),
        ]:
            self.assertTrue(EqC(*a) > EqC(*b))

    def test_ge(self):
        """
        __ge__ compares objects as tupges of attribute values.
        """
        for a, b in [
            ((2, 1), (1, 2)),
            ((1, 3), (1, 2)),
            ((1, 1), (1, 1)),
            (("b", "a"), ("a", "b")),
            (("a", "b"), ("a", "b")),
        ]:
            self.assertTrue(EqC(*a) >= EqC(*b))


@repr_attrs(["a", "b"])
class ReprC(object):
    def __init__(self, a, b):
        self.a = a
        self.b = b


class ReprAttrsTestCase(TestCase):
    def test_repr(self):
        """
        Test repr returns a sensible value.
        """
        self.assertEqual("<ReprC(a=1, b=2)>", repr(ReprC(1, 2)))


# Test certificates

PEM_DNS_ONLY = """\
-----BEGIN CERTIFICATE-----
MIIGbjCCBVagAwIBAgIDCesrMA0GCSqGSIb3DQEBBQUAMIGMMQswCQYDVQQGEwJJ
TDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0
YWwgQ2VydGlmaWNhdGUgU2lnbmluZzE4MDYGA1UEAxMvU3RhcnRDb20gQ2xhc3Mg
MSBQcmltYXJ5IEludGVybWVkaWF0ZSBTZXJ2ZXIgQ0EwHhcNMTMwNDEwMTk1ODA5
WhcNMTQwNDExMTkyODAwWjB1MRkwFwYDVQQNExBTN2xiQ3Q3TjJSNHQ5bzhKMQsw
CQYDVQQGEwJVUzEeMBwGA1UEAxMVd3d3LnR3aXN0ZWRtYXRyaXguY29tMSswKQYJ
KoZIhvcNAQkBFhxwb3N0bWFzdGVyQHR3aXN0ZWRtYXRyaXguY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxUH8iDxIEiDcMQb8kr/JTYXDGuE8ISQA
uw/gBqpvHIvCgPBkZpvjQLA23rnUZm1S3VG5MIq6gZVdtl9LFIfokMPGgY9EZng8
BaI+6Y36cMtubnzW53OZb7yLQQyg+rjuwjvJOY33ZulEthxhdB3km1Leb67iE9v7
dpyKeJ/8m2IWD37HCtXIEnp9ZqWOZkAPzlzDt6oNxj0s/l3z23+XqZdr+kmlh9U+
VWBTPppO4AJNwSqbBd0PgIozbYsp6urxSr40YQkIYFOOZQNs7HETJE71Ia7DQcUD
kUF1jZSYZnhVQwGPisqQLGodt9q9p2BhpSf0cUm02uKKzYi5A2h7UQIDAQABo4IC
7TCCAukwCQYDVR0TBAIwADALBgNVHQ8EBAMCA6gwEwYDVR0lBAwwCgYIKwYBBQUH
AwEwHQYDVR0OBBYEFGeuUvDrFHkl7Krl/+rlv1FsnsU6MB8GA1UdIwQYMBaAFOtC
NNCYsKuf9BtrCPfMZC7vDixFMDMGA1UdEQQsMCqCFXd3dy50d2lzdGVkbWF0cml4
LmNvbYIRdHdpc3RlZG1hdHJpeC5jb20wggFWBgNVHSAEggFNMIIBSTAIBgZngQwB
AgEwggE7BgsrBgEEAYG1NwECAzCCASowLgYIKwYBBQUHAgEWImh0dHA6Ly93d3cu
c3RhcnRzc2wuY29tL3BvbGljeS5wZGYwgfcGCCsGAQUFBwICMIHqMCcWIFN0YXJ0
Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MAMCAQEagb5UaGlzIGNlcnRpZmlj
YXRlIHdhcyBpc3N1ZWQgYWNjb3JkaW5nIHRvIHRoZSBDbGFzcyAxIFZhbGlkYXRp
b24gcmVxdWlyZW1lbnRzIG9mIHRoZSBTdGFydENvbSBDQSBwb2xpY3ksIHJlbGlh
bmNlIG9ubHkgZm9yIHRoZSBpbnRlbmRlZCBwdXJwb3NlIGluIGNvbXBsaWFuY2Ug
b2YgdGhlIHJlbHlpbmcgcGFydHkgb2JsaWdhdGlvbnMuMDUGA1UdHwQuMCwwKqAo
oCaGJGh0dHA6Ly9jcmwuc3RhcnRzc2wuY29tL2NydDEtY3JsLmNybDCBjgYIKwYB
BQUHAQEEgYEwfzA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Auc3RhcnRzc2wuY29t
L3N1Yi9jbGFzczEvc2VydmVyL2NhMEIGCCsGAQUFBzAChjZodHRwOi8vYWlhLnN0
YXJ0c3NsLmNvbS9jZXJ0cy9zdWIuY2xhc3MxLnNlcnZlci5jYS5jcnQwIwYDVR0S
BBwwGoYYaHR0cDovL3d3dy5zdGFydHNzbC5jb20vMA0GCSqGSIb3DQEBBQUAA4IB
AQCN85dUStYjHmWdXthpAqJcS3KD2JP6N9egOz7FTcToXLW8Kl5a2SUVaJv8Fzs+
wtbPJQSm0LyGtfdrR6iKFPf28Vm/VkYXPiOV08GD9B7yl1SjktXOsGMPlOHU8YQZ
DEsHOrRvaZBSA1VtBQjYnoO0pDVu9QwDLAPLFvFice2PN803HuMFIwcuQSIrh4nq
PqwitBZ6nPPHz7aSiAut/+txK3EZll0d+hl0H3Phd+ICeITYhNkLe90k7l1IFpET
fJiBDvG/iDAJISgkrR1heuX/e+yWfx7RvqGlMLIE35d+0MhWy92Jzejbl8fJdr4C
Kulh/pV07MWAUZxscUPtWmPo
-----END CERTIFICATE-----"""

PEM_CN_ONLY = """\
-----BEGIN CERTIFICATE-----
MIIGdDCCBVygAwIBAgIKGOC4tAABAAAx0TANBgkqhkiG9w0BAQUFADCBgDETMBEG
CgmSJomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEUMBIG
CgmSJomT8ixkARkWBGNvcnAxFzAVBgoJkiaJk/IsZAEZFgdyZWRtb25kMR8wHQYD
VQQDExZNU0lUIE1hY2hpbmUgQXV0aCBDQSAyMB4XDTEzMDExMjAwMDc0MVoXDTE1
MDExMjAwMDc0MVoweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQH
EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDjAMBgNV
BAsTBU1TQ09NMRowGAYDVQQDExF3d3cubWljcm9zb2Z0LmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAJ+h4bQ7OlcO0M9UvM0Y2LISEzGkTDc9CT7v
c91kI2GOlR/kbI1AUmJu3g6Cv0wqz4b9QT6BdXSE+WAxUM/yk4mf1HhkJtbSwucb
AQAtgq0iC1u6mDDXH2sl/NUB4VKSGryIYYdRVHduZlFkAHmxwcmxyQt6BQykXl7G
NkftiJZtVci/ZRPaBrFnkZjZCbJH+capx0v9hmBTLPVAGyIF5TwF1aldXT367S76
QGGn6UnI0O5Cua7GU1JDVmbPus0kgRTazvyW4g17jGFtNJTy43UqlX7TZ8B76OZC
sqoVxJblVh7I0WDcDFwIrSWiUEFc9i05g1g49xK8Y7tph8tbwv8CAwEAAaOCAvUw
ggLxMAsGA1UdDwQEAwIEsDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUK9tKP5ACSJ4PiSHi
60pzHuAPhWswHwYDVR0jBBgwFoAU69sRXvgJntjWYpz9Yp3jhEoo4Scwge4GA1Ud
HwSB5jCB4zCB4KCB3aCB2oZPaHR0cDovL21zY3JsLm1pY3Jvc29mdC5jb20vcGtp
L21zY29ycC9jcmwvTVNJVCUyME1hY2hpbmUlMjBBdXRoJTIwQ0ElMjAyKDEpLmNy
bIZNaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9tc2NvcnAvY3JsL01TSVQl
MjBNYWNoaW5lJTIwQXV0aCUyMENBJTIwMigxKS5jcmyGOGh0dHA6Ly9jb3JwcGtp
L2NybC9NU0lUJTIwTWFjaGluZSUyMEF1dGglMjBDQSUyMDIoMSkuY3JsMIGtBggr
BgEFBQcBAQSBoDCBnTBVBggrBgEFBQcwAoZJaHR0cDovL3d3dy5taWNyb3NvZnQu
Y29tL3BraS9tc2NvcnAvTVNJVCUyME1hY2hpbmUlMjBBdXRoJTIwQ0ElMjAyKDEp
LmNydDBEBggrBgEFBQcwAoY4aHR0cDovL2NvcnBwa2kvYWlhL01TSVQlMjBNYWNo
aW5lJTIwQXV0aCUyMENBJTIwMigxKS5jcnQwPwYJKwYBBAGCNxUHBDIwMAYoKwYB
BAGCNxUIg8+JTa3yAoWhnwyC+sp9geH7dIFPg8LthQiOqdKFYwIBZAIBCjAnBgkr
BgEEAYI3FQoEGjAYMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMA0GCSqGSIb3DQEB
BQUAA4IBAQBgwMY9qix/FoBY3QBHTNFVf+d6siaBWoQjwBXDQlPXLmowbt97j62Z
N6OogRP2V+ivnBcybucJTJE6zTxrGZ7hNeC9T3v34Q1OMezWiZf+jktNZvqiXctm
Dh774lt5S9X2C+k1e9K8YrnNb8PNeKkX/vVX9MZzn2aQqU34dOg6vVnrq0pBrq/Y
TJcPG4yq3kFR3ONTZb5JgE8EV1G43vW/LNQbEbQUgVtiKRapEs7rSSws6Jj47MUc
on6HgPTtfuJGMNWFTiw7nZTM8mLXsXBMePSgq8PkKPmPkB3KET/OitmePmhk4l+S
eMkNCM6YlrLcDF4fCLSjWYhoktmSJZnW
-----END CERTIFICATE-----
"""


PEM_OTHER_NAME = """\
-----BEGIN CERTIFICATE-----
MIID/DCCAuSgAwIBAgIJAIS0TSddIw6cMA0GCSqGSIb3DQEBBQUAMGwxFDASBgNV
BAMTC2V4YW1wbGUuY29tMSAwHgYJKoZIhvcNAQkBFhFib2d1c0BleGFtcGxlLmNv
bTEUMBIGA1UEChMLRXhhbXBsZSBJbmMxDzANBgNVBAcTBkJlcmxpbjELMAkGA1UE
BhMCREUwHhcNMTQwMzA2MTYyNTA5WhcNMTUwMzA2MTYyNTA5WjBsMRQwEgYDVQQD
EwtleGFtcGxlLmNvbTEgMB4GCSqGSIb3DQEJARYRYm9ndXNAZXhhbXBsZS5jb20x
FDASBgNVBAoTC0V4YW1wbGUgSW5jMQ8wDQYDVQQHEwZCZXJsaW4xCzAJBgNVBAYT
AkRFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGQUcOc8cAdzSJbk
0eCHA1qBY2XwRG8YQzihgQS8Ey+3j69Xf0mtWOlL6v23v8J1ilA7ERs87Y4nbV/9
GJVhC/jTMZmrC6ogwtVIl1wL8sTiHaQZ/4pbpx57YW3qCdefLQrZqAMUgAe20z0G
YVU97u5EGXHYahG4TnB3xN6Qd3BGKP7K69Lb7ZOES2Esq533AZxZShseYR4JNYAc
2anag2/DpHw6k8ZaxtWHR4SmxlkCoW5IPK0YypeUY91PFY+dxJQEewtisfALKltE
SYnOTWkc0K9YuLuYVogx0K285wX4/Yha2wyo6KSAm0txJayOhcrEP2/34aWCl62m
xOtPbQIDAQABo4GgMIGdMIGaBgNVHREEgZIwgY+CDSouZXhhbXBsZS5uZXSCC2V4
YW1wbGUuY29thwTAqAABhxAAEwAAAAAAAAAAAAAAAAAXhhNodHRwOi8vZXhhbXBs
ZS5jb20voCYGCCsGAQUFBwgHoBoWGF94bXBwLWNsaWVudC5leGFtcGxlLm5ldKAc
BggrBgEFBQcIBaAQDA5pbS5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQUFAAOCAQEA
ACVQcgEKzXEw0M9mmVFFXL2SyDk/4oaDFZbnNfyUp+H7bnxdVBG2M3DzQQLw5yH5
k4GNPvHOKshBbaFcZWiG1sdrfQJy/UjIWnaC5410npfBv7kJWafKKxZzMq3gp4rd
jPO2LxuWcYVOnUtA3CBe12tRV7ynGU8KmKOsU9bOWhUKo8DJ4a6XHB+YwXeOTPyU
mG7XBpQebT01I3OijFJ+apKR2ubjwZE8l1+BAlTzHyUmmcTTWTQk8FTFcP3nZuIr
VyudDBMASs4yVGHzQxmMalYYzd7ZDzM1NrgfG1KyKWqZEA0MzUxiYdUbZN79xL52
EyKUOXPHw78G6zsVmAE1Aw==
-----END CERTIFICATE-----"""

CERT_DNS_ONLY = load_certificate(FILETYPE_PEM, PEM_DNS_ONLY)
CERT_CN_ONLY = load_certificate(FILETYPE_PEM, PEM_CN_ONLY)
CERT_OTHER_NAME = load_certificate(FILETYPE_PEM, PEM_OTHER_NAME)


if __name__ == '__main__':
    from unittest import main
    main()
