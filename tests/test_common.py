from __future__ import absolute_import, division, print_function

import unittest

from contextlib import contextmanager

from OpenSSL.test.util import TestCase

import service_identity._common

from service_identity._common import (
    CertificateError,
    DNSMismatchError,
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
    _is_ip_address,
    _validate_pattern,
    verify_service_identity,
)
from service_identity.pyopenssl import extract_ids
from .util import CERT_DNS_ONLY


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
    Simple integration tests for :func:`verify_service_identity`.
    """
    def test_vsi_dns_id_success(self):
        """
        Return pairs of certificate ids and service ids on matches.
        """
        rv = verify_service_identity(extract_ids(CERT_DNS_ONLY),
                                     [DNS_ID(u"twistedmatrix.com")])
        self.assertEqual(
            [
                (DNSPattern(b"twistedmatrix.com"),
                 DNS_ID(u"twistedmatrix.com"),),
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
            extract_ids(CERT_DNS_ONLY), [DNS_ID(u"wrong.host")],
        )

    def test_vsi_contains_dnss_but_does_not_match_one(self):
        """
        Raise if both cert_patterns and service_ids contain at least one DNS-ID
        but none match.  Even if other IDs matched.
        """
        self.assertRaises(
            DNSMismatchError,
            verify_service_identity,
            [SRVPattern(b"_mail.example.net"), DNSPattern(b"example.com")],
            [SRV_ID(u"_mail.example.net"), DNS_ID(u"example.net")],
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
            [DNS_ID(u"example.net"), SRV_ID(u"_mail.example.net")],
        )

    def test_vsi_contains_srvs_and_matches(self):
        """
        If a matching SRV-ID is found, return the tuple within the returned
        list and don't raise an error.
        """
        p = SRVPattern(b"_mail.example.net")
        i = SRV_ID(u"_mail.example.net")
        rv = verify_service_identity(
            [DNSPattern(b"example.net"), p],
            [DNS_ID(u"example.net"), i],
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
            [DNS_ID(u"example.net"), URI_ID(u"http://example.net")],
        )

    def test_vsi_contains_uris_and_matches(self):
        """
        If a matching URI-ID is found, return the tuple within the returned
        list and don't raise an error.
        """
        p = URIPattern(b"sip:example.net")
        uri_id = URI_ID(u"sip:example.net")
        rv = verify_service_identity(
            [DNSPattern(b"example.net"), p],
            [DNS_ID(u"example.net"), uri_id],
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
        with hidden(service_identity._common, "idna"):
            self.assertRaises(ImportError, DNS_ID, u"f\xf8\xf8.com")

    def test_ascii_works_without_idna(self):
        """
        7bit-ASCII DNS-IDs work no matter whether idna is present or not.
        """
        with hidden(service_identity._common, "idna"):
            dns = DNS_ID(u"foo.com")
        self.assertEqual(b"foo.com", dns.hostname)

    def test_idna_used_if_available_on_non_ascii(self):
        """
        If idna is installed and a non-ASCII DNS-ID is passed, encode it to
        ASCII.
        """
        # Skip if idna is not present.  E.g. on Python 3.2.
        if not service_identity._common.idna:
            raise unittest.SkipTest("Missing idna package.")
        dns = DNS_ID(u"f\xf8\xf8.com")
        self.assertEqual(b'xn--f-5gaa.com', dns.hostname)

    def test_catches_empty(self):
        """
        Empty DNS-IDs raise a :class:`ValueError`.
        """
        self.assertRaises(ValueError, DNS_ID, u" ")

    def test_catches_invalid_chars(self):
        """
        Invalid chars as DNS-IDs raise a :class:`ValueError`.
        """
        self.assertRaises(ValueError, DNS_ID, u"host,name")

    def test_catches_ipv4_address(self):
        """
        IP addresses are invalid and raise a :class:`ValueError`.
        """
        self.assertRaises(ValueError, DNS_ID, u"192.168.0.0")

    def test_catches_ipv6_address(self):
        """
        IP addresses are invalid and raise a :class:`ValueError`.
        """
        self.assertRaises(ValueError, DNS_ID, u"::1")

    def test_lowercases(self):
        """
        The hostname is lowercased so it can be compared case-insensitively.
        """
        dns_id = DNS_ID(u"hOsTnAmE")
        self.assertEqual(b"hostname", dns_id.hostname)

    def test_verifies_only_dns(self):
        """
        If anything else than DNSPattern is passed to verify, return False.
        """
        self.assertFalse(
            DNS_ID(u"foo.com").verify(object())
        )

    def test_simple_match(self):
        """
        Simple integration test with _hostname_matches with a match.
        """
        self.assertTrue(
            DNS_ID(u"foo.com").verify(DNSPattern(b"foo.com"))
        )

    def test_simple_mismatch(self):
        """
        Simple integration test with _hostname_matches with a mismatch.
        """
        self.assertFalse(
            DNS_ID(u"foo.com").verify(DNSPattern(b"bar.com"))
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
        uri_id = URI_ID(u"sip:foo.com")
        self.assertEqual(DNS_ID(u"foo.com"), uri_id.dns_id)
        self.assertEqual(b"sip", uri_id.protocol)

    def test_lowercases(self):
        """
        The protocol is lowercased so it can be compared case-insensitively.
        """
        uri_id = URI_ID(u"sIp:foo.com")
        self.assertEqual(b"sip", uri_id.protocol)

    def test_catches_missing_colon(self):
        """
        Raise ValueError if there's no colon within a URI-ID.
        """
        self.assertRaises(ValueError, URI_ID, u"sip;foo.com")

    def test_is_only_valid_for_uri(self):
        """
        If anything else than an URIPattern is passed to verify, return
        False.
        """
        self.assertFalse(URI_ID(u"sip:foo.com").verify(object()))

    def test_protocol_mismatch(self):
        """
        If protocol doesn't match, verify returns False.
        """
        self.assertFalse(
            URI_ID(u"sip:foo.com").verify(URIPattern(b"xmpp:foo.com"))
        )

    def test_dns_mismatch(self):
        """
        If the hostname doesn't match, verify returns False.
        """
        self.assertFalse(
            URI_ID(u"sip:bar.com").verify(URIPattern(b"sip:foo.com"))
        )

    def test_match(self):
        """
        Accept legal matches.
        """
        for cert, actual in [
            (b"sip:foo.com", u"sip:foo.com"),
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
        srv_id = SRV_ID(u"_mail.example.com")
        self.assertEqual(DNS_ID(u"example.com"), srv_id.dns_id)

    def test_lowercases(self):
        """
        The service name is lowercased so it can be compared
        case-insensitively.
        """
        srv_id = SRV_ID(u"_MaIl.foo.com")
        self.assertEqual(b"mail", srv_id.name)

    def test_catches_missing_dot(self):
        """
        Raise ValueError if there's no dot within a SRV-ID.
        """
        self.assertRaises(ValueError, SRV_ID, u"_imapsfoocom")

    def test_catches_missing_underscore(self):
        """
        Raise ValueError if the service is doesn't start with an underscore.
        """
        self.assertRaises(ValueError, SRV_ID, u"imaps.foo.com")

    def test_is_only_valid_for_SRV(self):
        """
        If anything else than an SRVPattern is passed to verify, return False.
        """
        self.assertFalse(SRV_ID(u"_mail.foo.com").verify(object()))

    def test_match(self):
        """
        Accept legal matches.
        """
        for cert, actual in [
            (b"_mail.foo.com", u"_mail.foo.com"),
        ]:
            self.assertTrue(SRV_ID(actual).verify(SRVPattern(cert)))

    def test_match_idna(self):
        """
        IDNAs are handled properly.
        """
        # Skip if idna is not present.  E.g. on Python 3.2.
        if not service_identity._common.idna:
            raise unittest.SkipTest("Missing idna package.")
        self.assertTrue(
            SRV_ID(u"_mail.f\xf8\xf8.com").verify(
                SRVPattern(b'_mail.xn--f-5gaa.com')
            )
        )

    def test_mismatch_service_name(self):
        """
        If the service name doesn't match, verify returns False.
        """
        self.assertFalse(
            SRV_ID(u"_mail.foo.com").verify(SRVPattern(b"_xmpp.foo.com"))
        )

    def test_mismatch_dns(self):
        """
        If the dns_id doesn't match, verify returns False.
        """
        self.assertFalse(
            SRV_ID(u"_mail.foo.com").verify(SRVPattern(b"_mail.bar.com"))
        )


class DNSPatternTestCase(TestCase):
    def test_enforces_bytes(self):
        """
        Raise TypeError if unicode is passed.
        """
        self.assertRaises(TypeError, DNSPattern, u"foo.com")

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

    def test_invalid_wildcard(self):
        """
        Integration test with _validate_pattern: catches double wildcards thus
        is used if an wildward is present.
        """
        self.assertRaises(
            CertificateError,
            DNSPattern, b"*.foo.*"
        )


class URIPatternTestCase(TestCase):
    def test_enforces_bytes(self):
        """
        Raise TypeError if unicode is passed.
        """
        self.assertRaises(TypeError, URIPattern, u"sip:foo.com")

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
        self.assertRaises(TypeError, SRVPattern, u"_mail.example.com")

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


class IsIPAddressTestCase(TestCase):
    def test_ips(self):
        """
        Returns True for patterns and hosts that could match IP addresses.
        """
        for s in [
            b"127.0.0.1",
            u"127.0.0.1",
            b"172.16.254.12",
            b"*.0.0.1",
            b"::1",
            b"*::1",
            b"2001:0db8:0000:0000:0000:ff00:0042:8329",
            b"2001:0db8::ff00:0042:8329",
            b"3534232",
        ]:
            self.assertTrue(_is_ip_address(s),
                            "Not detected {0!r}".format(s))

    def test_no_ips(self):
        """
        Return False for patterns and hosts that aren't IP addresses.
        """
        for s in [
            b"*.twistedmatrix.com",
            b"twistedmatrix.com",
            b"mail.google.com",
            b"omega7.de",
            b"omega7",
        ]:
            self.assertFalse(_is_ip_address(s),
                             "False positive {0!r}".format(s))
