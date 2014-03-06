# -*- test-case-name: test_service_identity -*-

"""
Verify service identities.
"""

from __future__ import absolute_import, division, print_function

__version__ = "0.1"
__author__ = "Hynek Schlawack"
__license__ = "MIT"

import sys

from pyasn1.codec.der.decoder import decode
from pyasn1.type.char import IA5String
from pyasn1.type.univ import ObjectIdentifier
from pyasn1_modules.rfc2459 import GeneralNames

try:
    import idna
except ImportError:  # pragma: nocover
    idna = None


# Avoid depending on any particular Python 3 compatibility approach.  This
# module ought to be drop-in.
PY3 = sys.version_info[0] == 3
if PY3:  # pragma: nocover
    text_type = str

    def u(s):
        return s
else:
    text_type = unicode

    def u(s):
        return unicode(s.replace(r'\\', r'\\\\'), "unicode_escape")


class VerificationError(Exception):
    """
    Verification failed.
    """


class CertificateError(VerificationError):
    """
    Certificate contains invalid or unexpected data.
    """


class DNSMismatchError(VerificationError):
    """
    DNS-IDs were present but none matched.
    """


class SRVMismatchError(VerificationError):
    """
    SRV-IDs were present but none matched.
    """


class URIMismatchError(VerificationError):
    """
    URI-IDs were present but none matched.
    """


def verify_hostname(cert, hostname):
    """
    Verify whether *cert* is valid for *hostname*.

    :param cert: The certificate which is to be verified.
    :type cert: :class:`OpenSSL.SSL.X509`

    :param hostname: Hostname to check for.
    :type hostname: `unicode`

    :raises VerificationError: if *cert* is invalid for *hostname*

    :return: `None`
    """
    verify_service_identity(extract_ids(cert), [DNS_ID(hostname)])


def verify_service_identity(cert_patterns, service_ids):
    """
    Verify whether *cert* is valid for *some* ID within *service_ids*.

    :type cert_patters: List of service ID patterns usually extracted
        from a certificate.
    :type service_ids: `list` of service ID classes like :class:`DNS_ID`.

    :raises URIMismatchError: If at least one :class:`URIPattern` and at least
        one :class:`URI_ID` are specified but none of them match.

    :raises SRVMismatchError: If at least one :class:`SRVPattern` and at least
        one :class:`SRV_ID` are specified but none of them match.

    :raises URIMismatchError: If at least one :class:`URIPattern` and at least
        one :class:`URI_ID` are specified but none of them match.

    :raises VerificationError: If no matches are found at all.

    :return: A list of tuples of matching ``(certificate_pattern,
        service_id)``.
    """
    matched_ids = _find_matches(cert_patterns, service_ids)
    if not matched_ids:
        raise VerificationError(
            "No service reference ID could be validated against certificate."
        )

    for sid in service_ids:
        if (
            _contains_instance_of(cert_patterns, sid.pattern_class)
            and not _contains_instance_of((i for (p, i) in matched_ids),
                                          sid.__class__)
        ):
            raise sid.exc_on_mismatch

    return matched_ids


def _contains_instance_of(l, cl):
    """
    :param l: iterable
    :param cl: type
    """
    for e in l:
        if isinstance(e, cl):
            return True
    return False


def extract_ids(cert):
    """
    Extract all valid IDs from a certificate for service verification.

    If *cert* doesn't contain any identifiers, the ``CN``s are used as DNS-IDs
    as fallback.

    :param cert: The certificate to be dissected.
    :type cert: :class:`OpenSSL.SSL.X509`

    :return: List of IDs.
    """
    ids = []
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b"subjectAltName":
            names, _ = decode(ext.get_data(), asn1Spec=GeneralNames())
            for n in names:
                name_string = n.getName()
                if name_string == "dNSName":
                    ids.append(DNSPattern(n.getComponent().asOctets()))
                elif name_string == "uniformResourceIdentifier":
                    ids.append(URIPattern(n.getComponent().asOctets()))
                elif name_string == "otherName":
                    comp = n.getComponent()
                    oid = comp.getComponentByPosition(0)
                    # 1.3.6.1.5.5.7.8.7 = id-on-dnsSRV
                    if oid == ObjectIdentifier('1.3.6.1.5.5.7.8.7'):
                        srv, _ = decode(comp.getComponentByPosition(1))
                        if isinstance(srv, IA5String):
                            ids.append(SRVPattern(srv.asOctets()))
                        else:  # pragma: nocover
                            raise CertificateError(
                                "Unexpected certificate content."
                            )

    if not ids:
        # http://tools.ietf.org/search/rfc6125#section-6.4.4
        # A client MUST NOT seek a match for a reference identifier of CN-ID if
        # the presented identifiers include a DNS-ID, SRV-ID, URI-ID, or any
        # application-specific identifier types supported by the client.
        ids = [DNSPattern(comp[1])
               for comp
               in cert.get_subject().get_components()
               if comp[0] == b"CN"]
    return ids


def eq_attrs(attrs):
    """
    Adds __eq__, and __ne__ methods based on *attrs* and same type.

    __lt__, __le__, __gt__, and __ge__ compare the objects as if it were tuples
    of attrs.

    :param attrs: Attributes that have to be equal to make two instances equal.
    :type attrs: `list` of native strings
    """
    def wrap(cl):
        def eq(self, other):
            if isinstance(other, self.__class__):
                return all(
                    getattr(self, a) == getattr(other, a)
                    for a in attrs
                )
            else:
                return False

        def ne(self, other):
            return not eq(self, other)

        def attrs_to_tuple(obj):
            return tuple(getattr(obj, a) for a in attrs)

        def lt(self, other):
            return attrs_to_tuple(self) < attrs_to_tuple(other)

        def le(self, other):
            return attrs_to_tuple(self) <= attrs_to_tuple(other)

        def gt(self, other):
            return attrs_to_tuple(self) > attrs_to_tuple(other)

        def ge(self, other):
            return attrs_to_tuple(self) >= attrs_to_tuple(other)

        cl.__eq__ = eq
        cl.__ne__ = ne
        cl.__lt__ = lt
        cl.__le__ = le
        cl.__gt__ = gt
        cl.__ge__ = ge

        return cl
    return wrap


def repr_attrs(attrs):
    """
    Adds a __repr__ method that returns a sensible representation based on
    *attrs*.
    """
    def wrap(cl):
        def repr_(self):
            return "<{0}({1})>".format(
                self.__class__.__name__,
                ", ".join(a + "=" + repr(getattr(self, a)) for a in attrs)
            )

        cl.__repr__ = repr_
        return cl

    return wrap


def magic_attrs(attrs):
    """
    Combine :func:`eq_attrs` and :func:`repr_attrs` to avoid code duplication.
    """
    def wrap(cl):
        return eq_attrs(attrs)(repr_attrs(attrs)(cl))
    return wrap


@magic_attrs(["pattern"])
class DNSPattern(object):
    """
    A DNS pattern as extracted from certificates.
    """
    def __init__(self, pattern):
        """
        :type pattern: `bytes`
        """
        if not isinstance(pattern, bytes):
            raise TypeError("The DNS pattern must be a bytes string.")

        pattern = pattern.strip()

        if pattern == b"" or pattern[-1] in b"1234567890" or b"\0" in pattern:
            raise CertificateError(
                "Invalid DNS pattern {0!r}.".format(pattern)
            )

        self.pattern = pattern.translate(_TRANS_TO_LOWER)


@magic_attrs(["protocol_pattern", "dns_pattern"])
class URIPattern(object):
    """
    An URI pattern as extracted from certificates.
    """
    def __init__(self, pattern):
        """
        :type pattern: `bytes`
        """
        if not isinstance(pattern, bytes):
            raise TypeError("The URI pattern must be a bytes string.")

        pattern = pattern.strip().translate(_TRANS_TO_LOWER)

        if (
            b":" not in pattern
            or b"*" in pattern
            or pattern[-1] in b'1234567890'
        ):
            raise CertificateError(
                "Invalid URI pattern {0!r}.".format(pattern)
            )
        self.protocol_pattern, hostname = pattern.split(b":")
        self.dns_pattern = DNSPattern(hostname)


@magic_attrs(["name_pattern", "dns_pattern"])
class SRVPattern(object):
    """
    An SRV pattern as extracted from certificates.
    """
    def __init__(self, pattern):
        """
        :type pattern: `bytes`
        """
        if not isinstance(pattern, bytes):
            raise TypeError("The SRV pattern must be a bytes string.")

        pattern = pattern.strip().translate(_TRANS_TO_LOWER)

        if (
            pattern[0] != b"_"[0]
            or b"." not in pattern
            or b"*" in pattern
            or pattern[-1] in b"1234567890"
        ):
            raise CertificateError(
                "Invalid SRV pattern {0!r}.".format(pattern)
            )
        name, hostname = pattern.split(b".", 1)
        self.name_pattern = name[1:]
        self.dns_pattern = DNSPattern(hostname)


@magic_attrs(["hostname"])
class DNS_ID(object):
    """
    A DNS service ID, aka hostname.
    """
    pattern_class = DNSPattern
    exc_on_mismatch = DNSMismatchError

    def __init__(self, hostname):
        """
        :type hostname: `unicode`
        """
        if not isinstance(hostname, text_type):
            raise TypeError("DNS-ID must be a unicode string.")

        hostname = hostname.strip()
        if hostname == u("") or hostname[-1] in u('1234567890'):
            raise ValueError("Invalid DNS-ID.")

        if any(ord(c) > 127 for c in hostname):
            if idna:
                ascii_id = idna.encode(hostname)
            else:
                raise ImportError(
                    "idna library is required for non-ASCII IDs."
                )
        else:
            ascii_id = hostname

        self.hostname = ascii_id.encode("ascii").translate(_TRANS_TO_LOWER)

    def verify(self, pattern):
        """
        http://tools.ietf.org/search/rfc6125#section-6.4
        """
        if isinstance(pattern, self.pattern_class):
            return _hostname_matches(pattern.pattern, self.hostname)
        else:
            return False


@magic_attrs(["protocol", "dns_id"])
class URI_ID(object):
    """
    An URI service ID.
    """
    pattern_class = URIPattern
    exc_on_mismatch = URIMismatchError

    def __init__(self, uri):
        """
        :type uri: `unicode`
        """
        if not isinstance(uri, text_type):
            raise TypeError("URI-ID must be a unicode string.")

        uri = uri.strip()
        if u(":") not in uri or uri[-1] in u('1234567890'):
            raise ValueError("Invalid URI-ID.")

        prot, hostname = uri.split(u(":"))

        self.protocol = prot.encode("ascii").translate(_TRANS_TO_LOWER)
        self.dns_id = DNS_ID(hostname)

    def verify(self, pattern):
        """
        http://tools.ietf.org/search/rfc6125#section-6.5.2
        """
        if isinstance(pattern, self.pattern_class):
            return (
                pattern.protocol_pattern == self.protocol
                and self.dns_id.verify(pattern.dns_pattern)
            )
        else:
            return False


@magic_attrs(["name", "dns_id"])
class SRV_ID(object):
    """
    An SRV service ID.
    """
    pattern_class = SRVPattern
    exc_on_mismatch = SRVMismatchError

    def __init__(self, srv):
        """
        :type srv: `unicode`
        """
        if not isinstance(srv, text_type):
            raise TypeError("SRV-ID must be a unicode string.")

        srv = srv.strip()
        if u(".") not in srv or srv[-1] in u("1234567890") or srv[0] != u("_"):
            raise ValueError("Invalid SRV-ID.")

        name, hostname = srv.split(u("."), 1)

        self.name = name[1:].encode("ascii").translate(_TRANS_TO_LOWER)
        self.dns_id = DNS_ID(hostname)

    def verify(self, pattern):
        """
        http://tools.ietf.org/search/rfc6125#section-6.5.1
        """
        if isinstance(pattern, self.pattern_class):
            return (
                self.name == pattern.name_pattern
                and self.dns_id.verify(pattern.dns_pattern)
            )
        else:
            return False


def _find_matches(cert_patterns, service_ids):
    """
    Search for matching certificate patterns and service_ids.

    :param cert_ids: List certificate IDs like DNSPattern.
    :type cert_ids: `list`

    :param service_ids: List of service IDs like DNS_ID.
    :type service_ids: `list`

    :return: List of ``(certificate_pattern, service_id)`` `tuple`s.
    :rtype: `list` of `tuple`s
    """
    matches = []
    for sid in service_ids:
        for cid in cert_patterns:
            if sid.verify(cid):
                matches.append((cid, sid))
    return matches


def _hostname_matches(cert_pattern, actual_hostname):
    """
    :type cert_pattern: `bytes`
    :type actual_hostname: `bytes`

    :return: `True` if *cert_pattern* matches *actual_hostname*, else `False`.
    :rtype: `bool`
    """
    if b'*' in cert_pattern:
        _validate_pattern(actual_hostname)
        cert_head, cert_tail = cert_pattern.split(b".", 1)
        actual_head, actual_tail = actual_hostname.split(b".", 1)
        if cert_tail != actual_tail:
            return False
        # No patterns for IDNA
        if actual_head.startswith(b"xn--"):
            return False

        if cert_head == b"*":
            return True

        start, end = cert_head.split(b"*")
        if start == b"":
            # *oo
            return actual_head.endswith(end)
        elif end == b"":
            # f*
            return actual_head.startswith(start)
        else:
            # f*o
            return actual_head.startswith(start) and actual_head.endswith(end)

    else:
        return cert_pattern == actual_hostname


def _validate_pattern(cert_pattern):
    """
    Check whether the usage of wildcards within *cert_pattern* conforms with
    our expectations.

    :type hostname: `bytes`
    """
    cnt = cert_pattern.count(b"*")
    if cnt == 0:
        return
    if cnt > 1:
        raise CertificateError(
            "Certificate's DNS-ID {0!r} contains too many wildcards."
            .format(cert_pattern)
        )
    parts = cert_pattern.split(b".")
    if len(parts) < 3:
        raise CertificateError(
            "Certificate's DNS-ID {0!r} hast too few host components for "
            "wildcard usage."
            .format(cert_pattern)
        )
    # We assume there will always be only one wildcard allowed.
    if b"*" not in parts[0]:
        raise CertificateError(
            "Certificate's DNS-ID {0!r} has a wildcard outside the left-most "
            "part.".format(cert_pattern)
        )
    if any(not len(p) for p in parts):
        raise CertificateError(
            "Certificate's DNS-ID {0!r} contains empty parts."
            .format(cert_pattern)
        )


# Ensure no locale magic interferes.
_TRANS_TO_LOWER_ARG_TUPLE = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                             b"abcdefghijklmnopqrstuvwxyz")

if PY3:  # pragma: nocover
    _TRANS_TO_LOWER = bytes.maketrans(*_TRANS_TO_LOWER_ARG_TUPLE)
else:
    import string
    _TRANS_TO_LOWER = string.maketrans(*_TRANS_TO_LOWER_ARG_TUPLE)
