"""
All exceptions and warnings thrown by ``service-identity``.

Separated into an own package for nicer tracebacks, you should still import
them from __init__.py.
"""


import attr


class SubjectAltNameWarning(DeprecationWarning):
    """
    This warning is not used anymore and will be removed in a future version.

    Formerly:

    Server Certificate does not contain a ``SubjectAltName``.

    Hostname matching is performed on the ``CommonName`` which is deprecated.

    .. deprecated:: 23.1.0
    """


@attr.s(auto_exc=True)
class VerificationError(Exception):
    """
    Service identity verification failed.
    """

    errors = attr.ib()

    def __str__(self):
        return self.__repr__()


@attr.s
class DNSMismatch:
    """
    No matching DNSPattern could be found.
    """

    mismatched_id = attr.ib()


@attr.s
class SRVMismatch:
    """
    No matching SRVPattern could be found.
    """

    mismatched_id = attr.ib()


@attr.s
class URIMismatch:
    """
    No matching URIPattern could be found.
    """

    mismatched_id = attr.ib()


@attr.s
class IPAddressMismatch:
    """
    No matching IPAddressPattern could be found.
    """

    mismatched_id = attr.ib()


class CertificateError(Exception):
    """
    Certificate contains invalid or unexpected data.
    """
