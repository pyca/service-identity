"""
All exception thrown by service_identity.

Separated into an own package for nicer tracebacks, you should still import
them from __init__.py.
"""

from __future__ import absolute_import, division, print_function


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
