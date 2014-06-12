"""
All exceptions thrown by service_identity.

Separated into an own package for nicer tracebacks, you should still import
them from __init__.py.
"""

from __future__ import absolute_import, division, print_function

from characteristic import attributes


@attributes(["errors"])
class VerificationError(Exception):
    """
    Service identity verification failed.
    """


@attributes(["mismatched_id"])
class DNSMismatch(object):
    """
    Not matching DNSPattern could be found.
    """


@attributes(["mismatched_id"])
class SRVMismatch(object):
    """
    Not matching SRVPattern could be found.
    """


@attributes(["mismatched_id"])
class URIMismatch(object):
    """
    Not matching URIPattern could be found.
    """


class CertificateError(Exception):
    """
    Certificate contains invalid or unexpected data.
    """
