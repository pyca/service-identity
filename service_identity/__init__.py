"""
Verify service identities.
"""

from __future__ import absolute_import, division, print_function

__version__ = "1.0.0dev"
__author__ = "Hynek Schlawack"
__license__ = "MIT"

from . import pyopenssl
from .exceptions import (
    CertificateError,
    DNSMismatch,
    SRVMismatch,
    URIMismatch,
    VerificationError,
)
from ._common import (
    DNSPattern,
    DNS_ID,
    SRVPattern,
    SRV_ID,
    ServiceMatch,
    URIPattern,
    URI_ID,
    verify_service_identity,
)


__all__ = [
    "CertificateError",
    "DNSMismatch",
    "DNSPattern",
    "DNS_ID",
    "SRVMismatch",
    "SRVPattern",
    "SRV_ID",
    "ServiceMatch",
    "URIMismatch",
    "URIPattern",
    "URI_ID",
    "VerificationError",
    "pyopenssl",
    "verify_service_identity",
]
