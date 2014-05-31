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
    DNSMismatchError,
    SRVMismatchError,
    URIMismatchError,
    VerificationError,
)
from ._common import (
    DNSPattern,
    DNS_ID,
    SRVPattern,
    SRV_ID,
    URIPattern,
    URI_ID,
    verify_service_identity,
)


__all__ = [
    "CertificateError",
    "DNSMismatchError",
    "DNSPattern",
    "DNS_ID",
    "SRVMismatchError",
    "SRVPattern",
    "SRV_ID",
    "URIMismatchError",
    "URIPattern",
    "URI_ID",
    "VerificationError",
    "pyopenssl",
    "verify_service_identity",
]
