"""
Verify service identities.
"""

from __future__ import absolute_import, division, print_function

__version__ = "0.2"
__author__ = "Hynek Schlawack"
__license__ = "MIT"

from . import pyopenssl
from ._common import (
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
