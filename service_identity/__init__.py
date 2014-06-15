"""
Verify service identities.
"""

from __future__ import absolute_import, division, print_function

__version__ = "1.0.0"
__author__ = "Hynek Schlawack"
__license__ = "MIT"

from . import pyopenssl
from .exceptions import (
    CertificateError,
    VerificationError,
)

__all__ = [
    "CertificateError",
    "VerificationError",
    "pyopenssl",
]
