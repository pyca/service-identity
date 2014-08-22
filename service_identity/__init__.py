"""
Verify service identities.
"""

from __future__ import absolute_import, division, print_function

__version__ = "14.0.0"
__author__ = "Hynek Schlawack"
__license__ = "MIT"
__copyright__ = "Copyright 2014 Hynek Schlawack"

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
