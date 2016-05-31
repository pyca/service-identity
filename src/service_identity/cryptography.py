"""
`cryptography.x509 <https://github.com/pyca/cryptography>`_-specific code.
"""

from __future__ import absolute_import, division, print_function

from .exceptions import SubjectAltNameWarning
from ._common import (
    CertificateError,
    DNSPattern,
    DNS_ID,
    SRVPattern,
    URIPattern,
    verify_service_identity,
)


def verify_certificate(certificate, hostname):
    """
    Verify whether *certificate* is valid for *hostname*.

    :param certificate: A cryptography X509 certificate object.
    :type certificate: :class:`cryptography.x509.Certificate`


    :param hostname: The hostname that *connection* should be connected to.
    :type hostname: :class:`unicode`

    :raises service_identity.VerificationError: If *certificate* is not
        valid for *hostname*.
    :raises service_identity.CertificateError: If *certificate* contains
        invalid/unexpected data.

    :returns: ``None``
    """
