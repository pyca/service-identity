"""
`cryptography.x509 <https://github.com/pyca/cryptography>`_-specific code.
"""

from __future__ import absolute_import, division, print_function

from cryptography.x509 import (
    DNSName, ExtensionOID, OtherName, UniformResourceIdentifier)
from pyasn1.codec.der.decoder import decode
from pyasn1.type.char import IA5String

from .exceptions import SubjectAltNameWarning
from ._common import (
    CertificateError,
    DNSPattern,
    DNS_ID,
    ID_ON_DNS_SRV,
    SRVPattern,
    URIPattern,
    verify_service_identity,
)


def verify_hostname(certificate, hostname):
    """
    Verify whether *certificate* is valid for *hostname*.

    ..  note:: Nothing is verified about the *authority* of the certificate;
        the caller must verify that the certificate chains to an appropriate
        trust root themselves.

    :param certificate: A cryptography X509 certificate object.
    :type certificate: :class:`cryptography.x509.Certificate`

    :param hostname: The hostname that *certificate* should be valid for.
    :type hostname: :class:`unicode`

    :raises service_identity.VerificationError: If *certificate* is not valid
        for *hostname*.
    :raises service_identity.CertificateError: If *certificate* contains
        invalid/unexpected data.

    :returns: ``None``
    """
    verify_service_identity(
        cert_patterns=extract_ids(certificate),
        obligatory_ids=[DNS_ID(hostname)],
        optional_ids=[],
    )


def extract_ids(cert):
    """
    Extract all valid IDs from a certificate for service verification.

    If *cert* doesn't contain any identifiers, the ``CN``s are used as DNS-IDs
    as fallback.

    :param cert: The certificate to be dissected.
    :type cert: :class:`cryptography.x509.Certificate`

    :return: List of IDs.
    """
    ids = []
    ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    ids.extend([DNSPattern(name.encode('utf-8'))
                for name
                in ext.value.get_values_for_type(DNSName)])
    ids.extend([URIPattern(uri.encode('utf-8'))
                for uri
                in ext.value.get_values_for_type(UniformResourceIdentifier)])
    for other in ext.value.get_values_for_type(OtherName):
        if other.type_id == ID_ON_DNS_SRV:
            srv, _ = decode(other.value)
            if isinstance(srv, IA5String):
                ids.append(SRVPattern(srv.asOctets()))
            else:  # pragma: nocover
                raise CertificateError(
                    "Unexpected certificate content."
                )
