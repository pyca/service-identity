from __future__ import absolute_import, division, print_function

from ._common import (
    DNSPattern,
    DNS_ID,
    URIPattern,
    verify_service_identity,
)


def verify_hostname(connection, hostname):
    """
    Verify whether *connection* has a valid certificate chain for *hostname*.
    """
    verify_service_identity(
        cert_patterns=extract_ids(connection.getpeercert()),
        obligatory_ids=[DNS_ID(hostname)],
        optional_ids=[],
    )


def extract_ids(cert):
    ids = []
    if "subjectAltName" in cert:
        for i in cert["subjectAltName"]:
            if i[0] == "DNS":
                ids.append(DNSPattern(i[1].encode()))
            if i[0] == "URI":
                ids.append(URIPattern(i[1].encode()))

    if not ids:
        for i in cert["subject"]:
            for j in i:
                if j[0] == "commonName":
                    ids.append(DNSPattern(j[1].encode()))

    return ids
