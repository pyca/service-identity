"""
This module is used to test the typing of the public API of service-identity.

It is NOT intended to be executed.
"""

from __future__ import annotations

import socket

from typing import Sequence

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from OpenSSL import SSL

import service_identity


backend = default_backend()
c_cert = load_pem_x509_certificate("foo.pem", backend)

c_ids: Sequence[service_identity.hazmat.CertificatePattern] = (
    service_identity.cryptography.extract_patterns(c_cert)
)
service_identity.cryptography.verify_certificate_hostname(
    c_cert, "example.com"
)
service_identity.cryptography.verify_certificate_ip_address(
    c_cert, "127.0.0.1"
)


ctx = SSL.Context(SSL.TLSv1_2_METHOD)
conn = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
p_cert = conn.get_peer_certificate()
assert p_cert

p_ids: Sequence[service_identity.hazmat.CertificatePattern] = (
    service_identity.pyopenssl.extract_patterns(p_cert)
)
service_identity.pyopenssl.verify_hostname(conn, "example.com")
service_identity.pyopenssl.verify_ip_address(conn, "127.0.0.1")
