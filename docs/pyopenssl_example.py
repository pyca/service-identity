import pprint
import socket
import sys

import idna

from OpenSSL import SSL

import service_identity


hostname = sys.argv[1]

ctx = SSL.Context(SSL.SSLv23_METHOD)
ctx.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: ok)
ctx.set_default_verify_paths()

conn = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
conn.set_tlsext_host_name(idna.encode(hostname))
conn.connect((hostname, 443))

try:
    conn.do_handshake()

    print("Certificate is valid for the following patterns:\n")
    pprint.pprint(
        service_identity.pyopenssl.extract_patterns(
            conn.get_peer_certificate()
        )
    )

    try:
        service_identity.pyopenssl.verify_hostname(conn, hostname)
    except service_identity.VerificationError:
        print(f"\nPresented certificate is NOT valid for {hostname}.")
    finally:
        conn.shutdown()
except SSL.Error as e:
    print(f"TLS Handshake failed: {e!r}.")
finally:
    conn.close()
