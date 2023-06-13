import argparse
import pprint
import socket

import idna

from OpenSSL import SSL

import service_identity


parser = argparse.ArgumentParser(
    description="Connect to HOST, inspect its certificate "
    "and verify if it's valid for its hostname."
)
parser.add_argument("HOST")
args = parser.parse_args()
hostname = args.HOST

ctx = SSL.Context(SSL.TLSv1_2_METHOD)
ctx.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: bool(ok))
ctx.set_default_verify_paths()

conn = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
conn.set_tlsext_host_name(idna.encode(hostname))
conn.connect((hostname, 443))

try:
    conn.do_handshake()

    if cert := conn.get_peer_certificate():
        print("Server certificate is valid for the following patterns:\n")
        pprint.pprint(service_identity.pyopenssl.extract_patterns(cert))

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
