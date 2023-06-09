import socket

from OpenSSL import SSL

from service_identity import VerificationError
from service_identity.pyopenssl import verify_hostname


ctx = SSL.Context(SSL.SSLv23_METHOD)
ctx.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: ok)
ctx.set_default_verify_paths()

hostname = "hynek.me"
conn = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
conn.connect((hostname, 443))

try:
    conn.do_handshake()
    verify_hostname(conn, hostname)

    print("Hostname is valid!")
    # Do your super-secure stuff here.
except SSL.Error as e:
    print(f"TLS Handshake failed: {e!r}.")
except VerificationError:
    print(f"Presented certificate is not valid for {hostname}.")
finally:
    conn.shutdown()
    conn.close()
