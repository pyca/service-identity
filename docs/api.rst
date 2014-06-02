===
API
===


Verify a Hostname
=================

The simplest, most common, and most important usage:

.. code-block:: python

   from __future__ import absolute_import, division, print_function

   import socket

   from OpenSSL import SSL
   from service_identity import VerificationError
   from service_identity.pyopenssl import verify_hostname


   ctx = SSL.Context(SSL.SSLv23_METHOD)
   ctx.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: ok)
   ctx.set_default_verify_paths()

   hostname = u"twistedmatrix.com"
   conn = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
   conn.connect((hostname, 443))

   try:
       conn.do_handshake()
       verify_hostname(conn, hostname)
       # Do your super-secure stuff here.
   except SSL.Error as e:
       print("TLS Handshake failed: {0!r}.".format(e.args[0]))
   except VerificationError:
       print("Presented certificate is not valid for {0}.".format(hostname))
   finally:
       conn.shutdown()
       conn.close()
