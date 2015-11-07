===
API
===

.. note::

   The APIs for RFC 6125 verification beyond DNS-IDs (i.e. hostnames) aren't public yet.
   They are in place and used by the documented high-level APIs though.
   Eventually they will become public.
   If you'd like to play with them and provide feedback have a look at the ``verify_service_identity`` function in the `_common module <https://github.com/pyca/service_identity/blob/master/src/service_identity/_common.py>`_.


.. currentmodule:: service_identity.pyopenssl


.. function:: verify_hostname(connection, hostname)

   Verify whether the certificate of *connection* is valid for *hostname*.

   :param connection: A pyOpenSSL connection object.
   :type connection: :class:`OpenSSL.SSL.Connection`

   :param hostname: The hostname that *connection* should be connected to.
   :type hostname: :class:`unicode`

   :raises service_identity.VerificationError: If *connection* does not provide a certificate that is valid for *hostname*.
   :raises service_identity.CertificateError: If the certificate chain of *connection* contains a certificate that contains invalid/unexpected data.

   :returns: `None`

   In practice, this may look like the following::

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


.. currentmodule:: service_identity


.. exception:: VerificationError

   Verification failed.


.. exception:: CertificateError

   A certificate contains invalid or unexpected data.
