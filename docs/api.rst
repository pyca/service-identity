===
API
===

.. note::

   So far, public APIs are only available for hostnames (RFC 6125) and IP addresses (RFC 2818).
   All IDs specified by RFC 6125 are already implemented though.
   If you'd like to play with them and provide feedback have a look at the ``verify_service_identity`` function in the `_common module <https://github.com/pyca/service_identity/blob/master/src/service_identity/_common.py>`_.


pyOpenSSL
=========

.. currentmodule:: service_identity.pyopenssl

.. autofunction:: verify_hostname

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

.. autofunction:: verify_ip_address


PyCA cryptography
=================

.. currentmodule:: service_identity.cryptography

.. autofunction:: verify_certificate_hostname
.. autofunction:: verify_certificate_ip_address


Universal Errors and Warnings
=============================

.. currentmodule:: service_identity

.. autoexception:: VerificationError
.. autoexception:: CertificateError
.. autoexception:: SubjectAltNameWarning
