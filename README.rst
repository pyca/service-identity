===========================================
Service Identity Verification for pyOpenSSL
===========================================

.. image:: https://travis-ci.org/hynek/service_identity.png?branch=master
  :target: https://travis-ci.org/hynek/service_identity

.. image:: https://coveralls.io/repos/hynek/service_identity/badge.png
  :target: https://coveralls.io/r/hynek/service_identity


WARNING
=======

**This software is currently pre-alpha and under review.
Use it at your own peril.**

Any part is subject to change, but feedback is very welcome!


Pitch
=====

service_identity aspires to give you all the tools you need for verifying whether a certificate is valid for the intended purposes.

In the simplest case, this means *host name verification*.
However, service_identity implements `RFC 6125`_ fully and plans to add other relevant RFCs too.


Features
========


Present
-------

- ``dNSName`` with fallback to ``CN`` (DNS-ID, aka host names, `RFC 6125`_).
- ``uniformResourceIdentifier`` (URI-ID, `RFC 6125`_).
- SRV-ID (`RFC 6125`_)


Future
------

- ``xmppAddr`` (`RFC 3920`_).
- ``iPAddress`` (`RFC 2818`_).
- name constrains extensions (`RFC 3280`_).


Usage
=====


Verify a Hostname
-----------------

The simplest, most common, and most important usage:

.. code-block:: python

   from __future__ import absolute_import, division, print_function

   import socket

   from OpenSSL import SSL
   from service_identity import verify_hostname, VerificationError


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


Requirements
============

Python 2.6, 2.7, 3.2, 3.3, and 3.4 as well as PyPy are supported.

Additionally, the following PyPI modules are required:

- pyOpenSSL_ ``>= 0.12`` (``0.14`` strongly suggested)
- pyasn1_
- pyasn1-modules_

Optionally, idna_ can be used for `internationalized domain names`_ (IDN), aka non-ASCII domains.
Please note, that idna is not available for Python 3.2 and is required because Python's stdlib support is outdated_.


.. _Twisted: https://twistedmatrix.com/
.. _`RFC 2818`: http://www.rfc-editor.org/rfc/rfc2818.txt
.. _`RFC 3280`: http://tools.ietf.org/search/rfc3280#section-4.2.1.11
.. _`RFC 3920`: http://www.rfc-editor.org/rfc/rfc3920.txt
.. _`RFC 6125`: http://www.rfc-editor.org/info/rfc6125
.. _`internationalized domain names`: http://en.wikipedia.org/wiki/Internationalized_domain_name
.. _idna: https://pypi.python.org/pypi/idna/
.. _outdated: http://bugs.python.org/issue17305
.. _pyOpenSSL: https://pypi.python.org/pypi/pyOpenSSL/
.. _pyasn1-modules: https://pypi.python.org/pypi/pyasn1-modules/
.. _pyasn1: https://pypi.python.org/pypi/pyasn1/
.. _pydoctor: https://pypi.python.org/pypi/pydoctor/
.. _trial: http://twistedmatrix.com/documents/current/core/howto/testing.html
