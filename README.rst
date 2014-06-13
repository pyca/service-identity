===========================================
Service Identity Verification for pyOpenSSL
===========================================

.. image:: https://travis-ci.org/pyca/service_identity.png?branch=master
  :target: https://travis-ci.org/pyca/service_identity

.. image:: https://coveralls.io/repos/pyca/service_identity/badge.png
  :target: https://coveralls.io/r/pyca/service_identity

.. begin

**TL;DR**: Use this package if you use pyOpenSSL_ and don’t want to be MITM_\ ed.

``service_identity`` aspires to give you all the tools you need for verifying whether a certificate is valid for the intended purposes.

In the simplest case, this means *host name verification*.
However, ``service_identity`` implements `RFC 6125`_ fully and plans to add other relevant RFCs too.

``service_identity``\ ’s documentation lives at `Read the Docs <http://service-identity.readthedocs.org/>`_, the code on `GitHub <https://github.com/pyca/service_identity>`_.


.. _Twisted: https://twistedmatrix.com/
.. _pyOpenSSL: https://pypi.python.org/pypi/pyOpenSSL/
.. _MITM: http://en.wikipedia.org/wiki/Man-in-the-middle_attack
.. _`RFC 6125`: http://www.rfc-editor.org/info/rfc6125
