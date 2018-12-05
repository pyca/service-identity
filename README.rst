=============================
Service Identity Verification
=============================

.. image:: https://readthedocs.org/projects/service-identity/badge/?version=stable
   :target: https://service-identity.readthedocs.io/en/stable/?badge=stable
   :alt: Documentation Status

.. image:: https://travis-ci.org/pyca/service_identity.svg?branch=master
   :target: https://travis-ci.org/pyca/service_identity
   :alt: CI status

.. image:: https://codecov.io/github/pyca/service_identity/branch/master/graph/badge.svg
   :target: https://codecov.io/github/pyca/service_identity
   :alt: Test Coverage

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
   :target: https://github.com/ambv/black
   :alt: Code style: black

.. image:: https://www.irccloud.com/invite-svg?channel=%23cryptography-dev&amp;hostname=irc.freenode.net&amp;port=6697&amp;ssl=1
    :target: https://www.irccloud.com/invite?channel=%23cryptography-dev&amp;hostname=irc.freenode.net&amp;port=6697&amp;ssl=1

.. begin

Use this package if:

- you use pyOpenSSL_ and don’t want to be MITM_\ ed or
- if you want to verify that a `PyCA cryptography`_ certificate is valid for a certain hostname or IP address.

``service_identity`` aspires to give you all the tools you need for verifying whether a certificate is valid for the intended purposes.

In the simplest case, this means *host name verification*.
However, ``service_identity`` implements `RFC 6125`_ fully and plans to add other relevant RFCs too.

``service_identity``\ ’s documentation lives at `Read the Docs <https://service-identity.readthedocs.io/>`_, the code on `GitHub <https://github.com/pyca/service_identity>`_.


.. _Twisted: https://twistedmatrix.com/
.. _pyOpenSSL: https://pypi.org/project/pyOpenSSL/
.. _MITM: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
.. _RFC 6125: https://www.rfc-editor.org/info/rfc6125
.. _PyCA cryptography: https://cryptography.io/
