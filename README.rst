=============================
Service Identity Verification
=============================

.. image:: https://readthedocs.org/projects/service-identity/badge/?version=stable
   :target: https://service-identity.readthedocs.io/en/stable/?badge=stable
   :alt: Documentation Status

.. image:: https://github.com/pyca/service-identity/workflows/CI/badge.svg?branch=main
   :target: https://github.com/pyca/service-identity/actions?workflow=CI
   :alt: CI Status

.. image:: https://codecov.io/github/pyca/service-identity/branch/main/graph/badge.svg
   :target: https://codecov.io/github/pyca/service-identity
   :alt: Test Coverage

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
   :target: https://github.com/ambv/black
   :alt: Code style: black

.. image:: https://www.irccloud.com/invite-svg?channel=%23pyca&amp;hostname=irc.libera.chat&amp;port=6697&amp;ssl=1
   :target: https://www.irccloud.com/invite?channel=%23pyca&amp;hostname=irc.libera.chat&amp;port=6697&amp;ssl=1
   :alt: PyCA on IRC

.. spiel-begin

Use this package if:

- you use pyOpenSSL_ and don’t want to be MITM_\ ed or
- if you want to verify that a `PyCA cryptography`_ certificate is valid for a certain hostname or IP address.

``service-identity`` aspires to give you all the tools you need for verifying whether a certificate is valid for the intended purposes.

In the simplest case, this means *host name verification*.
However, ``service-identity`` implements `RFC 6125`_ fully and plans to add other relevant RFCs too.

.. _Twisted: https://twistedmatrix.com/
.. _pyOpenSSL: https://pypi.org/project/pyOpenSSL/
.. _MITM: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
.. _RFC 6125: https://www.rfc-editor.org/info/rfc6125
.. _PyCA cryptography: https://cryptography.io/

.. spiel-end

Project Information
===================

.. meta-begin

``service-identity``\ is released under the MIT license, its documentation lives at `Read the Docs <https://service-identity.readthedocs.io/>`_, the code on `GitHub <https://github.com/pyca/service-identity>`_, and the latest release on `PyPI <https://pypi.org/project/service-identity/>`_.
It’s rigorously tested on Python 2.7, 3.5+, and PyPy.


``service-identity`` for Enterprise
-----------------------------------

Available as part of the Tidelift Subscription.

The maintainers of ``service-identity`` and thousands of other packages are working with Tidelift to deliver commercial support and maintenance for the open-source packages you use to build your applications.
Save time, reduce risk, and improve code health, while paying the maintainers of the exact packages you use.
`Learn more. <https://tidelift.com/subscription/pkg/service-identity?utm_source=undefined&utm_medium=referral&utm_campaign=enterprise&utm_term=repo>`_
