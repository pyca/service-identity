===
API
===

.. note::

   So far, public APIs are only available for hostnames (RFC 6125) and IP addresses (RFC 2818).
   All IDs specified by RFC 6125 are already implemented though.
   If you'd like to play with them and provide feedback have a look at the ``verify_service_identity`` function in the `_common module <https://github.com/pyca/service-identity/blob/main/src/service_identity/_common.py>`_.


pyOpenSSL
=========

.. currentmodule:: service_identity.pyopenssl

.. autofunction:: verify_hostname

   In practice, this may look like the following:

   .. include:: pyopenssl_example.py
      :literal:

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
