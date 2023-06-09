===
API
===

.. note::

   So far, public APIs are only available for host names (:rfc:`6125`) and IP addresses (:rfc:`2818`).
   All IDs specified by :rfc:`6125` are already implemented though.
   If you'd like to play with them and provide feedback have a look at the ``verify_service_identity`` function in the `_common module <https://github.com/pyca/service-identity/blob/main/src/service_identity/_common.py>`_.


PyCA cryptography
=================

.. currentmodule:: service_identity.cryptography

.. autofunction:: verify_certificate_hostname
.. autofunction:: verify_certificate_ip_address


pyOpenSSL
=========

.. currentmodule:: service_identity.pyopenssl

.. autofunction:: verify_hostname

   In practice, this may look like the following:

   .. include:: pyopenssl_example.py
      :literal:

.. autofunction:: verify_ip_address


Universal Errors and Warnings
=============================

.. currentmodule:: service_identity

.. autoexception:: VerificationError
.. autoexception:: CertificateError
.. autoexception:: SubjectAltNameWarning
