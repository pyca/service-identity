===
API
===

.. note::

   So far, public high-level APIs are only available for host names (:rfc:`6125`) and IP addresses (:rfc:`2818`).
   All IDs specified by :rfc:`6125` are already implemented though.
   If you'd like to play with them and provide feedback have a look at the ``verify_service_identity`` function in the `hazmat module <https://github.com/pyca/service-identity/blob/main/src/service_identity/hazmat.py>`_.


PyCA cryptography
=================

.. currentmodule:: service_identity.cryptography

.. autofunction:: verify_certificate_hostname
.. autofunction:: verify_certificate_ip_address
.. autofunction:: extract_patterns


pyOpenSSL
=========

.. currentmodule:: service_identity.pyopenssl

.. autofunction:: verify_hostname

   In practice, this may look like the following:

   .. include:: pyopenssl_example.py
      :literal:

.. autofunction:: verify_ip_address
.. autofunction:: extract_patterns


Hazardous Materials
===================

.. currentmodule:: service_identity.hazmat


.. danger::

   The following APIs require reader's discretion.
   They are stable and they've been using internally by *service-identity* for years, but you need to know what you're doing.


Pattern Objects
---------------

The following are the objects return by the ``extract_patterns`` functions.
They each carry the attributes that are necessary to match an ID of their type.


.. autoclass:: CertificatePattern

   It includes all of those that follow now.

.. autoclass:: DNSPattern
   :members:
.. autoclass:: IPAddressPattern
   :members:
.. autoclass:: URIPattern
   :members:
.. autoclass:: SRVPattern
   :members:


Universal Errors and Warnings
=============================

.. currentmodule:: service_identity

.. autoexception:: VerificationError
.. autoexception:: CertificateError
.. autoexception:: SubjectAltNameWarning
