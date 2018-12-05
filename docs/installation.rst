=============================
Installation and Requirements
=============================


Installation
============

``$ pip install service_identity``


Requirements
============

Python 2.7, 3.4 and later, as well as PyPy are supported.

Additionally, the following PyPI packages are required:

- attrs_
- pyOpenSSL_ ``>= 0.14`` (``0.12`` and ``0.13`` may work but are not part of CI anymore)
- pyasn1_
- pyasn1-modules_
- ipaddress_ on Python 2.7

Optionally, idna_ ``>= 0.6`` can be used for `internationalized domain names`_ (IDN), i.e. non-ASCII domains.
Unfortunately it’s required because Python’s IDN support in the standard library is outdated_ even in the latest releases.

If you need Python 3.2 support, you will have to use the latest 0.2.x release.
If you need Python 2.6 or 3.3 support, you will have to use the latest 14.0.x release.
They will receive bug fix releases if necessary but other than that no further development is planned.

.. _attrs: https://www.attrs.org/
.. _pyOpenSSL: https://pypi.org/project/pyOpenSSL/
.. _pyasn1-modules: https://pypi.org/project/pyasn1-modules/
.. _pyasn1: https://pypi.org/project/pyasn1/
.. _`internationalized domain names`: https://en.wikipedia.org/wiki/Internationalized_domain_name
.. _idna: https://pypi.org/project/idna/
.. _outdated: https://bugs.python.org/issue17305
.. _ipaddress: https://pypi.org/project/ipaddress/
