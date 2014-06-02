=============================
Installation and Requirements
=============================


Installation
============

``$ pip install service_identity``


Requirements
============

Python 2.6, 2.7, 3.3 and later, as well as PyPy are supported.

Additionally, the following PyPI modules are required:

- pyOpenSSL_ ``>= 0.12`` (``0.14`` strongly recommended)
- pyasn1_
- pyasn1-modules_

Optionally, idna_ ``>= 0.6`` can be used for `internationalized domain names`_ (IDN), i.e. non-ASCII domains.
Unfortunately it’s required because Python’s IDN support in the standard library is outdated_ even in the latest releases.

If you need Python 3.2 support, you will have to use the latest 0.2.x release.
It will receive bug fix releases if necessary but other than that no further development is planned.

.. _pyOpenSSL: https://pypi.python.org/pypi/pyOpenSSL/
.. _pyasn1-modules: https://pypi.python.org/pypi/pyasn1-modules/
.. _pyasn1: https://pypi.python.org/pypi/pyasn1/
.. _`internationalized domain names`: http://en.wikipedia.org/wiki/Internationalized_domain_name
.. _idna: https://pypi.python.org/pypi/idna/
.. _outdated: http://bugs.python.org/issue17305
