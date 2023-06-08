=============================
Installation and Requirements
=============================


Installation
============

.. code-block:: console

   $ python -Im pip install service-identity


Requirements
============

*service-identity* depends on the cryptography_ package.
We're testing against the following oldest version constraint:

.. include:: ../constraints/oldest-cryptography.txt
   :literal:

If you want to use the pyOpenSSL_ functionality, you have to install it yourself.
We are checking against the following oldest version constraints (you have to add the *cryptography* pin yourself, if you want to use an old version of pyOpenSSL):

.. include:: ../constraints/oldest-pyopenssl.txt
   :literal:


International Domain Names
--------------------------

Optionally, the ``idna`` extra dependency can be used for `internationalized domain names`_ (IDN), i.e. non-ASCII domains:

.. code-block:: console

    $ python -Im pip install service-identity[idna]

Unfortunately it's required because Python's IDN support in the standard library is outdated_ even in the latest releases.

.. _cryptography: https://cryptography.io/
.. _pyOpenSSL: https://pypi.org/project/pyOpenSSL/
.. _`internationalized domain names`: https://en.wikipedia.org/wiki/Internationalized_domain_name
.. _idna: https://pypi.org/project/idna/
.. _outdated: https://github.com/python/cpython/issues/61507
