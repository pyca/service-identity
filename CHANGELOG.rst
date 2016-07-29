.. :changelog:

History
=======

Versions are year-based with a strict backwards-compatibility policy.
The third digit is only for regressions.


16.1.0 (UNRELEASED)
-------------------

Changes:
^^^^^^^^

- When ``service_identity.SubjectAltNameWarning`` is raised, the Common Name of the certificate is now included in the warning message.
  [`#17 <https://github.com/pyca/service_identity/pull/17>`_]
- ``cryptography.x509`` backend for verifying certificates.
  [`#18 <https://github.com/pyca/service_identity/pull/18>`_]


----


16.0.0 (2016-02-18)
-------------------

Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Python 3.3 and 2.6 aren't supported anymore.
  They may work by chance but any effort to keep them working has ceased.

  The last Python 2.6 release was on October 29, 2013 and isn't supported by the CPython core team anymore.
  Major Python packages like Django and Twisted dropped Python 2.6 a while ago already.

  Python 3.3 never had a significant user base and wasn't part of any distribution's LTS release.
- pyOpenSSL versions older than 0.14 are not tested anymore.
  They don't even build with recent OpenSSL versions.

Changes:
^^^^^^^^

- Officially support Python 3.5.
- ``service_identity.SubjectAltNameWarning`` is now raised if the server certicate lacks a proper ``SubjectAltName``.
  [`#9 <https://github.com/pyca/service_identity/issues/9>`_]
- Add a ``__str__`` method to ``VerificationError``.
- Port from ``characteristic`` to its spiritual successor `attrs <https://attrs.readthedocs.io/>`_.


----


14.0.0 (2014-08-22)
-------------------

Changes:
^^^^^^^^

- Switch to year-based version numbers.
- Port to ``characteristic`` 14.0 (get rid of deprecation warnings).
- Package docs with sdist.


----


1.0.0 (2014-06-15)
------------------

Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Drop support for Python 3.2.
  There is no justification to add complexity and unnecessary function calls for a Python version that `nobody uses <https://alexgaynor.net/2014/jan/03/pypi-download-statistics/>`_.

Changes:
^^^^^^^^

- Move into the `Python Cryptography Authority’s GitHub account <https://github.com/pyca/>`_.
- Move exceptions into ``service_identity.exceptions`` so tracebacks don’t contain private module names.
- Promoting to stable since Twisted 14.0 is optionally depending on ``service_identity`` now.
- Use `characteristic <https://characteristic.readthedocs.io/>`_ instead of a home-grown solution.
- ``idna`` 0.6 did some backward-incompatible fixes that broke Python 3 support.
  This has been fixed now therefore ``service_identity`` only works with ``idna`` 0.6 and later.
  Unfortunately since ``idna`` doesn’t offer version introspection, ``service_identity`` can’t warn about it.


----


0.2.0 (2014-04-06)
------------------

Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Refactor into a multi-module package.
  Most notably, ``verify_hostname`` and ``extract_ids`` live in the ``service_identity.pyopenssl`` module now.
- ``verify_hostname`` now takes an ``OpenSSL.SSL.Connection`` for the first argument.

Changes:
^^^^^^^^

- Less false positives in IP address detection.
- Officially support Python 3.4 too.
- More strict checks for URI_IDs.


----


0.1.0 (2014-03-03)
------------------

Initial release.
