.. :changelog:

History
=======


14.0.0 (2014-08-22)
-------------------

Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*none*


Deprecations:
^^^^^^^^^^^^^

*none*

Changes:
^^^^^^^^

- Switch to year-based version numbers.
- Port to ``characteristic`` 14.0 (get rid of deprecation warnings).


1.0.0 (2014-06-15)
------------------


Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*none*


Deprecations:
^^^^^^^^^^^^^

*none*


Changes:
^^^^^^^^

- Move into the `Python Cryptography Authority’s GitHub account <https://github.com/pyca/>`_.
- Drop support for Python 3.2.
  There is no justification to add complexity and unnecessary function calls for a Python version that nobody uses.
- Move exceptions into ``service_identity.exceptions`` so tracebacks don’t contain private module names.
- Promoting to stable since Twisted 14.0 is optionally depending on ``service_identity`` now.
- Use `characteristic <https://characteristic.readthedocs.org/>`_ instead of a home-grown solution.
- ``idna`` 0.6 did some backward-incompatible fixes that broke Python 3 support.
  This has been fixed now therefore ``service_identity`` only works with ``idna`` 0.6 and later.
  Unfortunately since ``idna`` doesn’t offer version introspection, ``service_identity`` can’t warn about it.


0.2.0 (2014-04-06)
------------------


Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Refactor into a multi-module package.
  Most notably, ``verify_hostname`` and ``extract_ids`` live in the ``service_identity.pyopenssl`` module now.
- ``verify_hostname`` now takes an ``OpenSSL.SSL.Connection`` for the first argument.


Deprecations:
^^^^^^^^^^^^^

*none*


Changes:
^^^^^^^^

- Less false positives in IP address detection.
- Officially support Python 3.4 too.
- More strict checks for URI_IDs.


0.1.0 (2014-03-03)
------------------

- Initial release.
