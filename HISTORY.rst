.. :changelog:

History
=======


1.0.0 (UNRELEASED)
------------------

- Promoting to stable since Twisted 14.0 is depending on `service_identity` now.
- Use `characteristic <http://characteristic.readthedocs.org/>`_ instead of a home-grown solution.
- idna 0.6 did some backward-incompatible fixes that broke Python 3 support.
  This has been fixed now therefore service_identity only works with idna 0.6 and later.


0.2.0 (2014-04-06)
------------------

This release contains multiple backward-incompatible changes.

- Refactor into a multi-module package.
  Most notably, ``verify_hostname`` and ``extract_ids`` live in the ``service_identity.pyopenssl`` module now.
- ``verify_hostname`` now takes an ``OpenSSL.SSL.Connection`` for the first argument.
- Less false positives in IP address detection.
- Officially support Python 3.4 too.
- More strict checks for URI_IDs.


0.1.0 (2014-03-03)
------------------

- Initial release.
