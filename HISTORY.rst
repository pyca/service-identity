.. :changelog:

History
=======


0.2.0 (UNRELEASED)
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
