.. :changelog:

History
=======


0.2.0 (UNRELEASED)
------------------

- ``verify_hostname`` now takes a ``OpenSSL.SSL.Connection`` for the first argument.
  This is a backward-incompatible change but future-proofs the API.
- Less false positives in IP address detection.
- Officially support Python 3.4 too.
- More strict checks for URI_IDs.


0.1.0 (2014-03-03)
------------------

- Initial release.
