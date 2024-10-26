# Changelog

All notable changes to this project will be documented in this file.

The format is based on [*Keep a Changelog*](https://keepachangelog.com/en/1.0.0/) and this project adheres to [*Calendar Versioning*](https://calver.org/).

The **first number** of the version is the year.
The **second number** is incremented with each release, starting at 1 for each year.
The **third number** is for emergencies when we need to start branches for older releases.

You can find out backwards-compatibility policy [here](https://github.com/pyca/service-identity/blob/main/.github/SECURITY.md).

<!-- changelog follows -->


## [24.2.0](https://github.com/pyca/service-identity/compare/24.1.0...24.2.0) - 2024-10-26

### Added

- Python 3.13 is now officially supported.
  [#74](https://github.com/pyca/service-identity/pull/74)


### Changed

- pyOpenSSL's identity extraction has been reimplemented using *cryptography*'s primitives instead of deprecated pyOpenSSL APIs.
  As a result, the oldest supported pyOpenSSL version is now 17.1.0.
  [#70](https://github.com/pyca/service-identity/pull/70)


## [24.1.0](https://github.com/pyca/service-identity/compare/23.1.0...24.1.0) - 2024-01-14

### Changed

- If a certificate doesn't contain any `subjectAltName`s, we now raise `service_identity.CertificateError` instead of `service_identity.VerificationError` to make the problem easier to debug.
  [#67](https://github.com/pyca/service-identity/pull/67)


## [23.1.0](https://github.com/pyca/service-identity/compare/21.1.0...23.1.0) - 2023-06-14

### Removed

- All Python versions up to and including 3.7 have been dropped.
- Support for `commonName` in certificates has been dropped.
  It has been deprecated since 2017 and isn't supported by any major browser.
- The oldest supported pyOpenSSL version (when using the `pyopenssl` backend) is now 17.0.0.
  When using such an old pyOpenSSL version, you have to pin *cryptography* yourself to ensure compatibility between them.
  Please check out [`constraints/oldest-pyopenssl.txt`](https://github.com/pyca/service-identity/blob/main/tests/constraints/oldest-pyopenssl.txt) to verify what we are testing against.


### Deprecated

- If you've used `service_identity.(cryptography|pyopenssl).extract_ids()`, please switch to the new names `extract_patterns()`.
  [#56](https://github.com/pyca/service-identity/pull/56)


### Added

- `service_identity.(cryptography|pyopenssl).extract_patterns()` are now public APIs (FKA `extract_ids()`).
  You can use them to extract the patterns from a certificate without verifying anything.
  [#55](https://github.com/pyca/service-identity/pull/55)
- *service-identity* is now fully typed.
  [#57](https://github.com/pyca/service-identity/pull/57)


## [21.1.0](https://github.com/pyca/service-identity/compare/18.1.0...21.1.0) - 2021-05-09

### Removed

- Python 3.4 is not supported anymore.
  It has been unsupported by the Python core team for a while now, its PyPI downloads are negligible, and our CI provider removed it as a supported option.

  It's very unlikely that `service-identity` will break under 3.4 anytime soon, which is why we do *not* block its installation on Python 3.4.
  But we don't test it anymore and will block it once someone reports breakage.


### Fixed

- `service_identity.exceptions.VerificationError` can now be pickled and is overall more well-behaved as an exception.
  This raises the requirement of `attrs` to 19.1.0.


## [18.1.0](https://github.com/pyca/service-identity/compare/17.0.0...18.1.0) - 2018-12-05

### Added

- pyOpenSSL is optional now if you use `service_identity.cryptography.*` only.
- Added support for `iPAddress` `subjectAltName`s.
  You can now verify whether a connection or a certificate is valid for an IP address using `service_identity.pyopenssl.verify_ip_address()` and `service_identity.cryptography.verify_certificate_ip_address()`.
  [#12](https://github.com/pyca/service-identity/pull/12)


## [17.0.0](https://github.com/pyca/service-identity/compare/16.0.0...17.0.0) - 2017-05-23

### Deprecated

- Since Chrome 58 and Firefox 48 both don't accept certificates that contain only a Common Name, its usage is hereby deprecated in `service-identity` too.
  We have been raising a warning since 16.0.0 and the support will be removed in mid-2018 for good.

### Added

- When `service_identity.SubjectAltNameWarning` is raised, the Common Name of the certificate is now included in the warning message.
  [#17](https://github.com/pyca/service-identity/pull/17)
- Added `cryptography.x509` backend for verifying certificates.
  [#18](https://github.com/pyca/service-identity/pull/18)


### Changed

- Wildcards (`*`) are now only allowed if they are the leftmost label in a certificate.
  This is common practice by all major browsers.
  [#19](https://github.com/pyca/service-identity/pull/19)


## [16.0.0](https://github.com/pyca/service-identity/compare/14.0.0...16.0.0) - 2016-02-18

### Removed

- Python 3.3 and 2.6 aren't supported anymore.
  They may work by chance but any effort to keep them working has ceased.

  The last Python 2.6 release was on October 29, 2013 and isn't supported by the CPython core team anymore.
  Major Python packages like Django and Twisted dropped Python 2.6 a while ago already.

  Python 3.3 never had a significant user base and wasn't part of any distribution's LTS release.

- pyOpenSSL versions older than 0.14 are not tested anymore.
  They don't even build on recent OpenSSL versions.
  Please note that its support may break without further notice.


### Added

- Officially support Python 3.5.
- A `__str__` method to `VerificationError`.


### Changed

- `service_identity.SubjectAltNameWarning` is now raised if the server certificate lacks a proper `SubjectAltName`.
  [#9](https://github.com/pyca/service-identity/issues/9)
- Port from `characteristic` to its spiritual successor [attrs](https://www.attrs.org/).


## [14.0.0](https://github.com/pyca/service-identity/compare/1.0.0...14.0.0) - 2014-08-22

### Changed

- Switch to year-based version numbers.
- Port to `characteristic` 14.0 (get rid of deprecation warnings).
- Package docs with source distributions.


## [1.0.0](https://github.com/pyca/service-identity/compare/0.2.0...1.0.0) - 2014-06-15

### Removed

- Drop support for Python 3.2.
  There is no justification to add complexity and unnecessary function calls for a Python version that [nobody uses](https://alexgaynor.net/2014/jan/03/pypi-download-statistics/).

### Changed

- Move into the [Python Cryptography Authority’s GitHub account](https://github.com/pyca/).
- Move exceptions into `service_identity.exceptions` so tracebacks don’t contain private module names.
- Promoting to stable since Twisted 14.0 is optionally depending on `service-identity` now.
- Use [characteristic](https://characteristic.readthedocs.io/) instead of a home-grown solution.


### Fixed

- `idna` 0.6 did some backward-incompatible fixes that broke Python 3 support.
  This has been fixed now therefore *service-identity* only works with `idna` 0.6 and later.
  Unfortunately since `idna` doesn’t offer version introspection, *service-identity* can’t warn about it.


## [0.2.0](https://github.com/pyca/service-identity/compare/0.1.0...0.2.0) - 2014-04-06

### Added

- Official support for Python 3.4.


### Changed

- Refactor into a multi-module package.
  Most notably, `verify_hostname` and `extract_ids` live in the `service_identity.pyopenssl` module now.
- `verify_hostname` now takes an `OpenSSL.SSL.Connection` for the first argument.
- More strict checks for URI_IDs.


### Fixed

- Less false positives in IP address detection.


## [0.1.0](https://github.com/pyca/service-identity/tree/0.1.0) - 2014-03-03

Initial release.
