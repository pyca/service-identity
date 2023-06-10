# Installation and Requirements

## Installation

```console
$ python -Im pip install service-identity
```


## Requirements

*service-identity* depends on the [cryptography] package.
In addition to the latest release, we're also testing against the following oldest version constraint:

```{include} ../tests/constraints/oldest-cryptography.txt
:literal: true
```

If you want to use the [pyOpenSSL] functionality, you have to install it yourself.
In addition to the latest release, we are also testing against the following oldest version constraints
(you have to add the *cryptography* pin yourself, if you want to use an old version of pyOpenSSL):

```{include} ../tests/constraints/oldest-pyopenssl.txt
:literal: true
```


### International Domain Names

Optionally, the `idna` extra dependency can be used for [internationalized domain names] (IDN), i.e. non-ASCII domains:

```console
$ python -Im pip install service-identity[idna]
```

Unfortunately it's required because Python's IDN support in the standard library is [outdated] even in the latest releases.

[cryptography]: https://cryptography.io/
[idna]: https://pypi.org/project/idna/
[internationalized domain names]: https://en.wikipedia.org/wiki/Internationalized_domain_name
[outdated]: https://github.com/python/cpython/issues/61507
[pyopenssl]: https://pypi.org/project/pyOpenSSL/
