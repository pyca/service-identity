import codecs
import os
import re

from setuptools import setup, find_packages


def read(*parts):
    """
    Build an absolute path from *parts* and and return the contents of the
    resulting file.  Assume UTF-8 encoding.
    """
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, *parts), 'rb', 'utf-8') as f:
        return f.read()


def find_version(*file_paths):
    """
    Build a path from *file_paths* and search for a ``__version__``
    string inside.
    """
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


if __name__ == "__main__":
    setup(
        description="Service identity verification for pyOpenSSL.",
        long_description=(
            read("README.rst") + "\n\n" +
            read("AUTHORS.rst")
        ),
        install_requires=[
            "characteristic>=14.0.0",
            "pyasn1",
            "pyasn1-modules",
            "pyopenssl>=0.12",
        ],
        extra_requires={
            'idna': ["idna"],
        },
        keywords="cryptography openssl pyopenssl",
        license="MIT",
        name="service_identity",
        packages=find_packages(exclude=['tests*']),
        url="https://github.com/pyca/service_identity",
        version=find_version('service_identity/__init__.py'),
        maintainer='Hynek Schlawack',
        maintainer_email='hs@ox.cx',
        classifiers=[
            "Development Status :: 5 - Production/Stable",
            "Intended Audience :: Developers",
            'License :: OSI Approved :: MIT License',
            "Natural Language :: English",
            "Operating System :: MacOS :: MacOS X",
            "Operating System :: POSIX",
            "Operating System :: POSIX :: BSD",
            "Operating System :: POSIX :: Linux",
            "Operating System :: Microsoft :: Windows",
            "Programming Language :: Python",
            "Programming Language :: Python :: 2",
            "Programming Language :: Python :: 2.6",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.3",
            "Programming Language :: Python :: 3.4",
            "Programming Language :: Python :: Implementation :: CPython",
            "Programming Language :: Python :: Implementation :: PyPy",
            "Topic :: Security :: Cryptography",
        ],
    )
