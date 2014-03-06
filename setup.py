import codecs
import os
import re

from setuptools import setup


def read(*parts):
    """
    Build an absolute path from *parts* and and return the contents of the
    resulting file.  Assume UTF-8 encoding.
    """
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, *parts), 'r', 'utf-8') as f:
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
        classifiers=[
            "Development Status :: 2 - Pre-Alpha",
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
            "Programming Language :: Python :: 3.2",
            "Programming Language :: Python :: 3.3",
            "Programming Language :: Python :: Implementation :: CPython",
            "Programming Language :: Python :: Implementation :: PyPy",
            "Topic :: Security :: Cryptography",
        ],
        description="Service identity verification for pyOpenSSL.",
        long_description=read('README.rst'),
        install_requires=[
            "pyasn1",
            "pyasn1-modules",
            "pyopenssl>=0.12",
        ],
        keywords="cryptography openssl pyopenssl",
        license="MIT",
        name="service_identity",
        py_modules=["service_identity", "test_service_identity"],
        url="https://github.com/hynek/service_identity",
        version=find_version('service_identity.py'),
        maintainer='Hynek Schlawack',
        maintainer_email='hs@ox.cx',
    )
