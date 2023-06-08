import codecs
import os
import re

from setuptools import find_packages, setup


###############################################################################

NAME = "service-identity"
KEYWORDS = ["cryptography", "openssl", "pyopenssl"]
CLASSIFIERS = [
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: Implementation :: CPython",
    "Programming Language :: Python :: Implementation :: PyPy",
    "Topic :: Security :: Cryptography",
    "Topic :: Software Development :: Libraries :: Python Modules",
]
INSTALL_REQUIRES = [
    "attrs>=19.1.0",
    "pyasn1-modules",
    # Place pyasn1 after pyasn1-modules to workaround setuptools install bug:
    # https://github.com/pypa/setuptools/issues/498
    "pyasn1",
    "cryptography",
]
EXTRAS_REQUIRE = {
    "idna": ["idna"],
    "tests": ["coverage[toml]>=5.0.2", "pytest"],
    "docs": ["sphinx", "furo"],
}
EXTRAS_REQUIRE["dev"] = (
    EXTRAS_REQUIRE["tests"] + EXTRAS_REQUIRE["docs"] + ["idna", "pyOpenSSL"]
)
PROJECT_URLS = {
    "Documentation": "https://service-identity.readthedocs.io/",
    "Bug Tracker": "https://github.com/pyca/service-identity/issues",
    "Source Code": "https://github.com/pyca/service-identity",
    "Funding": "https://github.com/sponsors/hynek",
}

###############################################################################

HERE = os.path.abspath(os.path.dirname(__file__))
PACKAGES = find_packages(where="src")
META_PATH = os.path.join(HERE, "src", NAME.replace("-", "_"), "__init__.py")


def read(*parts):
    """
    Build an absolute path from *parts* and and return the contents of the
    resulting file.  Assume UTF-8 encoding.
    """
    with codecs.open(os.path.join(HERE, *parts), "rb", "utf-8") as f:
        return f.read()


META_FILE = read(META_PATH)


def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.
    """
    meta_match = re.search(
        r"^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta), META_FILE, re.M
    )
    if meta_match:
        return meta_match.group(1)
    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))


URL = find_meta("url")
LONG = (
    read("README.rst")
    + "\n\n"
    + "Release Information\n"
    + "===================\n\n"
    + re.search(
        r"(\d+.\d.\d \(.*?\)\r?\n.*?)\r?\n\r?\n\r?\n----\r?\n\r?\n\r?\n",
        read("CHANGELOG.rst"),
        re.S,
    ).group(1)
    + "\n\n`Full changelog "
    + "<{uri}en/stable/changelog.html>`_."
).format(uri=URL)


if __name__ == "__main__":
    setup(
        name=NAME,
        description=find_meta("description"),
        license=find_meta("license"),
        url=URL,
        project_urls=PROJECT_URLS,
        version=find_meta("version"),
        author=find_meta("author"),
        author_email=find_meta("email"),
        maintainer=find_meta("author"),
        maintainer_email=find_meta("email"),
        keywords=KEYWORDS,
        long_description=LONG,
        long_description_content_type="text/x-rst",
        packages=PACKAGES,
        package_dir={"": "src"},
        zip_safe=False,
        classifiers=CLASSIFIERS,
        install_requires=INSTALL_REQUIRES,
        extras_require=EXTRAS_REQUIRE,
        options={"bdist_wheel": {"universal": "1"}},
    )
