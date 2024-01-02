import cryptography


try:
    import OpenSSL
    import OpenSSL.SSL
except ImportError:
    OpenSSL = None


def pytest_report_header(config):
    if OpenSSL is not None:
        openssl_version = OpenSSL.SSL.SSLeay_version(
            OpenSSL.SSL.SSLEAY_VERSION
        ).decode("ascii")
        pyopenssl_version = OpenSSL.__version__
    else:
        openssl_version = "n/a"
        pyopenssl_version = "missing"

    return f"""\
OpenSSL: {openssl_version}
pyOpenSSL: {pyopenssl_version}
cryptography: {cryptography.__version__}"""
