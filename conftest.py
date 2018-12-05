def pytest_report_header(config):
    import OpenSSL
    import OpenSSL.SSL
    import cryptography

    return """\
OpenSSL: {openssl}
pyOpenSSL: {pyOpenSSL}
cryptography: {cryptography}""".format(
        openssl=OpenSSL.SSL.SSLeay_version(OpenSSL.SSL.SSLEAY_VERSION).decode(
            "ascii"
        ),
        pyOpenSSL=OpenSSL.__version__,
        cryptography=cryptography.__version__,
    )
