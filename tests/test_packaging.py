from importlib import metadata

import pytest

import service_identity


class TestLegacyMetadataHack:
    def test_version(self):
        """
        service_identity.__version__ returns the correct version.
        """
        with pytest.deprecated_call():
            assert (
                metadata.version("service-identity")
                == service_identity.__version__
            )

    def test_description(self):
        """
        service_identity.__description__ returns the correct description.
        """
        with pytest.deprecated_call():
            assert (
                "Service identity verification for pyOpenSSL & cryptography."
                == service_identity.__description__
            )

    @pytest.mark.parametrize("name", ["uri", "url"])
    def test_uri(self, name):
        """
        service_identity.__uri__ & __url__ return the correct project URL.
        """
        with pytest.deprecated_call():
            assert "https://service-identity.readthedocs.io/" == getattr(
                service_identity, f"__{name}__"
            )

    def test_email(self):
        """
        service_identity.__email__ returns Hynek's email address.
        """
        with pytest.deprecated_call():
            assert "hs@ox.cx" == service_identity.__email__

    def test_does_not_exist(self):
        """
        Asking for unsupported dunders raises an AttributeError.
        """
        with pytest.raises(
            AttributeError,
            match="module service_identity has no attribute __yolo__",
        ):
            service_identity.__yolo__
