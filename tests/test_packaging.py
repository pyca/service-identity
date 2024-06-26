from importlib import metadata

import pytest

import service_identity


class TestLegacyMetadataHack:
    def test_version(self):
        """
        service_identity.__version__ returns the correct version.
        """
        assert (
            metadata.version("service-identity")
            == service_identity.__version__
        )

    def test_does_not_exist(self):
        """
        Asking for unsupported dunders raises an AttributeError.
        """
        with pytest.raises(
            AttributeError,
            match="module service_identity has no attribute __yolo__",
        ):
            service_identity.__yolo__
