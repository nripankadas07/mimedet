"""Make sure the public surface stays stable."""

import mimedet


def test_public_callables_present() -> None:
    expected = {
        "detect",
        "detect_all",
        "detect_file",
        "register",
        "reset_registry",
        "unregister_all",
        "signatures",
        "supported_types",
        "supported_extensions",
        "lookup_by_mime",
        "lookup_by_extension",
    }
    for name in expected:
        assert callable(getattr(mimedet, name)), name


def test_public_classes_present() -> None:
    assert isinstance(mimedet.Detection, type)
    assert isinstance(mimedet.Signature, type)
    assert issubclass(mimedet.MimeDetError, ValueError)
    assert issubclass(mimedet.EmptyDataError, mimedet.MimeDetError)
    assert issubclass(mimedet.InvalidSignatureError, mimedet.MimeDetError)


def test_version_exported() -> None:
    assert isinstance(mimedet.__version__, str)


def test_all_listing_complete() -> None:
    for name in mimedet.__all__:
        assert hasattr(mimedet, name), name
