"""Tests for the Signature dataclass and registry behaviour."""

import pytest

from mimedet import (
    Detection,
    InvalidSignatureError,
    MimeDetError,
    Signature,
    detect,
    lookup_by_extension,
    lookup_by_mime,
    register,
    reset_registry,
    signatures,
    supported_extensions,
    supported_types,
    unregister_all,
)


def test_signature_required_length_picks_max() -> None:
    sig = Signature(
        mime_type="x/y",
        extension="x",
        description="example",
        magic=((0, b"AB"), (10, b"CDE")),
    )
    assert sig.required_length() == 13


def test_signature_priority_inferred_from_byte_count() -> None:
    sig = Signature(
        mime_type="x/y",
        extension="x",
        description="example",
        magic=((0, b"AB"), (10, b"CDE")),
    )
    assert sig.priority == 5


def test_signature_explicit_priority_wins() -> None:
    sig = Signature(
        mime_type="x/y",
        extension="x",
        description="example",
        magic=((0, b"AB"),),
        priority=99,
    )
    assert sig.priority == 99


def test_signature_matches_returns_false_when_input_too_short() -> None:
    sig = Signature(
        mime_type="x/y",
        extension="x",
        description="example",
        magic=((0, b"ABCD"),),
    )
    assert sig.matches(b"AB") is False


def test_signature_matches_with_extra_check() -> None:
    sig = Signature(
        mime_type="x/y",
        extension="x",
        description="example",
        magic=((0, b"AA"),),
        extra_check=lambda data: data[2:3] == b"!",
    )
    assert sig.matches(b"AA!extra") is True
    assert sig.matches(b"AA?extra") is False


def test_signature_must_have_magic() -> None:
    with pytest.raises(InvalidSignatureError):
        Signature(
            mime_type="x/y",
            extension="x",
            description="example",
            magic=tuple(),
        )


def test_signature_rejects_negative_offset() -> None:
    with pytest.raises(InvalidSignatureError):
        Signature(
            mime_type="x/y",
            extension="x",
            description="example",
            magic=((-1, b"X"),),
        )


def test_signature_rejects_empty_magic_part() -> None:
    with pytest.raises(InvalidSignatureError):
        Signature(
            mime_type="x/y",
            extension="x",
            description="example",
            magic=((0, b""),),
        )


def test_signature_rejects_non_tuple_part() -> None:
    with pytest.raises(InvalidSignatureError):
        Signature(
            mime_type="x/y",
            extension="x",
            description="example",
            magic=("not a tuple",),  # type: ignore[arg-type]
        )


def test_signature_accepts_bytearray_in_magic() -> None:
    sig = Signature(
        mime_type="x/y",
        extension="x",
        description="example",
        magic=((0, bytearray(b"ABC")),),
    )
    assert sig.matches(b"ABCdef") is True


def test_detection_rejects_invalid_confidence() -> None:
    with pytest.raises(InvalidSignatureError):
        Detection(
            mime_type="x/y",
            extension="x",
            description="example",
            confidence=200,
        )


def test_register_new_signature_can_be_matched() -> None:
    custom = Signature(
        mime_type="application/x-magic",
        extension="mgc",
        description="custom magic",
        magic=((0, b"MAGICK"),),
        priority=200,
    )
    register(custom)
    detection = detect(b"MAGICK\x00\x00\x00\x00")
    assert detection is not None
    assert detection.mime_type == "application/x-magic"


def test_register_rejects_non_signature() -> None:
    with pytest.raises(InvalidSignatureError):
        register("not a signature")  # type: ignore[arg-type]


def test_unregister_all_clears_registry() -> None:
    unregister_all(restore_builtins=False)
    assert signatures() == []
    reset_registry()
    assert len(signatures()) > 30


def test_supported_types_lists_unique_mime_types() -> None:
    types_ = supported_types()
    assert "image/png" in types_
    assert "application/pdf" in types_
    assert types_ == sorted(set(types_))


def test_supported_extensions_excludes_blank() -> None:
    extensions = supported_extensions()
    assert "" not in extensions
    assert "png" in extensions
    assert "pdf" in extensions


def test_lookup_by_mime_returns_all_entries() -> None:
    pngs = lookup_by_mime("image/png")
    assert len(pngs) >= 1
    assert all(sig.mime_type == "image/png" for sig in pngs)


def test_lookup_by_mime_rejects_empty() -> None:
    with pytest.raises(MimeDetError):
        lookup_by_mime("")


def test_lookup_by_mime_rejects_non_string() -> None:
    with pytest.raises(MimeDetError):
        lookup_by_mime(123)  # type: ignore[arg-type]


def test_lookup_by_extension_strips_dot_and_lowercases() -> None:
    pngs_dot = lookup_by_extension(".PNG")
    pngs_plain = lookup_by_extension("png")
    assert [s.mime_type for s in pngs_dot] == [s.mime_type for s in pngs_plain]


def test_lookup_by_extension_rejects_empty() -> None:
    with pytest.raises(MimeDetError):
        lookup_by_extension("")


def test_lookup_by_extension_rejects_non_string() -> None:
    with pytest.raises(MimeDetError):
        lookup_by_extension(0)  # type: ignore[arg-type]
