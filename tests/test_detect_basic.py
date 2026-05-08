"""Tests for the basic detect / detect_all behaviour."""

import pytest

from mimedet import (
    Detection,
    EmptyDataError,
    MimeDetError,
    detect,
    detect_all,
)


def test_detect_returns_detection_dataclass() -> None:
    detection = detect(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    assert isinstance(detection, Detection)
    assert detection.extension == "png"
    assert detection.description.startswith("PNG")
    assert 60 <= detection.confidence <= 100


def test_detect_unknown_returns_none() -> None:
    assert detect(b"this is not any known format") is None


def test_detect_short_buffer_returns_none() -> None:
    assert detect(b"\x89PN") is None


def test_detect_empty_raises() -> None:
    with pytest.raises(EmptyDataError):
        detect(b"")


def test_detect_all_empty_raises() -> None:
    with pytest.raises(EmptyDataError):
        detect_all(b"")


def test_detect_accepts_bytearray() -> None:
    detection = detect(bytearray(b"\xff\xd8\xff\xe0"))
    assert detection is not None
    assert detection.mime_type == "image/jpeg"


def test_detect_accepts_memoryview() -> None:
    buffer = memoryview(b"%PDF-1.7\n%")
    detection = detect(buffer)
    assert detection is not None
    assert detection.mime_type == "application/pdf"


def test_detect_rejects_non_bytes() -> None:
    with pytest.raises(MimeDetError):
        detect("string")  # type: ignore[arg-type]


def test_detect_all_returns_priority_ordered() -> None:
    head = b"<!DOCTYPE html><html></html>"
    matches = detect_all(head)
    assert len(matches) >= 1
    assert matches[0].mime_type == "text/html"
    confidences = [m.confidence for m in matches]
    assert confidences == sorted(confidences, reverse=True)


def test_detect_unknown_returns_empty_detect_all() -> None:
    assert detect_all(b"random unrelated noise here") == []
