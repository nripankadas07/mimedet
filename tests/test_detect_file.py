"""Tests for detect_file."""

from pathlib import Path

import pytest

from mimedet import MimeDetError, detect_file


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_detect_file_png(tmp_path: Path) -> None:
    path = _write(tmp_path, "x.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    detection = detect_file(path)
    assert detection is not None
    assert detection.mime_type == "image/png"


def test_detect_file_pdf_via_str_path(tmp_path: Path) -> None:
    path = _write(tmp_path, "x.pdf", b"%PDF-1.5\n%\n")
    detection = detect_file(str(path))
    assert detection is not None
    assert detection.mime_type == "application/pdf"


def test_detect_file_empty_returns_none(tmp_path: Path) -> None:
    path = _write(tmp_path, "empty", b"")
    assert detect_file(path) is None


def test_detect_file_unknown_returns_none(tmp_path: Path) -> None:
    path = _write(tmp_path, "noise", b"completely unrelated bytes here")
    assert detect_file(path) is None


def test_detect_file_missing_raises_oserror(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        detect_file(tmp_path / "nope")


def test_detect_file_directory_raises_oserror(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        detect_file(tmp_path)


def test_detect_file_max_bytes_must_be_positive(tmp_path: Path) -> None:
    path = _write(tmp_path, "x.png", b"\x89PNG\r\n\x1a\n")
    with pytest.raises(MimeDetError):
        detect_file(path, max_bytes=0)


def test_detect_file_respects_max_bytes(tmp_path: Path) -> None:
    """If max_bytes only reads 4 bytes we cannot match an 8-byte signature."""
    path = _write(tmp_path, "x.png", b"\x89PNG\r\n\x1a\nIHDR" + b"\x00" * 16)
    detection = detect_file(path, max_bytes=4)
    assert detection is None
