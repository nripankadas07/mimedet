"""Detection tests for the archive / compressed signatures."""

import pytest

from mimedet import detect


@pytest.mark.parametrize(
    "head,expected",
    [
        (b"PK\x03\x04" + b"\x14\x00\x00\x00\x08\x00", "application/zip"),
        (b"PK\x05\x06" + b"\x00" * 18, "application/zip"),
        (b"\x1f\x8b\x08\x00\x00\x00\x00\x00", "application/gzip"),
        (b"BZh91AY&SY", "application/x-bzip2"),
        (b"\xfd7zXZ\x00\x00\x04", "application/x-xz"),
        (b"7z\xbc\xaf\x27\x1c\x00\x04", "application/x-7z-compressed"),
        (b"Rar!\x1a\x07\x00\x00", "application/vnd.rar"),
        (b"Rar!\x1a\x07\x01\x00\x00", "application/vnd.rar"),
        (b"\x28\xb5\x2f\xfd\x00\x48", "application/zstd"),
    ],
)
def test_archive_signatures_match(head: bytes, expected: str) -> None:
    detection = detect(head)
    assert detection is not None
    assert detection.mime_type == expected


def test_tar_ustar_signature_at_offset_257() -> None:
    head = bytearray(512)
    name = b"hello.txt".ljust(100, b"\x00")
    head[0 : len(name)] = name
    head[257 : 257 + 5] = b"ustar"
    detection = detect(bytes(head))
    assert detection is not None
    assert detection.mime_type == "application/x-tar"
