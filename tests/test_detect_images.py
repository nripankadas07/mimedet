"""Detection tests for the image format signatures."""

import pytest

from mimedet import detect


@pytest.mark.parametrize(
    "head,expected",
    [
        (b"\xff\xd8\xff\xe0\x00\x10JFIF", "image/jpeg"),
        (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR", "image/png"),
        (b"GIF89a" + b"\x10\x00\x10\x00", "image/gif"),
        (b"GIF87a" + b"\x10\x00\x10\x00", "image/gif"),
        (b"BM" + b"\x76\x00\x00\x00\x00\x00\x00\x00", "image/bmp"),
        (b"II*\x00" + b"\x08\x00\x00\x00", "image/tiff"),
        (b"MM\x00*" + b"\x00\x00\x00\x08", "image/tiff"),
        (b"RIFFxxxxWEBPVP8 ", "image/webp"),
        (b"\x00\x00\x01\x00\x01\x00\x10\x10", "image/vnd.microsoft.icon"),
        (b"\x00\x00\x00\x18ftypheic\x00", "image/heic"),
        (b"\x00\x00\x00\x18ftypavif\x00", "image/avif"),
        (b"<svg xmlns='http://www.w3.org/2000/svg'>", "image/svg+xml"),
    ],
)
def test_image_signatures_match(head: bytes, expected: str) -> None:
    detection = detect(head)
    assert detection is not None
    assert detection.mime_type == expected
