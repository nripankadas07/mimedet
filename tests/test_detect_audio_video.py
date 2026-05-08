"""Detection tests for the audio / video signatures."""

import pytest

from mimedet import detect


@pytest.mark.parametrize(
    "head,expected",
    [
        (b"ID3\x04\x00\x00\x00\x00\x00\x00", "audio/mpeg"),
        (b"\xff\xfb\x90\x44", "audio/mpeg"),
        (b"fLaC\x00\x00\x00\x22", "audio/flac"),
        (b"RIFFxxxxWAVEfmt ", "audio/wav"),
        (b"OggS\x00\x02\x00\x00", "audio/ogg"),
        (b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00", "video/mp4"),
        (b"\x00\x00\x00\x20ftypmp42\x00\x00\x00\x00", "video/mp4"),
        (b"\x1a\x45\xdf\xa3\x9f\x42\x86", "video/x-matroska"),
        (b"RIFFxxxxAVI LIST", "video/x-msvideo"),
    ],
)
def test_audio_video_signatures_match(head: bytes, expected: str) -> None:
    detection = detect(head)
    assert detection is not None
    assert detection.mime_type == expected


def test_mp4_unknown_brand_does_not_match() -> None:
    head = b"\x00\x00\x00\x18ftypwxyz\x00\x00\x02\x00"
    detection = detect(head)
    if detection is not None:
        assert detection.mime_type != "video/mp4"
