"""Detection tests for fonts and text-ish formats."""

import pytest

from mimedet import detect


@pytest.mark.parametrize(
    "head,expected",
    [
        (b"\x00\x01\x00\x00\x00\x10", "font/ttf"),
        (b"OTTO\x00\x10", "font/otf"),
        (b"wOFF\x00\x01\x00\x00", "font/woff"),
        (b"wOF2\x00\x01\x00\x00", "font/woff2"),
        (b"%PDF-1.4\n%", "application/pdf"),
        (b"%!PS-Adobe-3.0\n", "application/postscript"),
        (b"{\\rtf1\\ansi", "application/rtf"),
        (b"FWS\x08\xff\x00", "application/x-shockwave-flash"),
        (b"CWS\x09\xff\x00", "application/x-shockwave-flash"),
        (b"ZWS\x0d\xff\x00", "application/x-shockwave-flash"),
        (b"<?xml version='1.0'?>\n", "application/xml"),
        (b"<!DOCTYPE html><html><body></body></html>", "text/html"),
        (b"<html><head></head><body></body></html>", "text/html"),
    ],
)
def test_text_and_font_signatures_match(head: bytes, expected: str) -> None:
    detection = detect(head)
    assert detection is not None
    assert detection.mime_type == expected


def test_html_with_leading_whitespace_is_not_detected() -> None:
    """We require '<' at byte 0; leading whitespace defeats the magic match.

    This matches how `file(1)` and most other detectors behave — HTML
    that does not start with '<' is treated as plain text.
    """
    assert detect(b"  \n<!DOCTYPE html><html></html>") is None
