"""Detection tests for executables and binary container formats."""

import pytest

from mimedet import detect


@pytest.mark.parametrize(
    "head,expected",
    [
        (b"\x7fELF\x02\x01\x01\x00", "application/x-elf"),
        (b"\xfe\xed\xfa\xce", "application/x-mach-binary"),
        (b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
        (b"\xce\xfa\xed\xfe", "application/x-mach-binary"),
        (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
        (
            b"MZ\x90\x00\x03\x00\x00\x00",
            "application/vnd.microsoft.portable-executable",
        ),
        (b"\x00asm\x01\x00\x00\x00", "application/wasm"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x34", "application/java-vm"),
        (b"SQLite format 3\x00", "application/vnd.sqlite3"),
    ],
)
def test_executable_signatures_match(head: bytes, expected: str) -> None:
    detection = detect(head)
    assert detection is not None
    assert detection.mime_type == expected
