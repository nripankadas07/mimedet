"""Built-in MIME signatures for mimedet.

The table is hand-rolled — every entry is a small verifiable fact about
a file format. Each category lives in its own helper so the file stays
scannable; ordering does not matter (matches are ranked by priority).
"""

from __future__ import annotations

from typing import Callable, List, Tuple

from ._types import Signature

_MP4_BRANDS = {
    b"isom",
    b"iso2",
    b"mp41",
    b"mp42",
    b"mmp4",
    b"avc1",
    b"M4V ",
    b"M4A ",
    b"M4" ",
    b"dash",
}


def _is_mp4(data: bytes) -> bool:
    return data[8:12] in _MP4_BRANDS


def _is_text_starting(prefix: bytes) -> Callable[[bytes], bool]:
    def check(data: bytes) -> bool:
        head = data[: len(prefix) + 8].lstrip()
        return head.startswith(prefix)

    return check


def _make(
    mime: str,
    ext: str,
    description: str,
    magic: list[tuple[int, bytes]],
    *,
    priority: int = 0,
    extra: Callable[[bytes], bool] | None = None,
) -> Signature:
    return Signature(
        mime_type=mime,
        extension=ext,
        description=description,
        magic=tuple(magic),
        priority=priority,
        extra_check=extra,
    )


def _images() -> List[Signature]:
    return [
        _make("image/jpeg", "jpg", "JPEG image", [(0, b"\xff\xd8\xff")]),
        _make("image/png", "png", "PNG image", [(0, b"\x89PNG\r\n\x1a\n")]),
        _make("image/gif", "gif", "GIF image (87a)", [(0, b"GIF87a")]),
        _make("image/gif", "gif", "GIF image (89a)", [(0, b"GIF89a")]),
        _make("image/bmp", "bmp", "BMP image", [(0, b"BM")]),
        _make("image/tiff", "tiff", "TIFF image (LE)", [(0, b"II*\x00")]),
        _make("image/tiff", "tiff", "TIFF image (BE)", [(0, b"MM\x00*")]),
        _make("image/webp", "webp", "WebP image",
              [(0, b"RIFF"), (8, b"WEBP")]),
        _make("image/vnd.microsoft.icon", "ico", "Windows icon",
              [(0, b"\x00\x00\x01\x00")]),
        _make("image/heic", "heic", "HEIC image", [(4, b"ftypheic")]),
        _make("image/avif", "avif", "AVIF image", [(4, b"ftypavif")]),
        _make(
            "image/svg+xml", "svg", "SVG image",
            [(0, b"<")], priority=12,
            extra=_is_text_starting(b"<svg"),
        ),
    ]


def _documents() -> List[Signature]:
    return [
        _make("application/pdf", "pdf", "PDF document", [(0, b"%PDF-")]),
        _make("application/postscript", "ps", "PostScript", [(0, b"%!PS")]),
        _make("application/rtf", "rtf", "Rich Text Format",
              [(0, b"{\\rtf")]),
    ]


def _archives() -> List[Signature]:
    return [
        _make("application/zip", "zip",
              "ZIP archive (also docx/xlsx/pptx/jar/apk)",
              [(0, b"PK\x03\x04")]),
        _make("application/zip", "zip", "ZIP archive (empty)",
              [(0, b"PK\x05\x06")]),
        _make("application/gzip", "gz", "Gzip archive",
              [(0, b"\x1f\x8b")]),
        _make("application/x-bzip2", "bz2", "Bzip2 archive",
              [(0, b"BZh")]),
        _make("application/x-xz", "xz", "XZ archive",
              [(0, b"\xfd7zXZ\x00")]),
        _make("application/x-7z-compressed", "7z", "7-Zip archive",
              [(0, b"7z\xbc\xaf\x27\x1c")]),
        _make("application/vnd.rar", "rar", "RAR archive (v1.5–4)",
              [(0, b"Rar!\x1a\x07\x00")]),
        _make("application/vnd.rar", "rar", "RAR archive (v5)",
              [(0, b"Rar!\x1a\x07\x01\x00")]),
        _make("application/zstd", "zst", "Zstandard archive",
              [(0, b"\x28\xb5\x2f\xfd")]),
        _make("application/x-tar", "tar", "POSIX tar archive (ustar)",
              [(257, b"ustar")]),
    ]


def _audio_video() -> List[Signature]:
    return [
        _make("audio/mpeg", "mp3", "MP3 audio (ID3v2)", [(0, b"ID3")]),
        _make("audio/mpeg", "mp3", "MP3 audio (frame sync)",
              [(0, b"\xff\xfb")]),
        _make("audio/flac", "flac", "FLAC audio", [(0, b"fLaC")]),
        _make("audio/wav", "wav", "WAV audio",
              [(0, b"RIFF"), (8, b"WAVE")]),
        _make("audio/ogg", "ogg", "Ogg container", [(0, b"OggS")]),
        _make(
            "video/mp4", "mp4", "MP4 / ISO base media",
            [(4, b"ftyp")], priority=20, extra=_is_mp4,
        ),
        _make("video/x-matroska", "mkv", "Matroska / WebM container",
              [(0, b"\x1a\x45\xdf\xa3")]),
        _make("video/x-msvideo", "avi", "AVI video",
              [(0, b"RIFF"), (8, b"AVI ")]),
    ]


def _executables() -> List[Signature]:
    return [
        _make("application/x-elf", "", "ELF executable",
              [(0, b"\x7fELF")]),
        _make("application/x-mach-binary", "", "Mach-O 32-bit",
              [(0, b"\xfe\xed\xfa\xce")]),
        _make("application/x-mach-binary", "", "Mach-O 64-bit",
              [(0, b"\xfe\xed\xfa\xcf")]),
        _make("application/x-mach-binary", "", "Mach-O 32-bit swapped",
              [(0, b"\xce\xfa\xed\xfe")]),
        _make("application/x-mach-binary", "", "Mach-O 64-bit swapped",
              [(0, b"\xcf\xfa\xed\xfe")]),
        _make("application/vnd.microsoft.portable-executable", "exe",
              "Windows PE executable", [(0, b"MZ")]),
        _make("application/wasm", "wasm", "WebAssembly module",
              [(0, b"\x00asm")]),
        _make("application/java-vm", "class", "Java class file",
              [(0, b"\xca\xfe\xba\xbe")]),
        _make("application/vnd.sqlite3", "sqlite", "SQLite database",
              [(0, b"SQLite format 3\x00")]),
    ]


def _fonts() -> List[Signature]:
    return [
        _make("font/ttf", "ttf", "TrueType font",
              [(0, b"\x00\x01\x00\x00")]),
        _make("font/otf", "otf", "OpenType font", [(0, b"OTTO")]),
        _make("font/woff", "woff", "WOFF font", [(0, b"wOFF")]),
        _make("font/woff2", "woff2", "WOFF2 font", [(0, b"wOF2")]),
    ]


def _text_and_misc() -> List[Signature]:
    return [
        _make(
            "application/xml", "xml", "XML document",
            [(0, b"<")], priority=8, extra=_is_text_starting(b"<?xml"),
        ),
        _make(
            "text/html", "html", "HTML document",
            [(0, b"<")], priority=10,
            extra=_is_text_starting(b"<!DOCTYPE html"),
        ),
        _make(
            "text/html", "html", "HTML document (no doctype)",
            [(0, b"<")], priority=6, extra=_is_text_starting(b"<html"),
        ),
        _make("application/x-shockwave-flash", "swf",
              "Flash SWF (uncompressed)", [(0, b"FWS")]),
        _make("application/x-shockwave-flash", "swf",
              "Flash SWF (zlib)", [(0, b"CWS")]),
        _make("application/x-shockwave-flash", "swf",
              "Flash SWF (LZMA)", [(0, b"ZWS")]),
    ]


def _build() -> Tuple[Signature, ...]:
    sigs: List[Signature] = []
    sigs.extend(_images())
    sigs.extend(_documents())
    sigs.extend(_archives())
    sigs.extend(_audio_video())
    sigs.extend(_executables())
    sigs.extend(_fonts())
    sigs.extend(_text_and_misc())
    return tuple(sigs)


BUILTIN_SIGNATURES: Tuple[Signature, ...] = _build()
