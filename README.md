# mimedet

Pure-Python MIME-type detection from magic bytes — no `libmagic`, no
runtime dependencies, drop-in for environments where you can't install
the C library or wheels.

`mimedet` ships with signatures for **40+ common formats** across
images, audio, video, archives, executables, fonts, and documents. The
registry is open: register your own `Signature` instances to add
custom formats.

## Install

```bash
python -m pip install -e .
```

Requires Python 3.10+.

## Usage

```python
from mimedet import detect, detect_file, detect_all

# From bytes
detection = detect(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...")
print(detection.mime_type)   # 'image/png'
print(detection.extension)   # 'png'
print(detection.confidence)  # 0..100

# From a path
detection = detect_file("photo.jpg")
print(detection.mime_type if detection else "unknown")

# Every match (priority-ordered)
for match in detect_all(b"<!DOCTYPE html><html>"):
    print(match.mime_type, match.confidence)
```

`detect` returns `None` when nothing matches; it raises
`EmptyDataError` only when the buffer is zero bytes.

## Supported formats

Out of the box, the registry covers (non-exhaustive):

- Images: JPEG, PNG, GIF (87a/89a), BMP, TIFF (LE/BE), WebP, ICO,
  HEIC, AVIF, SVG
- Audio: MP3 (ID3 + frame-sync), FLAC, WAV, Ogg
- Video: MP4 (ISO base media + brand sniff), Matroska / WebM, AVI
- Archives: ZIP (incl. docx/xlsx/pptx/jar/apk), gzip, bzip2, XZ, 7z,
  RAR (v1.5–v5), Zstd, POSIX tar
- Executables: ELF, Mach-O (4 variants), PE/EXE, WebAssembly, Java
  class, SQLite database
- Fonts: TTF, OTF, WOFF, WOFF2
- Documents: PDF, PostScript, RTF
- Markup: XML, HTML (with and without doctype)
- Flash: SWF (FWS / CWS / ZWS)

Use `mimedet.supported_types()` or `mimedet.signatures()` to introspect
the live registry at runtime.

## API

```python
from mimedet import (
    detect, detect_all, detect_file,
    Detection, Signature,
    register, reset_registry, unregister_all, signatures,
    supported_types, supported_extensions,
    lookup_by_mime, lookup_by_extension,
    MimeDetError, EmptyDataError, InvalidSignatureError,
)
```

### `detect(data) -> Detection | None`

Returns the highest-priority match. `data` is `bytes`, `bytearray`, or
`memoryview`. Raises `EmptyDataError` only on zero-length input.

### `detect_all(data) -> list[Detection]`

Same input, but returns every signature that matches, sorted highest
priority first.

### `detect_file(path, *, max_bytes=8192) -> Detection | None`

Reads up to `max_bytes` from `path` (any `os.PathLike`) and detects.
Returns `None` for empty files; propagates `OSError` for missing files
and directories.

### `register(signature)`

Adds a `Signature` to the registry. Use `unregister_all()` to wipe
everything (or `unregister_all(restore_builtins=False)` to start from
a blank slate).

### Custom signatures

```python
from mimedet import Signature, register, detect

register(Signature(
    mime_type="application/x-mygame-save",
    extension="sav",
    description="MyGame save file",
    magic=((0, b"MGSAVE"), (16, b"\x01\x02\x03\x04")),
    priority=200,
))

detect(open("game.sav", "rb").read(64))
```

`Signature` validates its inputs eagerly: empty magic, negative
offsets, and zero-length parts all raise `InvalidSignatureError`.

## Running tests

```bash
pip install -e ".[dev]" pytest pytest-cov mypy
pytest --cov=mimedet --cov-branch
mypy --strict src/mimedet
```

The test suite has 99 tests at 100% line + 100% branch coverage and
mypy `--strict` is clean.

## License

MIT © Nripanka Das
