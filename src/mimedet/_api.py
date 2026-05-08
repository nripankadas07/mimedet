"""Public detection API.

The module owns a singleton list of registered ``Signature`` objects
which starts as a copy of the built-in table. Callers can ``register``
their own signatures or ``unregister_all`` to wipe the registry back to
the built-ins.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Sequence, Union

from ._errors import EmptyDataError, InvalidSignatureError, MimeDetError
from ._signatures import BUILTIN_SIGNATURES
from ._types import Detection, Signature

_BytesLike = Union[bytes, bytearray, memoryview]
PathLike = Union[str, "os.PathLike[str]"]

_DEFAULT_HEAD = 8192

_REGISTRY: List[Signature] = list(BUILTIN_SIGNATURES)


def _coerce_data(data: _BytesLike) -> bytes:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise MimeDetError(
        f"data must be bytes/bytearray/memoryview, got {type(data).__name__}"
    )


def _confidence_for(sig: Signature) -> int:
    """Map the priority/byte-length to a 0..100 confidence band."""
    score = sig.priority
    if score >= 16:
        return 100
    if score >= 8:
        return 90
    if score >= 4:
        return 80
    return 60


def detect(data: _BytesLike) -> Optional[Detection]:
    """Return the highest-priority match, or ``None`` if nothing matches.

    Raises :class:`EmptyDataError` if the buffer is empty.
    """
    raw = _coerce_data(data)
    if len(raw) == 0:
        raise EmptyDataError("cannot detect MIME type from zero bytes")
    matches = detect_all(raw)
    return matches[0] if matches else None


def detect_all(data: _BytesLike) -> List[Detection]:
    """Return every matching signature, sorted highest-priority first.

    Raises :class:`EmptyDataError` if the buffer is empty.
    """
    raw = _coerce_data(data)
    if len(raw) == 0:
        raise EmptyDataError("cannot detect MIME type from zero bytes")
    hits: list[tuple[int, Signature]] = []
    for sig in _REGISTRY:
        if sig.matches(raw):
            hits.append((sig.priority, sig))
    hits.sort(key=lambda pair: pair[0], reverse=True)
    return [
        Detection(
            mime_type=sig.mime_type,
            extension=sig.extension,
            description=sig.description,
            confidence=_confidence_for(sig),
        )
        for _, sig in hits
    ]


def detect_file(
    path: PathLike,
    *,
    max_bytes: int = _DEFAULT_HEAD,
) -> Optional[Detection]:
    """Read up to ``max_bytes`` from ``path`` and detect the MIME type.

    Returns ``None`` for an empty file. Propagates :class:`OSError` for
    missing files / directory paths / permission failures.
    """
    if max_bytes <= 0:
        raise MimeDetError(
            f"max_bytes must be positive, got {max_bytes}"
        )
    target = Path(os.fspath(path))
    with target.open("rb") as handle:
        head = handle.read(max_bytes)
    if not head:
        return None
    return detect(head)


def signatures() -> List[Signature]:
    """Return a snapshot of the current signature registry."""
    return list(_REGISTRY)


def register(signature: Signature) -> None:
    """Add ``signature`` to the registry. Raises if not a Signature."""
    if not isinstance(signature, Signature):
        raise InvalidSignatureError(
            f"register expected a Signature, got {type(signature).__name__}"
        )
    _REGISTRY.append(signature)


def unregister_all(*, restore_builtins: bool = True) -> None:
    """Reset the registry. If ``restore_builtins`` is True, reload defaults."""
    _REGISTRY.clear()
    if restore_builtins:
        _REGISTRY.extend(BUILTIN_SIGNATURES)


def reset_registry() -> None:
    """Alias for :func:`unregister_all` with default arguments."""
    unregister_all()


def supported_types() -> List[str]:
    """Return the sorted unique set of MIME types covered by the registry."""
    return sorted({sig.mime_type for sig in _REGISTRY})


def supported_extensions() -> List[str]:
    """Return the sorted unique set of extensions covered by the registry."""
    return sorted({sig.extension for sig in _REGISTRY if sig.extension})


def lookup_by_mime(mime_type: str) -> List[Signature]:
    """Return every registered signature with the given MIME type."""
    if not isinstance(mime_type, str) or mime_type == "":
        raise MimeDetError("mime_type must be a non-empty string")
    return [sig for sig in _REGISTRY if sig.mime_type == mime_type]


def lookup_by_extension(extension: str) -> List[Signature]:
    """Return every registered signature with the given extension."""
    if not isinstance(extension, str):
        raise MimeDetError("extension must be a string")
    cleaned = extension.lower().lstrip(".")
    if cleaned == "":
        raise MimeDetError("extension must be non-empty")
    return [sig for sig in _REGISTRY if sig.extension == cleaned]


__all__: Sequence[str] = (
    "detect",
    "detect_all",
    "detect_file",
    "register",
    "reset_registry",
    "unregister_all",
    "signatures",
    "supported_types",
    "supported_extensions",
    "lookup_by_mime",
    "lookup_by_extension",
)
