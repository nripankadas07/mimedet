"""Public dataclasses for mimedet: ``Signature`` and ``Detection``.

A ``Signature`` describes one or more (offset, magic bytes) tuples that
must all match the head of a buffer for the signature to fire. A
``Detection`` is the immutable result returned by ``detect`` /
``detect_file``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence, Tuple

from ._errors import InvalidSignatureError

_MagicPart = Tuple[int, bytes]


def _normalise_magic(magic: Sequence[_MagicPart]) -> Tuple[_MagicPart, ...]:
    """Validate and freeze a magic-bytes specification."""
    if not magic:
        raise InvalidSignatureError(
            "signature must declare at least one (offset, bytes) pair"
        )
    parts: list[_MagicPart] = []
    for entry in magic:
        if (
            not isinstance(entry, tuple)
            or len(entry) != 2
            or not isinstance(entry[0], int)
            or not isinstance(entry[1], (bytes, bytearray))
        ):
            raise InvalidSignatureError(
                "magic entries must be (int, bytes) tuples, got "
                f"{entry!r}"
            )
        offset, raw = entry
        if offset < 0:
            raise InvalidSignatureError(
                f"magic offset must be non-negative, got {offset}"
            )
        if len(raw) == 0:
            raise InvalidSignatureError("magic bytes must be non-empty")
        parts.append((offset, bytes(raw)))
    return tuple(parts)


@dataclass(frozen=True)
class Signature:
    """A single MIME-type signature.

    ``magic`` is a sequence of ``(offset, bytes)`` pairs: every pair must
    match for the signature to fire. ``priority`` ranks two competing
    matches (higher wins); when omitted, it defaults to the total number
    of bytes the signature actually checks.
    """

    mime_type: str
    extension: str
    description: str
    magic: Tuple[_MagicPart, ...]
    priority: int = 0
    extra_check: object = field(default=None, repr=False)

    def __post_init__(self) -> None:
        normalised = _normalise_magic(self.magic)
        object.__setattr__(self, "magic", normalised)
        if self.priority == 0:
            inferred = sum(len(part) for _, part in normalised)
            object.__setattr__(self, "priority", inferred)

    def required_length(self) -> int:
        """Smallest input length that could ever produce a match."""
        return max(offset + len(part) for offset, part in self.magic)

    def matches(self, data: bytes) -> bool:
        """Return True if ``data`` satisfies every magic part of this sig."""
        if len(data) < self.required_length():
            return False
        for offset, part in self.magic:
            if data[offset : offset + len(part)] != part:
                return False
        check = self.extra_check
        if check is not None:
            return bool(check(data))  # type: ignore[operator]
        return True


@dataclass(frozen=True)
class Detection:
    """Result of a detection: the best signature plus a 0–100 confidence."""

    mime_type: str
    extension: str
    description: str
    confidence: int

    def __post_init__(self) -> None:
        if not (0 <= self.confidence <= 100):
            raise InvalidSignatureError(
                f"confidence must be in 0..100, got {self.confidence}"
            )
