"""Exceptions raised by mimedet.

Every mimedet failure derives from `MimeDetError` so callers can use a
single `except MimeDetError` clause when they want to swallow them all.
"""

from __future__ import annotations


class MimeDetError(ValueError):
    """Base class for mimedet errors. Subclass of ``ValueError``."""


class EmptyDataError(MimeDetError):
    """Raised when zero bytes are provided to a detection function."""


class InvalidSignatureError(MimeDetError):
    """Raised when ``register`` is called with a malformed signature."""
