"""mimedet — pure-Python MIME-type detection from magic bytes.

Public surface::

    from mimedet import detect, detect_all, detect_file, Detection
    from mimedet import Signature, register, signatures
    from mimedet import MimeDetError, EmptyDataError, InvalidSignatureError
"""

from __future__ import annotations

from ._api import (
    detect,
    detect_all,
    detect_file,
    lookup_by_extension,
    lookup_by_mime,
    register,
    reset_registry,
    signatures,
    supported_extensions,
    supported_types,
    unregister_all,
)
from ._errors import EmptyDataError, InvalidSignatureError, MimeDetError
from ._types import Detection, Signature

__all__ = [
    "detect",
    "detect_all",
    "detect_file",
    "lookup_by_extension",
    "lookup_by_mime",
    "register",
    "reset_registry",
    "unregister_all",
    "signatures",
    "supported_extensions",
    "supported_types",
    "EmptyDataError",
    "InvalidSignatureError",
    "MimeDetError",
    "Detection",
    "Signature",
]

__version__ = "0.1.0"
