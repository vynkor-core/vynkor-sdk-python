"""SDK error types, mirroring vynkor-wire's `WireError` enum.

Rust `WireError` is a single enum with payload-carrying variants; Python gets
a hierarchy instead — one exception class per variant, all under `VynkorError`
so callers can catch the base or a specific variant.
"""


class VynkorError(Exception):
    """Base class for every Vynkor SDK error (mirrors `WireError`)."""


class VynkorIoError(VynkorError):
    """Underlying I/O failure (mirrors `WireError::Io`)."""


class VynkorProtoError(VynkorError):
    """Protobuf encode/decode failure (mirrors `WireError::Proto`)."""


class VynkorFrameMagicMismatch(VynkorError):
    """Frame magic != 0x5652 (mirrors `WireError::FrameMagicMismatch`)."""


class VynkorFrameCrcMismatch(VynkorError):
    """Frame CRC32 mismatch (mirrors `WireError::FrameCrcMismatch`)."""


class VynkorFrameReadTimeout(VynkorError):
    """Timed out reading a frame body once it started (mirrors
    `WireError::FrameReadTimeout`)."""


class VynkorPayloadTooLarge(VynkorError):
    """Payload exceeds the protocol limit (mirrors `WireError::PayloadTooLarge`)."""

    def __init__(self, size: int):
        self.size = size
        super().__init__(f"payload too large: {size} bytes")


class VynkorTimeout(VynkorError):
    """Operation timed out (mirrors `WireError::Timeout`)."""

    def __init__(self, message: str = "operation timed out"):
        super().__init__(message)


class VynkorPermissionDenied(VynkorError):
    """Permission denied; message carries the reason (mirrors
    `WireError::PermissionDenied`)."""

    def __init__(self, message: str):
        super().__init__(f"permission denied: {message}")


class VynkorInternal(VynkorError):
    """Internal/protocol error; message carries details (mirrors
    `WireError::Internal`)."""

    def __init__(self, message: str):
        super().__init__(f"internal error: {message}")


__all__ = [
    "VynkorError",
    "VynkorIoError",
    "VynkorProtoError",
    "VynkorFrameMagicMismatch",
    "VynkorFrameCrcMismatch",
    "VynkorFrameReadTimeout",
    "VynkorPayloadTooLarge",
    "VynkorTimeout",
    "VynkorPermissionDenied",
    "VynkorInternal",
]
