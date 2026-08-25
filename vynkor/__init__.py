"""Vynkor Python SDK — async IPC client (UDS + WebSocket), Plugin base,
and full Vynkor wire protocol.

Mirrors ``vynkor-sdk/src/lib.rs`` re-exports 1:1.
"""

try:
    from google.protobuf.runtime_version import VersionError as _ProtoVersionError
except ImportError:
    _ProtoVersionError = ImportError  # type: ignore[assignment,misc]

try:
    from .client import VynkorClient
    from .concurrent import ConcurrentHandler, response_envelope, run_concurrent_loop, serve_concurrent
    from .confirmation_gate import ConfirmationGate, PendingAction, send_confirmation, send_confirmation_request
    from .errors import VynkorError
    from .plugin import Plugin
except (ImportError, _ProtoVersionError) as _import_err:  # missing deps or protobuf version mismatch
    _captured_err = _import_err

    def _unavailable(name: str, _err: BaseException = _captured_err) -> type:  # type: ignore[assignment]
        def _raise(*_args: object, **_kwargs: object) -> None:
            raise ImportError(
                f"vynkor.{name} unavailable: {_err}. "
                "Install the vynkor SDK's declared dependencies (see pyproject.toml) to use it."
            ) from _err

        return type(name, (), {"__init__": _raise, "__init_subclass__": classmethod(_raise)})  # type: ignore[arg-type]

    VynkorClient = _unavailable("VynkorClient")  # type: ignore[assignment,misc]
    VynkorError = _unavailable("VynkorError")  # type: ignore[assignment,misc]
    Plugin = _unavailable("Plugin")  # type: ignore[assignment,misc]
    ConcurrentHandler = _unavailable("ConcurrentHandler")  # type: ignore[assignment,misc]
    ConfirmationGate = _unavailable("ConfirmationGate")  # type: ignore[assignment,misc]
    PendingAction = _unavailable("PendingAction")  # type: ignore[assignment,misc]

    def _unavailable_fn(*_args: object, _err: BaseException = _captured_err, **_kwargs: object):  # type: ignore[no-untyped-def]
        raise ImportError(f"vynkor unavailable: {_err}") from _err

    response_envelope = _unavailable_fn  # type: ignore[assignment]
    run_concurrent_loop = _unavailable_fn  # type: ignore[assignment]
    serve_concurrent = _unavailable_fn  # type: ignore[assignment]
    send_confirmation = _unavailable_fn  # type: ignore[assignment]
    send_confirmation_request = _unavailable_fn  # type: ignore[assignment]

from .framing import (
    FLAG_COMPRESSED,
    FLAG_FRAGMENTED,
    FLAG_MAC_PRESENT,
    FLAG_RAW_BINARY,
    async_read_frame,
    compute_tag,
    derive_session_key,
    pack_frame,
    read_frame,
    read_frame_from_bytes,
    verify_tag,
)

# Re-export framing as ``vynkor.framing`` sub-module (mirrors Rust ``vynkor_sdk::framing``)
from . import framing  # noqa: F401

# Re-export frame_mac primitives (mirrors Rust ``vynkor_sdk::frame_mac``)
from .framing import compute_tag as _compute_tag  # noqa: F401
from .framing import derive_session_key as _derive_session_key  # noqa: F401
from .framing import verify_tag as _verify_tag  # noqa: F401

# Alias for ``vynkor.frame_mac`` compatibility
import types as _types
import sys as _sys

frame_mac = _types.ModuleType("vynkor.frame_mac")
frame_mac.compute_tag = compute_tag  # type: ignore[attr-defined]
frame_mac.derive_session_key = derive_session_key  # type: ignore[attr-defined]
frame_mac.verify_tag = verify_tag  # type: ignore[attr-defined]
_sys.modules[__name__ + ".frame_mac"] = frame_mac

__all__ = [
    "VynkorClient",
    "VynkorError",
    "Plugin",
    # concurrent (hot-path plugins)
    "ConcurrentHandler",
    "response_envelope",
    "run_concurrent_loop",
    "serve_concurrent",
    # confirmation gate (high-risk actions)
    "ConfirmationGate",
    "PendingAction",
    "send_confirmation",
    "send_confirmation_request",
    # framing
    "framing",
    "frame_mac",
    "pack_frame",
    "read_frame",
    "read_frame_from_bytes",
    "async_read_frame",
    "compute_tag",
    "derive_session_key",
    "verify_tag",
    "FLAG_COMPRESSED",
    "FLAG_FRAGMENTED",
    "FLAG_MAC_PRESENT",
    "FLAG_RAW_BINARY",
]
