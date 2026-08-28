"""Async client for the Vynkor kernel IPC socket.

Speaks the full Vynkor wire protocol over two transports:

- **UDS** (default) — Unix domain socket via :meth:`VynkorClient.connect` /
  :meth:`VynkorClient.connect_with_secret`.
- **WebSocket** — the kernel's WS gateway (``ws://host:port/ws``) via
  :meth:`VynkorClient.connect_ws`, for remote devices (D-05). Registration,
  frame-MAC enable and reconnect mirror the UDS client exactly; the only
  differences are dictated by the gateway (R5-03): outbound frames are never
  zstd-compressed and never fragmented, while ``FLAG_RAW_BINARY`` passes
  unchanged.

Mirrors ``vynkor-sdk/src/client.rs`` 1:1.
"""

import asyncio
import itertools
import os
import time
from typing import Callable, Optional

from .errors import (
    VynkorInternal,
    VynkorPayloadTooLarge,
    VynkorProtoError,
    VynkorTimeout,
)
from .framing import (
    FLAG_FRAGMENTED,
    FLAG_MAC_PRESENT,
    FLAG_RAW_BINARY,
    FRAG_HEADER_SIZE,
    MAX_PAYLOAD,
    async_read_frame,
    derive_session_key,
    pack_frag_header,
    pack_frame,
    parse_frag_header,
    read_frame_from_bytes,
)
from .vynkor_protocol_pb2 import (
    ActionRequest,
    ActionRequestChunk,
    ActionResponse,
    ActionResponseChunk,
    AudioStreamChunk,
    Envelope,
    EventAck,
    EventPublish,
    EventPublishAck,
    KernelCommand,
    KernelCommandAck,
    Ping,
    PluginManifest,
    PluginRegister,
    PluginRegisterAck,
    Pong,
    SessionClose,
    Subscribe,
    Unsubscribe,
)

DEFAULT_PUBLISH_EVENT_TIMEOUT = 30.0
DEFAULT_ACTION_TIMEOUT = 30.0

# Module-level counter, mirroring the rust SDK's free-function
# next_request_id("act") (not per-connection state).
_action_seq = itertools.count()


def _next_action_id() -> str:
    return f"act-{int(time.time() * 1000)}-{next(_action_seq)}"


# Mirror of the kernel's inbound reassembly bounds (see src/ipc/connection.rs).
MAX_REASSEMBLY_STREAMS = 64
REASSEMBLY_TIMEOUT = 30.0


class _ReassemblyBuf:
    __slots__ = ("fragments", "total", "flags", "first_seen", "buffered_bytes")

    def __init__(self, total: int, flags: int):
        self.fragments: dict[int, bytes] = {}
        self.total = total
        self.flags = flags
        self.first_seen = time.monotonic()
        self.buffered_bytes = 0

    def is_complete(self) -> bool:
        return len(self.fragments) == self.total

    def reassemble(self) -> bytes:
        return b"".join(self.fragments[seq] for seq in range(self.total))


class VynkorClient:
    """Async connection to the Vynkor kernel over a Unix domain socket or a
    WebSocket.

    Create with :meth:`VynkorClient.connect` /
    :meth:`VynkorClient.connect_with_secret` (UDS, no auth / secured) or
    :meth:`VynkorClient.connect_ws` (the kernel's WS gateway, e.g. for
    remote devices), then call :meth:`register` /
    :meth:`register_with_token` before any other traffic.
    """

    def __init__(self, socket_path: str = "", secret: Optional[bytes] = None):
        self.socket_path = socket_path
        self._secret = secret
        self.session_key: Optional[bytes] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._ws = None  # websockets.WebSocketClientProtocol when on WS
        self._transport: str = "uds"  # "uds" or "ws"
        self.plugin_id: Optional[str] = None
        self._reassembly: dict[int, _ReassemblyBuf] = {}
        self._next_stream_id = 1

    # ── Construction ────────────────────────────────────────────────

    async def connect(self, socket_path: Optional[str] = None) -> Optional["VynkorClient"]:
        """Open the connection. Two forms:

        - instance: ``c = VynkorClient(path); await c.connect()`` (returns None)
        - class:    ``c = await VynkorClient.connect(path)`` (returns a connected client)

        Mirrors Rust's ``VynkorClient::connect(socket_path)`` constructor while
        keeping the historical instance-level pattern working.
        """
        if isinstance(self, VynkorClient):
            if socket_path is not None:
                self.socket_path = socket_path
            self._reader, self._writer = await asyncio.open_unix_connection(self.socket_path)
            self._transport = "uds"
            return None
        # Class form: ``self`` is actually the socket path string.
        return await VynkorClient.connect_with_secret(self, None)  # type: ignore[arg-type]

    @classmethod
    async def connect_with_secret(
        cls, socket_path: str, secret: Optional[bytes]
    ) -> "VynkorClient":
        client = cls(socket_path, secret=secret)
        client._reader, client._writer = await asyncio.open_unix_connection(socket_path)
        client._transport = "uds"
        return client

    @classmethod
    async def connect_from_env(cls) -> "VynkorClient":
        """Connect using ``VYN_SOCKET_PATH`` (falling back to the per-user
        default) and ``VYN_JWT_SECRET`` (optional; enables frame MACs)."""
        from .plugin import _default_socket_path

        socket_path = os.environ.get("VYN_SOCKET_PATH") or _default_socket_path()
        secret = os.environ.get("VYN_JWT_SECRET")
        if secret:
            return await cls.connect_with_secret(socket_path, secret.encode())
        return await cls.connect_with_secret(socket_path, None)

    @classmethod
    def from_stream(cls, reader, writer, secret: Optional[bytes] = None) -> "VynkorClient":
        """Wrap an existing ``(reader, writer)`` asyncio stream pair. Useful for
        tests (``socket.socketpair()``) and custom transports."""
        client = cls("", secret=secret)
        client._reader = reader
        client._writer = writer
        client._transport = "uds"
        return client

    @classmethod
    async def connect_ws(
        cls, url: str, jwt_token: str = "", secret: Optional[bytes] = None
    ) -> "VynkorClient":
        """Connect to the kernel's WebSocket gateway (D-05). ``url`` is a
        ``ws://`` or ``wss://`` endpoint, normally ``ws://<host>:<port>/ws``.

        The client always offers the ``vynkor`` subprotocol (the gateway's
        handshake marker). ``jwt_token``, when non-empty, is appended to it in
        the ``Sec-WebSocket-Protocol: vynkor, <jwt>`` header — the gateway's
        only channel for the token; never put tokens in the URL, they leak
        into access logs. Pass the same token to :meth:`register_full`; a
        non-empty token is required on secured kernels. ``secret`` enables
        frame MACs after registration, exactly like
        :meth:`connect_with_secret` on UDS.

        On a dropped connection the client is left in its last state;
        reconnect by calling ``connect_ws`` again and re-registering — the
        session key is re-derived from the fresh nonce in the new ack
        (mirrors the UDS client).
        """
        try:
            import websockets
            import websockets.exceptions
        except ImportError as e:
            raise VynkorInternal(
                "websockets package required for WebSocket transport: pip install vynkor-sdk[websockets] or websockets>=12"
            ) from e

        protocol = "vynkor" if not jwt_token else f"vynkor, {jwt_token}"

        # websockets 12+ uses additional_headers, older uses extra_headers
        connect_kwargs: dict = {}
        # Try modern API first
        try:
            ws = await websockets.connect(url, additional_headers={"Sec-WebSocket-Protocol": protocol})  # type: ignore[call-arg]
        except TypeError:
            try:
                ws = await websockets.connect(url, extra_headers={"Sec-WebSocket-Protocol": protocol})  # type: ignore[call-arg]
            except TypeError:
                # Fallback: websockets 13+ may use different param
                ws = await websockets.connect(url)  # type: ignore[call-arg]

        client = cls(url, secret=secret)
        client._ws = ws
        client._transport = "ws"
        # store protocol for introspection
        client._ws_protocol = protocol  # type: ignore[attr-defined]
        return client

    async def close(self) -> None:
        if self._transport == "ws" and self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            self._writer = None
            self._reader = None

    def is_secured(self) -> bool:
        """True once a secured registration has derived the per-connection
        MAC key."""
        return self.session_key is not None

    def _is_ws(self) -> bool:
        return self._transport == "ws"

    def _apply_session_nonce(self, plugin_id: str, nonce: bytes) -> None:
        """Derive and store session_key from a registration nonce."""
        if self._secret and nonce:
            self.session_key = derive_session_key(self._secret, nonce, plugin_id)

    # ── Registration ────────────────────────────────────────────────

    async def register(self, plugin_id: str, manifest: Optional[PluginManifest] = None) -> PluginRegisterAck:
        return await self.register_with_token(plugin_id, manifest, "")

    async def register_with_token(
        self, plugin_id: str, manifest: Optional[PluginManifest], jwt_token: str = ""
    ) -> PluginRegisterAck:
        return await self.register_full(plugin_id, "1.0.0", manifest, jwt_token)

    async def register_full(
        self,
        plugin_id: str,
        version: str,
        manifest: Optional[PluginManifest],
        jwt_token: str = "",
    ) -> PluginRegisterAck:
        self.plugin_id = plugin_id
        reg = PluginRegister(plugin_id=plugin_id, version=version, jwt_token=jwt_token)
        if manifest is not None:
            reg.manifest.CopyFrom(manifest)
        env = Envelope()
        env.plugin_register.CopyFrom(reg)
        await self.send("kernel", env)
        response = await self.recv()
        if response.HasField("plugin_register_ack"):
            ack = response.plugin_register_ack
            nonce = getattr(ack, "session_nonce", b"")
            if nonce:
                self._apply_session_nonce(plugin_id, nonce)
            return ack
        if response.HasField("error"):
            raise VynkorInternal(
                f"registration rejected: {response.error.message} ({response.error.details})"
            )
        raise VynkorInternal("expected PluginRegisterAck")

    # ── Sending ─────────────────────────────────────────────────────

    async def send(self, target: str, envelope: Envelope) -> None:
        payload = envelope.SerializeToString()
        await self.send_raw(target, payload)

    async def send_raw(self, target: str, payload: bytes) -> None:
        await self.send_raw_with_flags(target, 0, payload)

    async def send_raw_with_flags(self, target: str, extra_flags: int, payload: bytes) -> None:
        """Send a raw payload with explicit extra flags ORed into the frame
        header (e.g. FLAG_RAW_BINARY). MAC and compression are applied
        automatically by the framing layer.

        Over WebSocket, frames are never compressed (the gateway rejects
        FLAG_COMPRESSED inbound) — see :meth:`connect_ws`.
        """
        if self._is_ws():
            if len(payload) > MAX_PAYLOAD:
                raise VynkorPayloadTooLarge(len(payload))
            # Never compress over WS; MAC still applies
            frame = pack_frame(
                target, payload, flags=extra_flags, session_key=self.session_key, compress=False
            )
            try:
                await self._ws.send(frame)  # type: ignore[union-attr]
            except Exception as e:
                raise VynkorInternal(f"websocket send failed: {e}") from e
        else:
            frame = pack_frame(target, payload, flags=extra_flags, session_key=self.session_key)
            assert self._writer is not None, "not connected"
            self._writer.write(frame)
            await self._writer.drain()

    async def send_fragmented(self, target: str, payload: bytes, chunk_size: int) -> None:
        """Split ``payload`` into ``FLAG_FRAGMENTED`` frames of at most ``chunk_size``
        data bytes each and send them on a fresh stream id. The kernel
        reassembles them into a single logical frame for ``target``.

        Bounds mirror the kernel: total payload <= 1 MiB, <= 65535 fragments.
        UDS only — the WS gateway rejects fragmented inbound frames (R5-03),
        so this raises on a WebSocket transport.
        """
        if self._is_ws():
            raise VynkorInternal("fragmented frames are not supported over WebSocket (R5-03)")
        if len(payload) > MAX_PAYLOAD:
            raise VynkorPayloadTooLarge(len(payload))
        if chunk_size <= 0 or chunk_size + FRAG_HEADER_SIZE > MAX_PAYLOAD:
            raise VynkorInternal(f"invalid fragment chunk_size: {chunk_size}")
        total = max(1, -(-len(payload) // chunk_size))  # ceil div
        if total > 0xFFFF:
            raise VynkorInternal(f"payload needs {total} fragments; max is 65535")

        stream_id = self._next_stream_id
        self._next_stream_id = (self._next_stream_id + 1) & 0xFFFFFFFF or 1
        fragment_id = stream_id & 0xFFFF

        for seq in range(total):
            chunk = payload[seq * chunk_size : (seq + 1) * chunk_size]
            frag_payload = pack_frag_header(fragment_id, seq, total, stream_id) + chunk
            await self.send_raw_with_flags(target, FLAG_FRAGMENTED, frag_payload)

    # ── Receiving ───────────────────────────────────────────────────

    async def recv_frame(self):
        """Receive the next complete frame as ``(flags, payload)``, transparently
        reassembling ``FLAG_FRAGMENTED`` frames. Raw-binary frames are returned
        as-is (check ``flags & FLAG_RAW_BINARY``). Mirrors the Rust SDK's
        ``VynkorClient::recv_frame``."""
        while True:
            self._prune_reassembly()
            if self._is_ws():
                flags, payload = await self._ws_recv_frame()
            else:
                assert self._reader is not None, "not connected"
                flags, payload = await async_read_frame(self._reader, session_key=self.session_key)
            if flags & FLAG_FRAGMENTED:
                complete = self._absorb_fragment(flags, payload)
                if complete is None:
                    continue
                return complete
            return flags, payload

    async def _ws_recv_frame(self):
        """Read one WS binary message and parse it as a frame."""
        assert self._ws is not None, "not connected (ws)"
        while True:
            try:
                data = await self._ws.recv()  # type: ignore[union-attr]
            except Exception as e:
                # Map websocket close/error to Io-like error so callers see
                # disconnect / EOF, matching UDS behavior
                raise VynkorInternal(f"websocket connection closed: {e}") from e
            # websockets may deliver str for text frames — ignore them (kernel
            # gateway never sends them as traffic, per Rust docs)
            if isinstance(data, str):
                continue
            if not isinstance(data, (bytes, bytearray)):
                continue
            return read_frame_from_bytes(bytes(data), session_key=self.session_key)

    async def recv(self) -> Envelope:
        flags, payload = await self.recv_frame()
        if flags & FLAG_RAW_BINARY:
            raise VynkorInternal("received raw-binary frame; use recv_frame() for audio")
        env = Envelope()
        try:
            env.ParseFromString(payload)
        except Exception as e:
            raise VynkorProtoError(str(e)) from e
        return env

    async def recv_timeout(self, timeout: float) -> Envelope:
        """Receive and decode the next Envelope, bounded by ``timeout`` seconds.
        Raises VynkorTimeout if nothing arrives in time."""
        try:
            return await asyncio.wait_for(self.recv(), timeout=timeout)
        except asyncio.TimeoutError:
            raise VynkorTimeout() from None

    def _prune_reassembly(self) -> None:
        """Stale sets can't pin memory forever."""
        now = time.monotonic()
        stale = [
            sid
            for sid, buf in self._reassembly.items()
            if now - buf.first_seen >= REASSEMBLY_TIMEOUT
        ]
        for sid in stale:
            del self._reassembly[sid]

    def _absorb_fragment(self, flags: int, payload: bytes):
        """Buffer one fragment; returns ``(flags, payload)`` when the set is
        complete, else ``None``. Mirrors the Rust SDK's ``absorb_fragment``."""
        hdr = parse_frag_header(payload)
        if hdr is None:
            raise VynkorInternal("fragment header too short")
        _fragment_id, seq, total, stream_id = hdr
        if total == 0 or seq >= total:
            raise VynkorInternal(f"invalid fragment header: seq {seq} / total {total}")

        buf = self._reassembly.get(stream_id)
        if buf is not None:
            if buf.total != total:
                del self._reassembly[stream_id]
                raise VynkorInternal("fragment total mismatch within stream")
        elif len(self._reassembly) >= MAX_REASSEMBLY_STREAMS:
            raise VynkorInternal("too many concurrent fragment streams")
        else:
            buf = _ReassemblyBuf(total, flags & ~(FLAG_FRAGMENTED | FLAG_MAC_PRESENT))
            self._reassembly[stream_id] = buf

        chunk = payload[FRAG_HEADER_SIZE:]
        replaced_len = len(buf.fragments.get(seq, b""))
        new_total = buf.buffered_bytes - replaced_len + len(chunk)
        if new_total > MAX_PAYLOAD:
            del self._reassembly[stream_id]
            raise VynkorPayloadTooLarge(MAX_PAYLOAD + 1)
        buf.buffered_bytes = new_total
        buf.fragments[seq] = chunk

        if buf.is_complete():
            del self._reassembly[stream_id]
            return buf.flags, buf.reassemble()
        return None

    # ── Kernel requests ─────────────────────────────────────────────

    async def subscribe(self, event_types: list) -> None:
        sub = Subscribe(event_types=event_types)
        env = Envelope()
        env.subscribe.CopyFrom(sub)
        await self.send("kernel", env)

    async def unsubscribe(self, event_types: list) -> None:
        unsub = Unsubscribe(event_types=event_types)
        env = Envelope()
        env.unsubscribe.CopyFrom(unsub)
        await self.send("kernel", env)

    async def ack_event(self, event_id: str) -> None:
        """Confirm an Event was received and handled — kernel stops retrying
        it. An un-acked event is redelivered up to max_retries then dropped
        (T-06)."""
        env = Envelope()
        env.event_ack.CopyFrom(EventAck(event_id=event_id))
        await self.send("kernel", env)

    async def publish_event(
        self, event_type: str, payload_json: bytes, timeout_ms: int = 0
    ) -> EventPublishAck:
        """Publish an event to the kernel event bus. Requires
        ``PERMISSION_EVENT_PUBLISH``. ``timeout_ms == 0`` uses the kernel default of
        30s. Raises ``VynkorInternal`` on a kernel Error envelope, ``VynkorTimeout`` on
        deadline expiry. The returned ``EventPublishAck`` is returned as-is
        regardless of its status field — callers inspect ``ack.status``
        themselves, mirroring the Rust SDK."""
        env = Envelope()
        env.event_publish.CopyFrom(EventPublish(event_type=event_type, payload_json=payload_json))
        await self.send("kernel", env)

        deadline = time.monotonic() + (
            timeout_ms / 1000 if timeout_ms else DEFAULT_PUBLISH_EVENT_TIMEOUT
        )
        resp = await self._await_matching(
            deadline,
            lambda r: r.HasField("event_publish_ack") or r.HasField("error"),
        )
        if resp.HasField("error"):
            raise VynkorInternal(
                f"kernel error: {resp.error.message} ({resp.error.details})"
            )
        return resp.event_publish_ack

    async def send_action(
        self, action: str, params_json: bytes, timeout_ms: int = 0
    ) -> ActionResponse:
        """Ask the kernel to perform an action and await its ``ActionResponse``.
        ``timeout_ms == 0`` uses the kernel default of 30s. Raises
        ``VynkorInternal`` on a kernel Error envelope or an ActionStreamAbort for
        this ``action_id``, ``VynkorTimeout`` on deadline expiry."""
        action_id = _next_action_id()
        env = Envelope()
        env.action_request.CopyFrom(ActionRequest(
            action_id=action_id,
            action=action,
            params_json=params_json,
            timeout_ms=timeout_ms,
            streaming=False,
        ))
        await self.send("kernel", env)

        deadline = time.monotonic() + (
            timeout_ms / 1000 if timeout_ms else DEFAULT_ACTION_TIMEOUT
        )
        resp = await self._await_matching(
            deadline,
            lambda r: (r.HasField("action_response") and r.action_response.action_id == action_id)
            or (r.HasField("action_stream_abort") and r.action_stream_abort.action_id == action_id)
            or r.HasField("error"),
        )
        if resp.HasField("error"):
            raise VynkorInternal(
                f"kernel error: {resp.error.message} ({resp.error.details})"
            )
        if resp.HasField("action_stream_abort"):
            raise VynkorInternal(f"stream aborted: {resp.action_stream_abort.reason}")
        return resp.action_response

    async def send_action_streaming(self, action: str, timeout_ms: int = 0) -> str:
        """Fire an ``ActionRequest`` with ``streaming=True`` and return its ``action_id``
        immediately — no wait. Caller drives ``send_request_chunk``/``recv``/
        ``close_session`` afterward."""
        action_id = _next_action_id()
        env = Envelope()
        env.action_request.CopyFrom(ActionRequest(
            action_id=action_id,
            action=action,
            timeout_ms=timeout_ms,
            streaming=True,
        ))
        await self.send("kernel", env)
        return action_id

    async def send_request_chunk(
        self, action_id: str, seq: int, chunk: bytes, is_final: bool
    ) -> None:
        """Fire-and-forget: one chunk of a streaming action's request body."""
        env = Envelope()
        env.action_request_chunk.CopyFrom(ActionRequestChunk(
            action_id=action_id, seq=seq, chunk=chunk, final=is_final
        ))
        await self.send("kernel", env)

    async def send_response_chunk(self, action_id: str, seq: int, chunk: bytes) -> None:
        """Fire-and-forget: one chunk of a streaming action's response body."""
        env = Envelope()
        env.action_response_chunk.CopyFrom(ActionResponseChunk(
            action_id=action_id, seq=seq, chunk=chunk
        ))
        await self.send("kernel", env)

    async def close_session(self, action_id: str, reason: str) -> None:
        """Fire-and-forget: tell the peer this action's session is done."""
        env = Envelope()
        env.session_close.CopyFrom(SessionClose(action_id=action_id, reason=reason))
        await self.send("kernel", env)

    async def send_command(
        self, command_id: str, command: str, params_json: bytes
    ) -> KernelCommandAck:
        """Send a ``KernelCommand`` and await its ack."""
        env = Envelope()
        env.kernel_command.CopyFrom(KernelCommand(
            command_id=command_id, command=command, params_json=params_json
        ))
        await self.send("kernel", env)
        response = await self.recv()
        if response.HasField("kernel_command_ack"):
            return response.kernel_command_ack
        raise VynkorInternal("expected KernelCommandAck")

    async def ping(self) -> float:
        """Round-trip a ``Ping`` to the kernel; returns measured latency in
        seconds."""
        ts = int(time.time() * 1000)
        ping_msg = Ping(timestamp=ts)
        env = Envelope()
        env.ping.CopyFrom(ping_msg)
        t0 = time.monotonic()
        await self.send("kernel", env)
        response = await self.recv()
        if not response.HasField("pong"):
            raise VynkorInternal("expected Pong")
        return time.monotonic() - t0

    # ── Audio ───────────────────────────────────────────────────────

    async def send_audio_chunk(self, target: str, chunk: AudioStreamChunk) -> None:
        """Send an ``AudioStreamChunk`` (stream negotiation / Opus-over-envelope)
        to a peer plugin. Requires ``PERMISSION_AUDIO_STREAM``."""
        env = Envelope()
        env.audio_stream_chunk.CopyFrom(chunk)
        await self.send(target, env)

    async def send_raw_audio(self, target: str, data: bytes) -> None:
        """Send raw audio bytes (PCM_S16LE or Opus) with ``FLAG_RAW_BINARY``; the
        router skips Protobuf decode. Raw-binary payloads are never
        compressed. Works over both UDS and WebSocket — ``FLAG_RAW_BINARY``
        passes unchanged over WS."""
        await self.send_raw_with_flags(target, FLAG_RAW_BINARY, data)

    async def _await_matching(
        self, deadline: float, predicate: Callable[[Envelope], bool]
    ) -> Envelope:
        """Loop ``recv``/``predicate`` until ``predicate(env)`` is true or deadline
        passes. Shared by ``publish_event`` and ``send_action`` — each supplies its
        own match/discard predicate."""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VynkorTimeout()
            resp = await self.recv_timeout(remaining)
            if predicate(resp):
                return resp
            # unrelated traffic while waiting — discard, keep waiting
