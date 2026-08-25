"""The Plugin base class: implement it, call ``Plugin.run()``, and the SDK
handles connection, registration, auth, the receive loop, Ping/Pong,
event acknowledgement, and graceful shutdown.

Mirrors ``vynkor-sdk/src/plugin.rs`` 1:1.
"""

import asyncio
import os
import time
from typing import Optional

from .client import VynkorClient
from .errors import VynkorError, VeyronPermissionDenied
from .vynkor_protocol_pb2 import Envelope, Event, PluginManifest, Pong


def _default_socket_path() -> str:
    """Per-user socket location, mirroring the kernel's default_socket_path():
    XDG_RUNTIME_DIR → /run/user/<uid> → ~/.local/state/vyn/run (created 0700 if used).
    Never the world-writable shared /tmp (BUG-006)."""
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        return os.path.join(runtime_dir, "vyn.sock")
    run_user = f"/run/user/{os.getuid()}"
    if os.path.isdir(run_user):
        return os.path.join(run_user, "vyn.sock")
    # Last-resort private dir, created like vynkor-wire's default_private_dir
    # so it exists (and is not world-readable) by the time we return it.
    run_dir = os.path.join(os.path.expanduser("~"), ".local", "state", "vyn", "run")
    os.makedirs(run_dir, exist_ok=True)
    os.chmod(run_dir, 0o700)
    return os.path.join(run_dir, "vyn.sock")


class Plugin:
    """Base class for Vynkor plugins. Only ``id`` and ``on_message`` are mandatory;
    everything else has a sensible default. Mirrors the Rust ``Plugin`` trait.

    Lifecycle driven by ``run`` / ``run_with`` / ``run_ws`` / ``serve``:

    1. Connect to the kernel socket (``VYN_SOCKET_PATH`` or the per-user
       default; never the shared world-writable ``/tmp``).
    2. Register, presenting ``VYN_JWT_TOKEN`` if set. When
       ``VYN_JWT_SECRET`` is also set, all subsequent frames carry an
       HMAC-SHA256 tag.
    3. Call ``on_init``.
    4. Receive loop: Ping is answered automatically; ``PluginShutdown`` exits
       the loop; Events are passed to ``on_event`` and acknowledged when it
       returns successfully; everything else goes to ``on_message``.
    5. Call ``on_shutdown``.
    """

    def __init__(self) -> None:
        # set by serve(); available to handlers for convenience
        self._client: Optional[VynkorClient] = None

    def id(self) -> str:
        """Unique plugin id, e.g. "weather". Override, or set the legacy
        ``plugin_id`` class attribute."""
        val = getattr(self, "plugin_id", None)
        if val:
            return val
        raise NotImplementedError(
            "Plugin must define id() or the `plugin_id` class attribute"
        )

    def version(self) -> str:
        """Semver version reported at registration."""
        return "1.0.0"

    def manifest(self) -> PluginManifest:
        """Declared capabilities: permissions, actions, event subscriptions,
        IPC targets. Override, or set the legacy ``manifest`` class attribute."""
        val = getattr(type(self), "manifest", None)
        # legacy class-attribute style shadows the method; accept it as fallback
        if val is not None and not callable(val):
            return val
        return PluginManifest()

    async def on_init(self, client: VynkorClient) -> None:
        """Called once after successful registration, before the receive loop.
        Use the client to subscribe, negotiate audio streams, etc."""

    async def on_message(self, envelope: Envelope) -> Optional[Envelope]:
        """Called for every inbound envelope not handled by the SDK
        (Ping/Pong, PluginShutdown and Event have dedicated handling).
        Return an envelope to send it back to the kernel."""
        return None

    async def on_event(self, event: Event) -> Optional[Envelope]:
        """Called for each delivered Event. Returning normally makes the SDK
        send an EventAck so the kernel stops retrying; raising skips the ack
        (kernel retries). Return an envelope to send additional traffic."""
        return None

    async def on_shutdown(self) -> None:
        """Called once when the receive loop ends (kernel shutdown request,
        disconnect, or handler error)."""

    async def run(self) -> None:
        """Connect, register and serve until shutdown. Socket path comes from
        ``VYN_SOCKET_PATH``, falling back to the per-user default."""
        socket_path = os.environ.get("VYN_SOCKET_PATH") or _default_socket_path()
        await self.run_with(socket_path)

    async def run_with(self, socket_path: str) -> None:
        """Like ``run`` against an explicit socket path. JWT credentials are
        still read from ``VYN_JWT_TOKEN`` / ``VYN_JWT_SECRET``."""
        token = os.environ.get("VYN_JWT_TOKEN", "")
        secret = os.environ.get("VYN_JWT_SECRET")
        if secret:
            client = await VynkorClient.connect_with_secret(socket_path, secret.encode())
        else:
            client = await VynkorClient.connect_with_secret(socket_path, None)
        try:
            await self.serve(client, token)
        finally:
            await client.close()

    async def run_ws(self, url: str) -> None:
        """Connect to a kernel WebSocket gateway (D-05), register and serve
        until shutdown — the WS mirror of :meth:`run_with` for remote devices.
        JWT credentials come from the same env vars as the UDS path
        (``VYN_JWT_TOKEN`` / ``VYN_JWT_SECRET``); the token is presented both
        in the ``Sec-WebSocket-Protocol`` handshake header and in the
        registration envelope.

        Mirrors ``Plugin::run_ws`` in the Rust SDK.
        """
        token = os.environ.get("VYN_JWT_TOKEN", "")
        secret = os.environ.get("VYN_JWT_SECRET")
        secret_bytes = secret.encode() if secret else None
        client = await VynkorClient.connect_ws(url, token, secret_bytes)
        try:
            await self.serve(client, token)
        finally:
            await client.close()

    async def serve(self, client: VynkorClient, jwt_token: str) -> None:
        """Register on an existing client and run the receive loop. Building
        block for ``run``; also useful in tests."""
        self._client = client
        ack = await client.register_full(self.id(), self.version(), self.manifest(), jwt_token)
        if not ack.accepted:
            raise VeyronPermissionDenied(f"registration rejected: {ack.reject_reason}")

        try:
            await self.on_init(client)
        except BaseException:
            try:
                await self.on_shutdown()
            except BaseException:
                pass
            raise

        # A handler error ends the receive loop (see on_shutdown's contract):
        # it's the plugin signalling a fatal condition. Captured here so it
        # propagates out of serve() after on_shutdown() runs, instead of being
        # silently swallowed by the ``break`` (mirrors the Rust SDK's serve()).
        handler_err: Optional[BaseException] = None
        try:
            while True:
                try:
                    env = await client.recv()
                except Exception:
                    break  # disconnect / EOF
                if env.HasField("ping"):
                    # Answer the kernel watchdog directly — a supervised plugin
                    # whose last Pong goes stale is SIGKILLed (AUDIT H-02).
                    pong = Envelope(
                        pong=Pong(
                            original_timestamp=env.ping.timestamp,
                            server_timestamp=int(time.time() * 1000),
                        )
                    )
                    await client.send("kernel", pong)
                    continue
                if env.HasField("plugin_shutdown"):
                    break
                if env.HasField("event"):
                    event = env.event
                    # On handler error no ack is sent — the kernel will retry
                    # (mirrors the Rust SDK; T-06).
                    try:
                        reply = await self.on_event(event)
                    except Exception:
                        continue
                    await client.ack_event(event.event_id)
                    if reply is not None:
                        await client.send("kernel", reply)
                    continue
                try:
                    reply = await self.on_message(env)
                except BaseException as e:
                    handler_err = e
                    break
                if reply is not None:
                    await client.send("kernel", reply)
        finally:
            await self.on_shutdown()
        if handler_err is not None:
            raise handler_err
