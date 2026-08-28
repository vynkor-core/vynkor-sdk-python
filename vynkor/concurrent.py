"""Concurrent message loop for hot-path plugins.

Mirrors ``vynkor-sdk/src/concurrent.rs`` 1:1.

The default :class:`vynkor.plugin.Plugin` serve loop is fully sequential:
``recv() → on_message() → reply → next recv()``. That is correct for
low-volume, network-bound plugins (``ai``, ``tts``, ``stt``) but wrong
for storage-class plugins that get called far more often — a slow request
would block every other caller.

This module provides the hot-path pattern as a first-class SDK facility:

- one task owns the :class:`vynkor.client.VynkorClient` exclusively and
  ``asyncio.wait``-selects between inbound frames and a queue of completed
  response envelopes;
- each inbound ``ActionRequest`` is dispatched to an ``asyncio.create_task``
  handler, so requests run concurrently and replies may come back out of
  order (the kernel matches on ``action_id``);
- the client is never wrapped in a lock, so a handler replying can never
  deadlock against the loop parked inside ``recv()``;
- a handler that raises is caught and becomes an ``ACTION_ERROR`` response
  instead of a silently dropped reply.

Usage — implement :class:`ConcurrentHandler` and drive it from ``main``::

    import asyncio
    from vynkor.concurrent import ConcurrentHandler, serve_concurrent
    from vynkor.client import VynkorClient
    from vynkor.vynkor_protocol_pb2 import PluginManifest

    class MyHandler(ConcurrentHandler):
        def id(self) -> str:
            return "database"

        def manifest(self):
            return PluginManifest(actions=["get", "put"])

        async def on_action(self, req):
            # ... handle req, return [envelope] or [response_envelope(...)]
            ...

    async def main():
        client = await VynkorClient.connect_from_env()
        await serve_concurrent(client, "", MyHandler())  # jwt_token second arg
"""

from __future__ import annotations

import abc
import asyncio
import time
from typing import List, Optional

from .vynkor_protocol_pb2 import (
    ActionRequest,
    ActionResponse,
    ActionStatus,
    Envelope,
    Event,
    PluginManifest,
    Pong,
)

RESPONSE_CHANNEL_CAPACITY = 256


def response_envelope(action_id: str, result) -> Envelope:
    """Build the response envelope for a completed (or failed) action.

    ``result`` is ``Ok(bytes)`` as ``bytes`` → ``ACTION_OK`` or
    ``Err(str)`` as ``str`` → ``ACTION_ERROR``.

    Mirrors ``vynkor_sdk::concurrent::response_envelope``.
    """
    if isinstance(result, bytes):
        resp = ActionResponse(
            action_id=action_id, status=ActionStatus.ACTION_OK, data_json=result
        )
    elif isinstance(result, str):
        resp = ActionResponse(
            action_id=action_id, status=ActionStatus.ACTION_ERROR, error=result
        )
    else:
        raise TypeError("response_envelope expects bytes (ok) or str (error)")
    env = Envelope()
    env.action_response.CopyFrom(resp)
    return env


class ConcurrentHandler(abc.ABC):
    """Handler for a plugin driven by the concurrent message loop.

    Unlike :class:`vynkor.plugin.Plugin`, handlers are invoked through
    ``self`` from multiple concurrently running tasks, so implementations
    must be safe to share (use ``asyncio.Lock`` / thread-safe structures
    for interior state).

    Registration metadata (``id``/``version``/``manifest``) lives on the
    trait so :func:`serve_concurrent` can perform registration itself.
    """

    @abc.abstractmethod
    def id(self) -> str:
        """Unique plugin id, e.g. ``\"database\"``."""
        ...

    def version(self) -> str:
        return "1.0.0"

    @abc.abstractmethod
    def manifest(self) -> PluginManifest:
        """Declared capabilities: permissions, actions, event subscriptions."""
        ...

    async def on_init(self, client) -> None:
        """Called once after successful registration, before the receive loop."""
        pass

    def accept(self, req: ActionRequest) -> None:
        """Pre-spawn gate, run in the loop task before a handler task is
        spawned for ``req``. Raise ``ValueError(str)`` / ``Exception(str)``
        to reject the request immediately with an ``ACTION_ERROR`` (no task
        spawned). Keep this cheap — it runs on the loop's critical path.

        The default accepts everything.
        """
        pass

    @abc.abstractmethod
    async def on_action(self, req: ActionRequest) -> List[Envelope]:
        """Handle one inbound ``ActionRequest`` in a spawned task.

        Return the reply envelope(s) to send back to the kernel — usually
        exactly one ``ActionResponse`` (use :func:`response_envelope`), but
        a handler may return additional best-effort envelopes.

        A panic (unhandled exception) inside this method is caught and
        converted into an ``ACTION_ERROR`` reply for the request's
        ``action_id``, so no reply is ever dropped on the floor.
        """
        ...

    async def on_event(self, event: Event) -> Optional[Envelope]:
        """Called for each inbound ``Event`` the kernel delivers.

        Returning normally makes the loop send an ``EventAck`` so the
        kernel stops retrying; raise to skip the ack. Return a reply
        envelope to send additional traffic.
        """
        return None

    async def on_message(self, env: Envelope) -> Optional[Envelope]:
        """Called for any inbound envelope the loop does not handle itself
        (Ping, ``PluginShutdown``, ``ActionRequest`` and ``Event`` are
        consumed by the loop). Return a reply envelope to send, or ``None``.
        """
        return None

    async def on_shutdown(self) -> None:
        """Called once when the loop ends (kernel shutdown request,
        disconnect, or handler error)."""
        pass


async def serve_concurrent(client, jwt_token: str, handler: ConcurrentHandler) -> None:
    """Register ``handler`` with the kernel, run ``on_init``, then drive
    the concurrent message loop until shutdown.

    Wraps :func:`run_concurrent_loop` with registration; ``jwt_token`` is
    presented at registration (empty string on unsecured kernels). A
    rejected registration raises :class:`vynkor.errors.VynkorPermissionDenied`.
    """
    from .errors import VynkorPermissionDenied

    ack = await client.register_full(
        handler.id(), handler.version(), handler.manifest(), jwt_token
    )
    if not ack.accepted:
        raise VynkorPermissionDenied(f"registration rejected: {ack.reject_reason}")
    try:
        await handler.on_init(client)
    except BaseException:
        try:
            await handler.on_shutdown()
        except BaseException:
            pass
        raise
    result = await run_concurrent_loop(client, handler)
    try:
        await handler.on_shutdown()
    except BaseException:
        pass
    return result


async def run_concurrent_loop(client, handler: ConcurrentHandler) -> None:
    """Drive the concurrent message loop to completion.

    ``client`` is owned exclusively by this function — never shared behind
    a lock. Each loop iteration ``asyncio.wait`` s between two futures:

    - ``client.recv()``: the next inbound frame from the kernel.
    - ``queue.get()``: the next completed response envelope pushed by a
      spawned handler task.

    Because the client is never wrapped in a lock, a handler finishing
    while this function is parked inside ``client.recv()`` only does
    ``queue.put(...)`` — a short-lived, always-available operation
    unrelated to the client's state. No task ever waits on a resource
    held by a task that is itself waiting on it.

    Use this directly in tests against a pre-registered client
    (e.g. built with ``VynkorClient.from_stream`` over a socketpair).
    """
    queue: asyncio.Queue[Envelope] = asyncio.Queue(maxsize=RESPONSE_CHANNEL_CAPACITY)

    def _spawn(req: ActionRequest) -> None:
        async def _run() -> None:
            try:
                envelopes = await handler.on_action(req)
            except BaseException as e:
                envelopes = [
                    response_envelope(req.action_id, f"handler panicked: {e}")
                ]
            for env in envelopes:
                try:
                    queue.put_nowait(env)
                except asyncio.QueueFull:
                    # Channel full — drop is correct; receiver only goes
                    # away when the main loop exits anyway.
                    await queue.put(env)

        asyncio.create_task(_run())

    while True:
        recv_task = asyncio.create_task(client.recv())
        queue_task = asyncio.create_task(queue.get())
        done, pending = await asyncio.wait(
            [recv_task, queue_task], return_when=asyncio.FIRST_COMPLETED
        )
        # Cancel the loser
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        if recv_task in done:
            try:
                envelope = recv_task.result()
            except BaseException:
                # disconnect / EOF — drain queue then exit
                # flush any queued responses before leaving
                while not queue.empty():
                    try:
                        env = queue.get_nowait()
                        try:
                            await client.send("kernel", env)
                        except BaseException:
                            pass
                    except asyncio.QueueEmpty:
                        break
                break

            kind = envelope.WhichOneof("payload")
            if kind == "ping":
                pong = Envelope(
                    pong=Pong(
                        original_timestamp=envelope.ping.timestamp,
                        server_timestamp=int(time.time() * 1000),
                    )
                )
                try:
                    await client.send("kernel", pong)
                except BaseException:
                    pass
            elif kind == "plugin_shutdown":
                # flush queued responses before exit
                while not queue.empty():
                    try:
                        env = queue.get_nowait()
                        try:
                            await client.send("kernel", env)
                        except BaseException:
                            pass
                    except asyncio.QueueEmpty:
                        break
                break
            elif kind == "action_request":
                req = envelope.action_request
                try:
                    handler.accept(req)
                except Exception as e:
                    env = response_envelope(req.action_id, str(e))
                    try:
                        await client.send("kernel", env)
                    except BaseException:
                        pass
                    continue
                _spawn(req)
            elif kind == "event":
                event = envelope.event
                try:
                    reply = await handler.on_event(event)
                except BaseException:
                    continue  # no ack — kernel will retry
                try:
                    await client.ack_event(event.event_id)
                except BaseException:
                    pass
                if reply is not None:
                    try:
                        await client.send("kernel", reply)
                    except BaseException:
                        pass
            elif kind is None:
                continue
            else:
                try:
                    reply = await handler.on_message(envelope)
                except BaseException:
                    continue
                if reply is not None:
                    try:
                        await client.send("kernel", reply)
                    except BaseException:
                        pass

            # Also drain any completed handler responses that arrived
            # while we were handling this envelope (without blocking)
            while not queue.empty():
                try:
                    env = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                try:
                    await client.send("kernel", env)
                except BaseException:
                    pass
        else:
            # queue produced a response
            try:
                env = queue_task.result()
            except asyncio.CancelledError:
                continue
            try:
                await client.send("kernel", env)
            except BaseException:
                pass
            # recv_task was cancelled above; loop will recreate it
