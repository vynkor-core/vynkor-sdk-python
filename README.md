# vynkor-sdk-python

Python SDK for writing [Vynkor](https://github.com/vynkor-core/vynkor) plugins.

A Vynkor plugin is a separate OS process supervised by the Vynkor kernel. It
talks to the kernel using the Vynkor wire protocol — 44-byte framed messages
carrying Protobuf envelopes, with optional zstd compression, HMAC-SHA256 frame
authentication, and fragmentation — over a Unix domain socket (local plugins)
or the kernel's WebSocket gateway (remote devices, D-05).

## Install

```bash
pip install vynkor-sdk
```

## Quick start

```python
import asyncio
import json

from vynkor import Plugin
from vynkor.vynkor_protocol_pb2 import ActionResponse, ActionStatus, Envelope, PluginManifest


class EchoPlugin(Plugin):
    def id(self) -> str:
        return "echo-plugin"

    def manifest(self) -> PluginManifest:
        return PluginManifest(actions=["echo"])

    async def on_message(self, envelope: Envelope) -> Envelope | None:
        if envelope.WhichOneof("payload") != "action_request":
            return None
        req = envelope.action_request
        resp = ActionResponse(
            action_id=req.action_id,
            status=ActionStatus.ACTION_OK,
            data_json=req.params_json,
            error="",
        )
        out = Envelope(sender_id=self.id())
        out.action_response.CopyFrom(resp)
        return out  # auto-sent to "kernel" by serve()


if __name__ == "__main__":
    asyncio.run(EchoPlugin().run())
```

`Plugin.run` connects, registers, and serves until the kernel asks the plugin
to shut down. The SDK answers `Ping` automatically, acknowledges delivered
events after `on_event` succeeds, and exits the loop on `PluginShutdown`.

### Confirmation gate (high-risk actions)

For high-risk operations (a kernel gate would violate the dumb-core rule, so
the gate lives in the plugin), `ConfirmationGate` splits one operation into
`request_<op>` — any caller may invoke, the action spec is marked
`requires_confirmation`, nothing executes — and `confirm_<op>`, which only
callers on the gate's allowlist may invoke and which executes the params
stored at request time. Enforcement keys on the kernel-stamped
`caller_plugin_id`, which the kernel overwrites from the real registered
sender and cannot be spoofed:

```python
from vynkor.confirmation_gate import ConfirmationGate, send_confirmation_request, send_confirmation
from vynkor.vynkor_protocol_pb2 import ActionRisk

gate = ConfirmationGate(
    "transfer",
    "Move money between accounts",
    '{"type":"object"}',
    ActionRisk.ACTION_RISK_CRITICAL,
    ["device.phone"],      # only the user's device may confirm
)
actions, action_specs = gate.manifest_entries()
# merge into PluginManifest(actions=actions, action_specs=action_specs, ...)

# provider side, per inbound request:
envelopes = await gate.route(req, lambda params: execute(params))

# caller side:
pending_id = await send_confirmation_request(client, "transfer", params)
resp = await send_confirmation(client, "transfer", pending_id)
```

Pending requests expire (default 5 minutes, configurable via
`with_pending_ttl`), and the allowlist supports `prefix.*` globs so
`"device.*"` covers every device bridge mirror. See `vynkor/confirmation_gate.py`
for the full API.

### Concurrent message loop (hot-path plugins)

The default `Plugin.serve` loop is sequential — correct for low-volume plugins
but wrong for storage-class plugins that get called far more often. Use the
concurrent loop so a slow request never blocks the next one:

```python
from vynkor.concurrent import ConcurrentHandler, response_envelope, serve_concurrent
from vynkor.vynkor_protocol_pb2 import PluginManifest

class MyHandler(ConcurrentHandler):
    def id(self) -> str:
        return "database"

    def manifest(self) -> PluginManifest:
        return PluginManifest(actions=["get", "put"])

    async def on_action(self, req):
        # ... handle req ...
        return [response_envelope(req.action_id, b'{"ok": true}')]

async def main():
    from vynkor import VynkorClient
    client = await VynkorClient.connect_from_env()
    await serve_concurrent(client, "", MyHandler())
```

Each inbound `ActionRequest` runs in its own task; the single task that owns
the `VynkorClient` multiplexes inbound frames and completed responses. See
`vynkor/concurrent.py` for the full API (mirrors `src/concurrent.rs`).

### WebSocket transport (remote devices)

`Plugin.run_ws(url)` is the WS mirror of `Plugin.run` for plugins that live
on a different machine than the kernel (see the Remote Devices roadmap). The
URL is the gateway endpoint, e.g. `ws://host:8080/ws`:

```python
import asyncio
from vynkor import Plugin

class EchoPlugin(Plugin):
    def id(self) -> str:
        return "echo"

    def manifest(self):
        from vynkor.vynkor_protocol_pb2 import PluginManifest
        return PluginManifest()

    async def on_message(self, envelope):
        return None

async def main():
    await EchoPlugin().run_ws("ws://192.168.1.10:8080/ws")

if __name__ == "__main__":
    asyncio.run(main())
```

JWT credentials come from the same env vars as the UDS path — the token is
presented both in the `Sec-WebSocket-Protocol: vynkor, <jwt>` handshake header
and in the registration envelope. Registration, frame-MAC enable and reconnect
behave exactly like the UDS client. Two differences are dictated by the
gateway (R5-03): outbound frames are never zstd-compressed and never
fragmented over WS (`send_fragmented` raises), while `FLAG_RAW_BINARY` audio
passes unchanged.

## Environment

| Variable             | Meaning                                                        |
|----------------------|----------------------------------------------------------------|
| `VYN_SOCKET_PATH` | Kernel UDS path. Default: `XDG_RUNTIME_DIR` → `/run/user/<uid>` → `~/.local/state/vyn/run` (never shared `/tmp`). |
| `VYN_JWT_TOKEN`   | JWT presented at registration (required on secured kernels).   |
| `VYN_JWT_SECRET`  | Shared secret; enables per-frame HMAC-SHA256 tags after registration. |

## Protocol coverage

The SDK re-exports the kernel framing layer (`vynkor.framing`), so the
wire format cannot drift between the two sides. All flag bits from
`docs/FRAMING.md` are handled:

| Flag               | Send                                             | Receive                                    |
|--------------------|--------------------------------------------------|--------------------------------------------|
| `FLAG_MAC_PRESENT` | automatic after secured registration             | verified; untagged frames rejected         |
| `FLAG_COMPRESSED`  | automatic for payloads ≥ 64 KiB (UDS only — the WS gateway rejects compressed inbound frames, so the WS transport never compresses) | decompressed + normalized by `read_frame`  |
| `FLAG_FRAGMENTED`  | `VynkorClient.send_fragmented` (UDS only — raises over WS) | reassembled by `recv`/`recv_frame` (64 streams, 1 MiB, 30 s bounds) |
| `FLAG_RAW_BINARY`  | `VynkorClient.send_raw_audio` (UDS and WS)      | returned raw by `recv_frame`               |

## Protocol source

`proto/vynkor_protocol.proto` is vendored from
[`vynkor-wire`](https://crates.io/crates/vynkor-wire)'s `proto/` (wire
protocol **v1.7** as of the latest sync). It's copied by hand, not
path-referenced — re-sync it when the protocol changes upstream, then
regenerate `vynkor/vynkor_protocol_pb2.py`:

```bash
python scripts/gen_proto_python.py
```

(the kernel's `R8-05` test guards byte identity).

## Client API

For lower-level control, use `VynkorClient` directly:

```python
client = await VynkorClient.connect_with_secret(socket_path, secret)
ack = await client.register_with_token("weather", manifest, jwt)

await client.subscribe(["alarm.fired"])
ack = await client.publish_event("weather.updated", b'{"city":"Berlin"}', 5_000)
latency = await client.ping()  # round-trip in seconds

resp = await client.send_action("get_weather", b'{"city":"Berlin"}', 5_000)

action_id = await client.send_action_streaming("transcribe", 30_000)
await client.send_request_chunk(action_id, 0, b"hi", True)
await client.send_response_chunk(action_id, 0, b"ok")
await client.close_session(action_id, "done")
```

Over WebSocket, connect with the gateway URL instead — same API afterwards:

```python
client = await VynkorClient.connect_ws("ws://host:8080/ws", jwt, secret)
ack = await client.register_with_token("device.geo", manifest, jwt)
```

`publish_event` requires `PERMISSION_EVENT_PUBLISH`; `timeout_ms == 0` uses
the kernel's 30s default. It returns the kernel's `EventPublishAck` as-is —
inspect `ack.status` yourself (`EVENT_PUBLISH_OK`/`ERROR`/`PERMISSION_DENY`)
— and only raises on a kernel `Error` envelope or on timeout.

`send_action` follows the same `timeout_ms == 0` → 30s-default convention
and returns the kernel's `ActionResponse` as-is (inspect `.status` yourself).
It raises on a kernel `Error` envelope, on an `ActionStreamAbort` for this
`action_id`, or on timeout. `send_action_streaming` fires an
`ActionRequest{streaming: true}` and returns its generated `action_id`
immediately, without waiting for any response — drive `recv`/chunks yourself
afterward. `send_request_chunk`, `send_response_chunk`, and `close_session`
are fire-and-forget sends (no response awaited); `close_session` has no
`final` flag — the response side of a stream is terminated by an ordinary
`ActionResponse`.

Requests and responses are matched on a single connection; drive
request/response traffic from one task, or use the `Plugin` trait's serve
loop.

Other client methods: `recv()` / `recv_frame()` / `recv_timeout(timeout)`,
`subscribe` / `unsubscribe`, `ack_event`, `send_command` (returns
`KernelCommandAck`), `send_audio_chunk`, `send_raw_audio`,
`send_fragmented`, `is_secured()`.

## Errors

All SDK-level failures raise `vynkor.VynkorError` (or a subclass) instead of
bare `ValueError` / `RuntimeError` / `TimeoutError`. Subclasses mirror the
Rust `WireError` variants: `VynkorIoError`, `VynkorProtoError`,
`VynkorFrameMagicMismatch`, `VynkorFrameCrcMismatch`, `VynkorFrameReadTimeout`,
`VynkorPayloadTooLarge`, `VynkorTimeout`, `VynkorPermissionDenied`,
`VynkorInternal`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite lives in `tests/` and imports the in-tree package directly
(`pythonpath = ["."]` in `pyproject.toml`), so no install is needed to run
it. `tests/test_sdk.py` requires a live kernel socket and is skipped when
absent; the rest use fake clients / socketpairs.

## License

MIT
