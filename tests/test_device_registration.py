"""CD-02 / E-01: a paired device's registration carries device_id and its
frame MAC keys off the device's own secret. Runs over socket.socketpair() —
no kernel required."""
import asyncio
import socket

from vynkor import VynkorClient
from vynkor.framing import async_read_frame, derive_session_key, pack_frame
from vynkor.vynkor_protocol_pb2 import Envelope, PluginManifest

NONCE = b"0123456789abcdef"


def _ack_frame(target: str, nonce: bytes) -> bytes:
    env = Envelope()
    env.plugin_register_ack.accepted = True
    env.plugin_register_ack.session_nonce = nonce
    return pack_frame(target, env.SerializeToString())


async def _pair(secret):
    a, b = socket.socketpair()
    reader, writer = await asyncio.open_unix_connection(sock=a)
    k_reader, k_writer = await asyncio.open_unix_connection(sock=b)
    return VynkorClient.from_stream(reader, writer, secret=secret), k_reader, k_writer


async def _read_register(k_reader):
    _flags, payload = await async_read_frame(k_reader)
    env = Envelope()
    env.ParseFromString(payload)
    assert env.HasField("plugin_register")
    return env.plugin_register


def test_device_registration_sends_device_id_and_macs_with_device_secret():
    device_secret = b"per-device-secret-from-pairing"

    async def main():
        client, k_reader, k_writer = await _pair(device_secret)
        client.with_device_id("phone-1")
        # queue the ack before registering; the socket buffers it
        k_writer.write(_ack_frame("phone-1", NONCE))
        await k_writer.drain()

        ack = await client.register("phone-1", PluginManifest())
        assert ack.accepted
        assert client.is_secured()
        assert (await _read_register(k_reader)).device_id == "phone-1"

        # next frame must verify under the key derived from the device secret
        await client.subscribe(["*"])
        key = derive_session_key(device_secret, NONCE, "phone-1")
        await async_read_frame(k_reader, session_key=key)
        await client.close()
        k_writer.close()

    asyncio.run(main())


def test_local_registration_leaves_device_id_empty():
    async def main():
        client, k_reader, k_writer = await _pair(None)
        k_writer.write(_ack_frame("local-plugin", b""))
        await k_writer.drain()

        await client.register("local-plugin", PluginManifest())
        assert (await _read_register(k_reader)).device_id == ""
        await client.close()
        k_writer.close()

    asyncio.run(main())
