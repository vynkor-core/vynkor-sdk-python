import asyncio
import io
import struct

import pytest

from vynkor.framing import (
    FLAG_MAC_PRESENT,
    derive_session_key,
    compute_tag,
    verify_tag,
    pack_frame,
    read_frame,
    async_read_frame,
    HEADER_SIZE,
)
from vynkor.errors import VynkorInternal


def test_derive_session_key_is_deterministic():
    k1 = derive_session_key(b"secret", b"nonce-0123456789ab", "plugin-a")
    k2 = derive_session_key(b"secret", b"nonce-0123456789ab", "plugin-a")
    assert k1 == k2
    assert len(k1) == 32


def test_derive_session_key_is_input_sensitive():
    k = derive_session_key(b"secret", b"nonce-0123456789ab", "plugin-a")
    assert k != derive_session_key(b"other!", b"nonce-0123456789ab", "plugin-a")
    assert k != derive_session_key(b"secret", b"nonce-xxxxxxxxxxxx", "plugin-a")
    assert k != derive_session_key(b"secret", b"nonce-0123456789ab", "plugin-b")


def test_compute_and_verify_tag():
    key = derive_session_key(b"secret", b"nonce-0123456789ab", "p")
    header = bytes(range(44))
    payload = b"hello vynkor"
    tag = compute_tag(key, header, payload)
    assert len(tag) == 32
    assert verify_tag(key, header, payload, tag)


def test_verify_tag_rejects_tampered_payload():
    key = derive_session_key(b"secret", b"nonce-0123456789ab", "p")
    header = bytes(range(44))
    payload = b"hello"
    tag = compute_tag(key, header, payload)
    assert not verify_tag(key, header, b"hellx", tag)


def test_verify_tag_rejects_tampered_header():
    key = derive_session_key(b"secret", b"nonce-0123456789ab", "p")
    header = bytes(range(44))
    payload = b"hello"
    tag = compute_tag(key, header, payload)
    bad_header = bytes([header[0] ^ 0xFF]) + header[1:]
    assert not verify_tag(key, bad_header, payload, tag)


def test_verify_tag_rejects_wrong_key():
    key = derive_session_key(b"secret", b"nonce-0123456789ab", "p")
    other = derive_session_key(b"secret", b"nonce-xxxxxxxxxxxx", "p")
    header = bytes(range(44))
    payload = b"hello"
    tag = compute_tag(key, header, payload)
    assert not verify_tag(other, header, payload, tag)


def test_pack_frame_mac_sets_flag_and_appends_tag():
    key = derive_session_key(b"secret", b"nonce-0123456789ab", "tgt")
    payload = b"test payload"
    frame = pack_frame("tgt", payload, session_key=key)
    # header is 44 bytes, payload is 12, tag is 32
    assert len(frame) == 44 + 12 + 32
    flags = struct.unpack(">H", frame[2:4])[0]
    assert flags & FLAG_MAC_PRESENT


def test_pack_frame_no_key_no_mac():
    payload = b"test payload"
    frame = pack_frame("tgt", payload)
    assert len(frame) == 44 + len(payload)
    flags = struct.unpack(">H", frame[2:4])[0]
    assert not (flags & FLAG_MAC_PRESENT)


def test_read_frame_mac_verifies():
    key = derive_session_key(b"secret", b"nonce-0123456789ab", "tgt")
    payload = b"round trip"
    frame = pack_frame("tgt", payload, session_key=key)
    result = read_frame(io.BytesIO(frame), session_key=key)
    assert result == payload


def test_read_frame_mac_rejects_tampered():
    key = derive_session_key(b"secret", b"nonce-0123456789ab", "tgt")
    payload = b"round trip"
    frame = bytearray(pack_frame("tgt", payload, session_key=key))
    frame[-1] ^= 0xFF  # corrupt last byte of MAC tag
    with pytest.raises(VynkorInternal, match="MAC verification failed"):
        read_frame(io.BytesIO(bytes(frame)), session_key=key)


def test_read_frame_no_key_skips_verification():
    key = derive_session_key(b"secret", b"nonce-0123456789ab", "tgt")
    payload = b"no verify"
    frame = pack_frame("tgt", payload, session_key=key)
    # No session_key passed: reads and discards MAC bytes, returns payload
    result = read_frame(io.BytesIO(frame))
    assert result == payload


def test_async_read_frame_mac_verifies():
    key = derive_session_key(b"secret", b"nonce-0123456789ab", "tgt")
    payload = b"async round trip"
    frame = pack_frame("tgt", payload, session_key=key)

    async def _run():
        reader = asyncio.StreamReader()
        reader.feed_data(frame)
        reader.feed_eof()
        return await async_read_frame(reader, session_key=key)

    flags, result = asyncio.run(_run())
    assert result == payload


def test_client_derive_session_key_after_mock_ack():
    """Client correctly derives session_key from a mock PluginRegisterAck."""
    from vynkor.client import VynkorClient
    from vynkor.vynkor_protocol_pb2 import Envelope, PluginRegisterAck

    secret = b"test-jwt-secret"
    nonce = b"nonce-0123456789ab"[:16]
    plugin_id = "mock-plugin"

    client = VynkorClient("/tmp/not-used.sock", secret=secret)
    # Simulate what register() does after receiving the ack
    client._apply_session_nonce(plugin_id, nonce)

    from vynkor.framing import derive_session_key
    expected_key = derive_session_key(secret, nonce, plugin_id)
    assert client.session_key == expected_key
