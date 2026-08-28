"""R5-01: Python SDK must decompress FLAG_COMPRESSED frames and verify the MAC
against the rebuilt plaintext header, mirroring src/ipc/framing.rs:228-241.
"""
import io
import os
import struct

import pytest

zstandard = pytest.importorskip("zstandard")

from binascii import crc32

from vynkor.framing import (
    FLAG_COMPRESSED,
    FLAG_MAC_PRESENT,
    HEADER_FMT,
    MAGIC,
    compute_tag,
    derive_session_key,
    pack_frame,
    read_frame,
)
from vynkor.errors import VynkorInternal


def _pack_compressed_frame(target: str, plain_payload: bytes, session_key=None) -> bytes:
    """Build a wire frame the way the kernel does for payloads >= 64 KiB:
    zstd-compress, set FLAG_COMPRESSED, CRC over compressed bytes, MAC (if any)
    over the *plaintext* header+payload."""
    compressed = zstandard.ZstdCompressor(level=3).compress(plain_payload)
    flags = FLAG_COMPRESSED
    if session_key is not None:
        flags |= FLAG_MAC_PRESENT
    target_bytes = target.encode()[:32].ljust(32, b"\x00")[:32]

    wire_crc = crc32(compressed) & 0xFFFFFFFF
    wire_header = struct.pack(HEADER_FMT, MAGIC, flags, len(compressed), target_bytes, wire_crc)
    frame = wire_header + compressed

    if session_key is not None:
        plain_flags = flags & ~FLAG_COMPRESSED
        plain_crc = crc32(plain_payload) & 0xFFFFFFFF
        plain_header = struct.pack(
            HEADER_FMT, MAGIC, plain_flags, len(plain_payload), target_bytes, plain_crc
        )
        frame += compute_tag(session_key, plain_header, plain_payload)

    return frame


def test_read_frame_decompresses_large_payload():
    payload = os.urandom(100_000)
    frame = _pack_compressed_frame("kernel", payload)
    assert read_frame(io.BytesIO(frame)) == payload


def test_read_frame_decompresses_and_verifies_mac():
    session_key = derive_session_key(b"top-secret", b"nonce123", "plugin-a")
    payload = b"x" * 100_000
    frame = _pack_compressed_frame("kernel", payload, session_key=session_key)
    assert read_frame(io.BytesIO(frame), session_key=session_key) == payload


def test_read_frame_rejects_bad_mac_on_compressed_frame():
    session_key = derive_session_key(b"top-secret", b"nonce123", "plugin-a")
    wrong_key = derive_session_key(b"different", b"nonce123", "plugin-a")
    payload = b"y" * 100_000
    frame = _pack_compressed_frame("kernel", payload, session_key=session_key)
    with pytest.raises(VynkorInternal, match="MAC"):
        read_frame(io.BytesIO(frame), session_key=wrong_key)


def test_uncompressed_roundtrip_unaffected():
    payload = b"small payload"
    frame = pack_frame("kernel", payload)
    assert read_frame(io.BytesIO(frame)) == payload


def test_read_frame_rejects_garbage_compressed_payload():
    """T-14 (Python fuzz half): a FLAG_COMPRESSED frame whose payload isn't
    valid zstd must raise VynkorError like every other malformed-frame path,
    not let zstandard.ZstdError escape uninstructed."""
    garbage = b"\xff" * 64
    target_bytes = b"kernel".ljust(32, b"\x00")[:32]
    crc = crc32(garbage) & 0xFFFFFFFF
    header = struct.pack(HEADER_FMT, MAGIC, FLAG_COMPRESSED, len(garbage), target_bytes, crc)
    with pytest.raises(VynkorInternal):
        read_frame(io.BytesIO(header + garbage))
