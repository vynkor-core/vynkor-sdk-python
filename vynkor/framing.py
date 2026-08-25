import asyncio
import hashlib
import hmac as _hmac
import struct
from binascii import crc32
from typing import Optional

import zstandard

from .errors import (
    VeyronFrameCrcMismatch,
    VeyronFrameMagicMismatch,
    VeyronFrameReadTimeout,
    VeyronInternal,
    VeyronIoError,
    VeyronPayloadTooLarge,
)

MAGIC = 0x5652
HEADER_FMT = ">HHI32sI"  # magic, flags, length, target, crc32
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 44
MAX_PAYLOAD = 1_048_576
FLAG_MAC_PRESENT   = 0x0001
FLAG_COMPRESSED    = 0x0002  # payload is zstd-compressed; CRC32 over compressed bytes
FLAG_FRAGMENTED    = 0x0004  # payload is one fragment; first FRAG_HEADER_SIZE bytes are metadata
FLAG_RAW_BINARY    = 0x0010  # payload is raw bytes (PCM/Opus); router skips Protobuf decode
COMPRESS_THRESHOLD = 65_536  # payloads >= this size are candidates for compression

# Once a frame has started arriving, the rest of the header + payload must
# complete within this window. Bounds slow-loris stalls (a peer that sends
# one byte declaring a large payload then dribbles or stops). Idle
# connections waiting for the next frame are NOT subject to it. Mirrors
# wire/src/framing.rs FRAME_READ_TIMEOUT.
FRAME_READ_TIMEOUT = 10.0  # seconds

# Fragment metadata header: [fragment_id: u16][sequence: u16][total: u16][stream_id: u32]
FRAG_HEADER_FMT = ">HHHI"
FRAG_HEADER_SIZE = struct.calcsize(FRAG_HEADER_FMT)  # 10


def pack_frag_header(fragment_id: int, sequence: int, total: int, stream_id: int) -> bytes:
    return struct.pack(FRAG_HEADER_FMT, fragment_id, sequence, total, stream_id)


def parse_frag_header(payload: bytes):
    """Returns (fragment_id, sequence, total, stream_id) or None if too short."""
    if len(payload) < FRAG_HEADER_SIZE:
        return None
    return struct.unpack(FRAG_HEADER_FMT, payload[:FRAG_HEADER_SIZE])


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869) — no external deps needed
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        h = _hmac.new(prk, digestmod=hashlib.sha256)
        h.update(t)
        h.update(info)
        h.update(bytes([counter]))
        t = h.digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_session_key(secret: bytes, nonce: bytes, plugin_id: str) -> bytes:
    """HKDF-SHA256 session key. Mirrors Rust auth::frame_mac::derive_session_key."""
    prk = _hkdf_extract(salt=nonce, ikm=secret)
    info = b"vynkor-frame-mac-v1|" + plugin_id.encode()
    return _hkdf_expand(prk, info, 32)


def compute_tag(key: bytes, header: bytes, payload: bytes) -> bytes:
    """HMAC-SHA256 over header || payload. Returns 32-byte tag."""
    h = _hmac.new(key, digestmod=hashlib.sha256)
    h.update(header)
    h.update(payload)
    return h.digest()


def verify_tag(key: bytes, header: bytes, payload: bytes, tag: bytes) -> bool:
    """Constant-time MAC verification."""
    expected = compute_tag(key, header, payload)
    return _hmac.compare_digest(expected, tag)


# ---------------------------------------------------------------------------
# Frame encoding / decoding
# ---------------------------------------------------------------------------

def _target_bytes(target: str) -> bytes:
    return target.encode()[:32].ljust(32, b"\x00")[:32]


def header_bytes_for(flags: int, target_bytes: bytes, payload: bytes) -> bytes:
    checksum = crc32(payload) & 0xFFFFFFFF
    return struct.pack(HEADER_FMT, MAGIC, flags, len(payload), target_bytes, checksum)


def _compress(payload: bytes) -> bytes:
    return zstandard.ZstdCompressor(level=3).compress(payload)


def _decompress(payload: bytes) -> bytes:
    """Bounded zstd decompression mirroring wire/src/framing.rs read_frame_body."""
    decompressor = zstandard.ZstdDecompressor()
    try:
        out = decompressor.decompress(payload, max_output_size=MAX_PAYLOAD)
    except zstandard.ZstdError as e:
        raise VeyronInternal(f"decompress frame: {e}") from e
    if len(out) > MAX_PAYLOAD:
        raise VeyronPayloadTooLarge(len(out))
    return out


def pack_frame(
    target: str,
    payload: bytes,
    flags: int = 0,
    session_key: Optional[bytes] = None,
    compress: bool = True,
) -> bytes:
    """Encode one outbound frame. Mirrors vynkor-wire's write_frame_raw:
    MAC is computed over the *plaintext* header+payload first, then payloads
    >= COMPRESS_THRESHOLD (and not already compressed / raw binary) are
    zstd-compressed at level 3; CRC32 covers the wire (possibly compressed)
    bytes.

    ``compress=False`` disables zstd (for WebSocket transport — the gateway
    rejects FLAG_COMPRESSED inbound, so the WS path never compresses).
    """
    if len(payload) > MAX_PAYLOAD:
        raise VeyronPayloadTooLarge(len(payload))
    if session_key is not None:
        flags |= FLAG_MAC_PRESENT

    tag = None
    if session_key is not None:
        # MAC over the pre-compression header + payload, so the receiver can
        # rebuild the plaintext header and verify (matches wire crate).
        plain_header = header_bytes_for(flags, _target_bytes(target), payload)
        tag = compute_tag(session_key, plain_header, payload)

    wire_payload = payload
    wire_flags = flags
    if (
        compress
        and len(payload) >= COMPRESS_THRESHOLD
        and not (flags & FLAG_COMPRESSED)
        and not (flags & FLAG_RAW_BINARY)
    ):
        compressed = _compress(payload)
        if len(compressed) < len(payload):
            wire_payload = compressed
            wire_flags = flags | FLAG_COMPRESSED

    wire_crc = crc32(wire_payload) & 0xFFFFFFFF
    wire_header = struct.pack(
        HEADER_FMT, MAGIC, wire_flags, len(wire_payload), _target_bytes(target), wire_crc
    )
    frame = wire_header + wire_payload
    if tag is not None:
        frame += tag
    return frame


def _normalize(flags: int, target_bytes: bytes, payload: bytes):
    """If FLAG_COMPRESSED, decompress and rebuild the plaintext header the MAC
    was computed over. Mirrors wire/src/framing.rs read_frame_body."""
    if not flags & FLAG_COMPRESSED:
        return flags, header_bytes_for(flags, target_bytes, payload), payload
    plain = _decompress(payload)
    plain_flags = flags & ~FLAG_COMPRESSED
    plain_header = header_bytes_for(plain_flags, target_bytes, plain)
    return plain_flags, plain_header, plain


def read_frame(stream, session_key: Optional[bytes] = None) -> bytes:
    """Read one frame from a synchronous, file-like stream (e.g. io.BytesIO)
    and return the payload. No timeout: intended for already-buffered input,
    not a live socket — use async_read_frame for that."""
    header_bytes = stream.read(HEADER_SIZE)
    if len(header_bytes) < HEADER_SIZE:
        raise VeyronIoError("truncated frame header")
    magic, flags, length, target_bytes, stored_crc = struct.unpack(HEADER_FMT, header_bytes)
    if magic != MAGIC:
        raise VeyronFrameMagicMismatch()
    if length > MAX_PAYLOAD:
        raise VeyronPayloadTooLarge(length)
    payload = stream.read(length) if length > 0 else b""
    if len(payload) < length:
        raise VeyronIoError("truncated frame payload")
    computed = crc32(payload) & 0xFFFFFFFF
    if computed != stored_crc:
        raise VeyronFrameCrcMismatch()

    flags, header_bytes, payload = _normalize(flags, target_bytes, payload)

    if flags & FLAG_MAC_PRESENT:
        tag = stream.read(32)
        if len(tag) < 32:
            raise VeyronIoError("truncated MAC tag")
        if session_key is not None and not verify_tag(session_key, header_bytes, payload, tag):
            raise VeyronInternal("frame MAC verification failed")
    elif session_key is not None:
        raise VeyronInternal("MAC missing on secured connection")
    return payload


def read_frame_from_bytes(data: bytes, session_key: Optional[bytes] = None):
    """Parse one frame from a complete ``bytes`` blob (one WebSocket binary
    message). Returns ``(flags, payload)`` with ``FLAG_COMPRESSED`` already
    normalized but ``FLAG_FRAGMENTED``/``FLAG_RAW_BINARY`` preserved.

    Mirrors the Rust WS ``Transport::read_frame`` path which does
    ``read_frame(&mut cursor)`` over the binary message.
    """
    import io

    stream = io.BytesIO(data)
    header_bytes = stream.read(HEADER_SIZE)
    if len(header_bytes) < HEADER_SIZE:
        raise VeyronIoError("truncated frame header")
    magic, flags, length, target_bytes, stored_crc = struct.unpack(HEADER_FMT, header_bytes)
    if magic != MAGIC:
        raise VeyronFrameMagicMismatch()
    if length > MAX_PAYLOAD:
        raise VeyronPayloadTooLarge(length)
    payload = stream.read(length) if length > 0 else b""
    if len(payload) < length:
        raise VeyronIoError("truncated frame payload")
    computed = crc32(payload) & 0xFFFFFFFF
    if computed != stored_crc:
        raise VeyronFrameCrcMismatch()

    flags, header_bytes2, payload = _normalize(flags, target_bytes, payload)

    if flags & FLAG_MAC_PRESENT:
        tag = stream.read(32)
        if len(tag) < 32:
            raise VeyronIoError("truncated MAC tag")
        if session_key is not None and not verify_tag(session_key, header_bytes2, payload, tag):
            raise VeyronInternal("frame MAC verification failed")
    elif session_key is not None:
        raise VeyronInternal("MAC missing on secured connection")
    return flags, payload


async def async_read_frame(
    reader,
    session_key: Optional[bytes] = None,
    frame_timeout: float = FRAME_READ_TIMEOUT,
):
    """Read one frame from an asyncio StreamReader. Returns (flags, payload);
    flags has FLAG_COMPRESSED cleared (already normalized) but FLAG_FRAGMENTED
    and FLAG_RAW_BINARY preserved for the caller to act on."""
    # Block indefinitely for the first byte — an idle connection between
    # frames must not be torn down. Once a byte arrives, a frame is in
    # progress and the remainder is bounded by frame_timeout.
    first_byte = await reader.readexactly(1)

    async def _read_body():
        header_bytes = first_byte + await reader.readexactly(HEADER_SIZE - 1)
        magic, flags, length, target_bytes, stored_crc = struct.unpack(HEADER_FMT, header_bytes)
        if magic != MAGIC:
            raise VeyronFrameMagicMismatch()
        if length > MAX_PAYLOAD:
            raise VeyronPayloadTooLarge(length)
        payload = await reader.readexactly(length) if length > 0 else b""
        computed = crc32(payload) & 0xFFFFFFFF
        if computed != stored_crc:
            raise VeyronFrameCrcMismatch()

        flags, header_bytes2, payload = _normalize(flags, target_bytes, payload)

        if flags & FLAG_MAC_PRESENT:
            tag = await reader.readexactly(32)
            if session_key is not None and not verify_tag(session_key, header_bytes2, payload, tag):
                raise VeyronInternal("frame MAC verification failed")
        elif session_key is not None:
            raise VeyronInternal("MAC missing on secured connection")
        return flags, payload

    try:
        return await asyncio.wait_for(_read_body(), timeout=frame_timeout)
    except asyncio.TimeoutError:
        raise VeyronFrameReadTimeout() from None
