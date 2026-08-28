"""P7-02: VynkorClient.send_action/send_action_streaming/send_request_chunk/
send_response_chunk/close_session — mirrors sdk/rust/src/client.rs's
send_action tests plus streaming-specific additions."""
import asyncio
import socket
import threading
import time

import pytest

from vynkor import VynkorClient
from vynkor.errors import VynkorInternal, VynkorTimeout
from vynkor.framing import pack_frame, read_frame
from vynkor.vynkor_protocol_pb2 import (
    Envelope,
    ACTION_OK,
)


def _recv_kernel_side(sock) -> Envelope:
    payload = read_frame(sock.makefile("rb"))
    env = Envelope()
    env.ParseFromString(payload)
    return env


def _send_kernel_side(sock, env: Envelope) -> None:
    frame = pack_frame("plugin", env.SerializeToString())
    sock.sendall(frame)


async def _make_client():
    sock_a, sock_b = socket.socketpair()
    reader, writer = await asyncio.open_connection(sock=sock_a)
    client = VynkorClient("unused")
    client._reader = reader
    client._writer = writer
    return client, sock_b


@pytest.mark.asyncio
async def test_send_action_ok_response_returned():
    client, kernel_sock = await _make_client()

    def kernel():
        req = _recv_kernel_side(kernel_sock)
        assert req.HasField("action_request")
        assert req.action_request.action == "get_weather"
        assert req.action_request.streaming is False

        resp = Envelope()
        resp.action_response.action_id = req.action_request.action_id
        resp.action_response.status = ACTION_OK
        resp.action_response.data_json = b"{}"
        _send_kernel_side(kernel_sock, resp)

    t = threading.Thread(target=kernel)
    t.start()
    resp = await client.send_action("get_weather", b"{}", 1000)
    t.join()

    assert resp.status == ACTION_OK
    assert resp.data_json == b"{}"


@pytest.mark.asyncio
async def test_send_action_stream_abort_for_action_id_raises():
    client, kernel_sock = await _make_client()

    def kernel():
        req = _recv_kernel_side(kernel_sock)
        resp = Envelope()
        resp.action_stream_abort.action_id = req.action_request.action_id
        resp.action_stream_abort.reason = "plugin crashed"
        _send_kernel_side(kernel_sock, resp)

    t = threading.Thread(target=kernel)
    t.start()
    with pytest.raises(VynkorInternal):
        await client.send_action("get_weather", b"{}", 1000)
    t.join()


@pytest.mark.asyncio
async def test_send_action_kernel_error_envelope_raises():
    client, kernel_sock = await _make_client()

    def kernel():
        _recv_kernel_side(kernel_sock)
        resp = Envelope()
        resp.error.message = "boom"
        resp.error.details = "detail"
        _send_kernel_side(kernel_sock, resp)

    t = threading.Thread(target=kernel)
    t.start()
    with pytest.raises(VynkorInternal):
        await client.send_action("get_weather", b"{}", 1000)
    t.join()


@pytest.mark.asyncio
async def test_send_action_times_out_when_no_response():
    client, kernel_sock = await _make_client()

    def kernel():
        _recv_kernel_side(kernel_sock)
        time.sleep(0.5)

    t = threading.Thread(target=kernel)
    t.start()
    start = time.monotonic()
    with pytest.raises(VynkorTimeout):
        await client.send_action("get_weather", b"{}", 150)
    elapsed = time.monotonic() - start
    assert elapsed < 2.0
    t.join()
    kernel_sock.close()


@pytest.mark.asyncio
async def test_send_action_unrelated_envelope_discarded_then_response_returned():
    client, kernel_sock = await _make_client()

    def kernel():
        req = _recv_kernel_side(kernel_sock)

        ping_env = Envelope()
        ping_env.ping.timestamp = 1
        _send_kernel_side(kernel_sock, ping_env)

        resp = Envelope()
        resp.action_response.action_id = req.action_request.action_id
        resp.action_response.status = ACTION_OK
        _send_kernel_side(kernel_sock, resp)

    t = threading.Thread(target=kernel)
    t.start()
    resp = await client.send_action("get_weather", b"{}", 1000)
    t.join()

    assert resp.status == ACTION_OK


@pytest.mark.asyncio
async def test_send_action_streaming_returns_action_id_immediately_without_blocking():
    client, kernel_sock = await _make_client()

    def kernel():
        req = _recv_kernel_side(kernel_sock)
        assert req.HasField("action_request")
        assert req.action_request.streaming is True
        assert req.action_request.params_json == b""
        # Deliberately never respond — send_action_streaming must not block.

    t = threading.Thread(target=kernel)
    t.start()
    action_id = await asyncio.wait_for(client.send_action_streaming("transcribe", 1000), timeout=1.0)
    assert action_id
    t.join()


@pytest.mark.asyncio
async def test_request_and_response_chunks_serialize_expected_fields():
    client, kernel_sock = await _make_client()

    def kernel():
        req_chunk = _recv_kernel_side(kernel_sock)
        assert req_chunk.HasField("action_request_chunk")
        assert req_chunk.action_request_chunk.action_id == "act-1"
        assert req_chunk.action_request_chunk.seq == 3
        assert req_chunk.action_request_chunk.chunk == b"hello"
        assert req_chunk.action_request_chunk.final is True

        resp_chunk = _recv_kernel_side(kernel_sock)
        assert resp_chunk.HasField("action_response_chunk")
        assert resp_chunk.action_response_chunk.action_id == "act-1"
        assert resp_chunk.action_response_chunk.seq == 7
        assert resp_chunk.action_response_chunk.chunk == b"world"

    t = threading.Thread(target=kernel)
    t.start()
    await client.send_request_chunk("act-1", 3, b"hello", True)
    await client.send_response_chunk("act-1", 7, b"world")
    t.join()


@pytest.mark.asyncio
async def test_close_session_serializes_action_id_and_reason():
    client, kernel_sock = await _make_client()

    def kernel():
        env = _recv_kernel_side(kernel_sock)
        assert env.HasField("session_close")
        assert env.session_close.action_id == "act-2"
        assert env.session_close.reason == "done"

    t = threading.Thread(target=kernel)
    t.start()
    await client.close_session("act-2", "done")
    t.join()
