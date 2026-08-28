"""Integration tests for the Python Vynkor SDK.

Requires a running kernel (vyn start --foreground) at /tmp/vyn.sock.
Run with: pytest tests/ -v
"""
import asyncio
import os

import pytest
import pytest_asyncio

from vynkor import VynkorClient
from vynkor.vynkor_protocol_pb2 import PluginManifest

SOCKET = os.environ.get("VYN_SOCKET_PATH", "/tmp/vyn.sock")
pytestmark = pytest.mark.skipif(
    not os.path.exists(SOCKET),
    reason=f"no kernel socket at {SOCKET}",
)


@pytest_asyncio.fixture(scope="function")
async def client():
    c = VynkorClient(SOCKET)
    await c.connect()
    yield c
    await c.close()


@pytest.mark.asyncio
async def test_connect_and_register(client):
    ack = await client.register("py-test-plugin", PluginManifest())
    assert ack.accepted, f"registration rejected: {ack.reject_reason}"


@pytest.mark.asyncio
async def test_ping_pong_round_trip(client):
    await client.register("py-ping-plugin", PluginManifest())
    elapsed = await client.ping()
    assert elapsed < 1.0, f"ping took too long: {elapsed:.3f}s"


@pytest.mark.asyncio
async def test_subscribe_completes_without_error(client):
    await client.register("py-sub-plugin", PluginManifest())
    await client.subscribe(["system.plugin_joined", "system.plugin_died"])
