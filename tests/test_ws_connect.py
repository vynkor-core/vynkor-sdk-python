"""connect_ws must *offer* the `vynkor` subprotocol (and the JWT as a second one)
through the websockets `subprotocols` option. Sending a raw Sec-WebSocket-Protocol
header makes the client library reject the server's selected subprotocol with
NegotiationError("no subprotocols supported"). Uses a local websockets server —
no kernel required."""
import pytest
import websockets

from vynkor import VynkorClient

TOKEN = "aaa.bbb.ccc"


async def _serve(offered: list):
    def select(_conn, subprotocols):
        offered.extend(subprotocols)
        return "vynkor" if "vynkor" in subprotocols else None

    async def handler(_ws):
        pass

    return await websockets.serve(handler, "127.0.0.1", 0, subprotocols=["vynkor"], select_subprotocol=select)


def _url(server) -> str:
    return f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/ws"


async def test_connect_ws_offers_vynkor_and_jwt():
    offered: list = []
    server = await _serve(offered)
    try:
        client = await VynkorClient.connect_ws(_url(server), TOKEN)
        assert client._transport == "ws"
        assert client._ws.subprotocol == "vynkor"
        assert offered == ["vynkor", TOKEN]
        await client._ws.close()
    finally:
        server.close()
        await server.wait_closed()


async def test_connect_ws_without_token_offers_only_vynkor():
    offered: list = []
    server = await _serve(offered)
    try:
        client = await VynkorClient.connect_ws(_url(server))
        assert client._ws.subprotocol == "vynkor"
        assert offered == ["vynkor"]
        await client._ws.close()
    finally:
        server.close()
        await server.wait_closed()


async def test_connect_ws_forwards_extra_connect_kwargs():
    offered: list = []
    server = await _serve(offered)
    try:
        with pytest.raises(TypeError):
            # an unknown option must reach websockets.connect, not be swallowed
            await VynkorClient.connect_ws(_url(server), TOKEN, no_such_option=1)
    finally:
        server.close()
        await server.wait_closed()
