"""Unit tests: Plugin/Client pick up JWT credentials and the socket path from
env vars (R5-05). No live kernel required — connection methods are
monkeypatched."""
import asyncio

import pytest

from vynkor import VynkorClient
from vynkor.errors import VynkorInternal
from vynkor.plugin import Plugin, WsCredentials, resolve_ws_credentials
from vynkor.vynkor_protocol_pb2 import Envelope, PluginRegisterAck


class _NoopPlugin(Plugin):
    plugin_id = "env-test-plugin"

    async def on_message(self, envelope):
        return None


class _FakeClient:
    def __init__(self):
        self.register_args = None

    async def register_full(self, plugin_id, version, manifest, jwt_token):
        self.register_args = (plugin_id, version, manifest, jwt_token)
        return PluginRegisterAck(accepted=True)

    async def recv(self):
        env = Envelope()
        env.plugin_shutdown.SetInParent()
        return env

    async def send(self, target, envelope):
        pass

    async def ack_event(self, event_id):
        pass

    async def close(self):
        pass


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "VYN_JWT_TOKEN",
        "VYN_JWT_SECRET",
        "VYN_SOCKET_PATH",
        "VYN_DEVICE_ID",
        "VYN_DEVICE_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)


def test_connect_from_env_reads_socket_path_and_secret(monkeypatch):
    monkeypatch.setenv("VYN_SOCKET_PATH", "/tmp/vynkor-env.sock")
    monkeypatch.setenv("VYN_JWT_SECRET", "shh-secret")
    captured = {}

    async def fake_cws(cls, socket_path, secret):
        captured["socket_path"] = socket_path
        captured["secret"] = secret
        return _FakeClient()

    monkeypatch.setattr(VynkorClient, "connect_with_secret", classmethod(fake_cws))
    asyncio.run(VynkorClient.connect_from_env())
    assert captured == {"socket_path": "/tmp/vynkor-env.sock", "secret": b"shh-secret"}


def test_connect_from_env_no_secret_passes_none(monkeypatch):
    monkeypatch.setenv("VYN_SOCKET_PATH", "/tmp/vynkor-env.sock")
    captured = {}

    async def fake_cws(cls, socket_path, secret):
        captured["socket_path"] = socket_path
        captured["secret"] = secret
        return _FakeClient()

    monkeypatch.setattr(VynkorClient, "connect_with_secret", classmethod(fake_cws))
    asyncio.run(VynkorClient.connect_from_env())
    assert captured == {"socket_path": "/tmp/vynkor-env.sock", "secret": None}


def test_run_with_passes_env_token_and_secret_through(monkeypatch):
    monkeypatch.setenv("VYN_JWT_TOKEN", "tok-123")
    monkeypatch.setenv("VYN_JWT_SECRET", "shh-secret")

    fake = _FakeClient()
    captured = {}

    async def fake_cws(cls, socket_path, secret):
        captured["socket_path"] = socket_path
        captured["secret"] = secret
        return fake

    monkeypatch.setattr(VynkorClient, "connect_with_secret", classmethod(fake_cws))

    plugin = _NoopPlugin()
    asyncio.run(plugin.run_with("/tmp/vynkor-env.sock"))

    assert captured["socket_path"] == "/tmp/vynkor-env.sock"
    assert captured["secret"] == b"shh-secret"
    # register_full called with id/version/manifest/jwt_token
    assert fake.register_args[0] == "env-test-plugin"
    assert fake.register_args[1] == "1.0.0"
    assert fake.register_args[3] == "tok-123"


# ── resolve_ws_credentials (CD-02 / E-01) — same policy as Rust/C++ ──


def test_device_pair_selects_device_credentials():
    assert resolve_ws_credentials("phone-1", "dev-secret", None) == WsCredentials(
        "device", "phone-1", b"dev-secret"
    )


def test_master_secret_alone_is_shared():
    assert resolve_ws_credentials(None, None, "master") == WsCredentials(
        "shared", secret=b"master"
    )


def test_nothing_set_is_unsecured():
    # env vars set to "" count as unset
    assert resolve_ws_credentials(None, "", "") == WsCredentials("none")


def test_master_secret_next_to_device_pair_is_rejected():
    with pytest.raises(VynkorInternal, match="VYN_JWT_SECRET"):
        resolve_ws_credentials("phone-1", "dev-secret", "master")


@pytest.mark.parametrize("device_id,device_secret", [("phone-1", None), (None, "dev-secret")])
@pytest.mark.parametrize("jwt_secret", [None, "master"])
def test_half_device_pair_is_rejected_even_with_master_fallback(
    device_id, device_secret, jwt_secret
):
    with pytest.raises(VynkorInternal):
        resolve_ws_credentials(device_id, device_secret, jwt_secret)


def test_run_ws_uses_device_credentials_from_env(monkeypatch):
    monkeypatch.setenv("VYN_JWT_TOKEN", "dev-tok")
    monkeypatch.setenv("VYN_DEVICE_ID", "phone-1")
    monkeypatch.setenv("VYN_DEVICE_SECRET", "dev-secret")
    fake = _FakeClient()
    captured = {}

    async def fake_device(cls, url, jwt_token, device_id, device_secret):
        captured.update(url=url, token=jwt_token, device_id=device_id, secret=device_secret)
        return fake

    async def no_shared(cls, *args, **kwargs):
        raise AssertionError("run_ws must not take the shared-secret path")

    monkeypatch.setattr(VynkorClient, "connect_ws_device", classmethod(fake_device))
    monkeypatch.setattr(VynkorClient, "connect_ws", classmethod(no_shared))

    asyncio.run(_NoopPlugin().run_ws("ws://host:8080/ws"))

    assert captured == {
        "url": "ws://host:8080/ws",
        "token": "dev-tok",
        "device_id": "phone-1",
        "secret": b"dev-secret",
    }
    assert fake.register_args[3] == "dev-tok"


def test_run_ws_refuses_master_secret_on_device(monkeypatch):
    monkeypatch.setenv("VYN_DEVICE_ID", "phone-1")
    monkeypatch.setenv("VYN_DEVICE_SECRET", "dev-secret")
    monkeypatch.setenv("VYN_JWT_SECRET", "master")
    with pytest.raises(VynkorInternal):
        asyncio.run(_NoopPlugin().run_ws("ws://host:8080/ws"))
