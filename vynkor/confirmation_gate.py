"""Confirmation gate (D-09): plugin-level permission separation for high-risk actions.

Mirrors ``vynkor-sdk/src/confirmation_gate.rs`` 1:1.

Splits one risky operation into two actions:

- ``request_<op>`` — any registered caller may invoke; the params are
  stored as *pending* and the action spec is marked
  ``requires_confirmation``. Nothing executes yet.
- ``confirm_<op>`` — only callers on the gate's confirm allowlist may
  invoke; it executes the params stored by the matching ``request_<op>``
  call. Everyone else gets ``PermissionDenied``.

The kernel stays dumb on purpose (dumb-core rule — a kernel gate would
violate it): the gate lives entirely inside the plugin, keyed on the
kernel-stamped ``ActionRequest.caller_plugin_id``. The kernel overwrites
that field from the real registered sender on every forwarded request,
so the check cannot be spoofed by the caller.

Provider side — one-liner::

    from vynkor.confirmation_gate import ConfirmationGate
    from vynkor.vynkor_protocol_pb2 import ActionRisk

    gate = ConfirmationGate(
        "transfer",
        "Move money between accounts",
        '{"type":"object"}',
        ActionRisk.ACTION_RISK_CRITICAL,
        ["device.phone"],  # only the user's device may confirm
    )
    actions, action_specs = gate.manifest_entries()
    # merge into PluginManifest(actions=actions, action_specs=action_specs, ...)

    # in on_action: envelopes = await gate.route(req, lambda params: execute(params))

The allowlist supports a trailing ``.*`` suffix: ``"device.*"`` matches any
caller whose plugin id starts with ``device.``.

Caller side::

    from vynkor.confirmation_gate import send_confirmation_request, send_confirmation

    pending_id = await send_confirmation_request(client, "transfer", params)
    resp = await send_confirmation(client, "transfer", pending_id)

Pending requests expire after ``with_pending_ttl`` (default 5 minutes) —
a request nobody confirms is forgotten, so a hostile caller cannot
accumulate unbounded pending entries.
"""

from __future__ import annotations

import itertools
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, Tuple

from .vynkor_protocol_pb2 import (
    ActionRequest,
    ActionResponse,
    ActionSpec,
    ActionStatus,
    Envelope,
)

DEFAULT_PENDING_TTL = 300.0  # seconds

_seq = itertools.count()


def _next_seq() -> int:
    return next(_seq)


def _validate_op(op: str) -> None:
    if not op:
        raise ValueError("operation name must not be empty")
    if not all(c.isascii() and (c.isalnum() or c in "-_") for c in op):
        raise ValueError(
            "operation name may only contain ASCII alphanumerics, '-' and '_'"
        )
    if op.startswith("request_") or op.startswith("confirm_"):
        raise ValueError(
            "operation name must not start with request_/confirm_ "
            "(would collide with the gate's own action names)"
        )


def _response_envelope(action_id: str, result) -> Envelope:
    """Build an ActionResponse envelope — mirrors concurrent::response_envelope."""
    if isinstance(result, tuple) and len(result) == 2:
        # legacy: caller passed (ok, data_or_error) — not used internally
        ok, payload = result
        if ok:
            resp = ActionResponse(
                action_id=action_id,
                status=ActionStatus.ACTION_OK,
                data_json=payload if isinstance(payload, bytes) else b"",
            )
        else:
            resp = ActionResponse(
                action_id=action_id,
                status=ActionStatus.ACTION_ERROR,
                error=str(payload),
            )
    elif isinstance(result, bytes):
        resp = ActionResponse(
            action_id=action_id, status=ActionStatus.ACTION_OK, data_json=result
        )
    elif isinstance(result, str):
        # error string
        resp = ActionResponse(
            action_id=action_id, status=ActionStatus.ACTION_ERROR, error=result
        )
    else:
        # Result-style: Ok(bytes) or Err(str) encoded as bytes vs str
        resp = result  # type: ignore[assignment]
    env = Envelope()
    env.action_response.CopyFrom(resp)
    return env


def response_envelope(action_id: str, result) -> Envelope:
    """Public helper — mirrors ``vynkor_sdk::concurrent::response_envelope``.

    ``result`` is ``Ok(bytes)`` → ``ACTION_OK`` or ``Err(str)`` →
    ``ACTION_ERROR``. Accepts ``bytes`` (ok) or ``str`` (error) as shorthand.
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
        # Assume caller passed Result-like: (ok, value)
        raise TypeError("response_envelope expects bytes (ok) or str (error)")
    env = Envelope()
    env.action_response.CopyFrom(resp)
    return env


def _response_ok(action_id: str, data: bytes) -> Envelope:
    resp = ActionResponse(
        action_id=action_id, status=ActionStatus.ACTION_OK, data_json=data
    )
    env = Envelope()
    env.action_response.CopyFrom(resp)
    return env


def _response_err(action_id: str, error: str) -> Envelope:
    resp = ActionResponse(
        action_id=action_id, status=ActionStatus.ACTION_ERROR, error=error
    )
    env = Envelope()
    env.action_response.CopyFrom(resp)
    return env


def _not_found(action_id: str) -> List[Envelope]:
    resp = ActionResponse(
        action_id=action_id,
        status=ActionStatus.ACTION_NOT_FOUND,
        error="unknown action",
    )
    env = Envelope()
    env.action_response.CopyFrom(resp)
    return [env]


@dataclass
class PendingAction:
    """A stored ``request_<op>`` awaiting confirmation."""

    action: str
    params: bytes
    caller_plugin_id: str
    created_at: float = field(default_factory=time.monotonic)


class ConfirmationGate:
    """Plugin-side confirmation gate for one high-risk operation.

    Cheap to share behind one instance across concurrent handler tasks —
    the only interior state is the pending map behind a lock, never held
    across an ``await``.
    """

    def __init__(
        self,
        op: str,
        description: str,
        params_schema: str,
        risk,  # ActionRisk int or enum
        confirm_callers: List[str],
    ):
        _validate_op(op)
        if not description:
            raise ValueError("description must not be empty")
        if not confirm_callers:
            raise ValueError(
                "confirm_callers must name at least one caller allowed to confirm"
            )
        self._op = op
        self._description = description
        self._params_schema = params_schema
        # Normalize risk to int
        try:
            self._risk = int(risk)
        except Exception:
            self._risk = risk
        self._confirm_callers: List[str] = list(confirm_callers)
        self._pending_ttl: float = DEFAULT_PENDING_TTL
        self._pending: dict[str, PendingAction] = {}
        self._lock = threading.Lock()

    # ── Builder ───────────────────────────────────────────────────────

    def with_pending_ttl(self, ttl: float) -> "ConfirmationGate":
        """Override how long an unconfirmed pending request survives (seconds).

        Chainable — returns self.
        """
        self._pending_ttl = float(ttl)
        return self

    # ── Accessors ─────────────────────────────────────────────────────

    def op(self) -> str:
        return self._op

    @property
    def pending_ttl(self) -> float:
        return self._pending_ttl

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    # ── Manifest ──────────────────────────────────────────────────────

    def manifest_entries(self) -> Tuple[List[str], List[ActionSpec]]:
        """Manifest entries to merge into the plugin's ``PluginManifest``.

        Returns ``(actions, action_specs)`` — the two action names for
        ``actions[]`` and the two ``ActionSpec`` s for ``action_specs[]``.
        """
        request = f"request_{self._op}"
        confirm = f"confirm_{self._op}"
        actions = [request, confirm]
        specs = [
            ActionSpec(
                name=request,
                description=(
                    f"{self._description} — requests execution; the operation only "
                    "runs after an approved caller confirms (requires_confirmation)."
                ),
                params_schema=self._params_schema,
                risk=self._risk,
                requires_confirmation=True,
            ),
            ActionSpec(
                name=confirm,
                description=(
                    f"{self._description} — executes a previously requested operation; "
                    "only approved callers may invoke."
                ),
                params_schema='{"type":"object","properties":{"pending_id":{"type":"string"}},"required":["pending_id"]}',
                risk=self._risk,
                requires_confirmation=False,
            ),
        ]
        return actions, specs

    # ── Routing ───────────────────────────────────────────────────────

    async def route(
        self,
        req: ActionRequest,
        executor: Callable[[bytes], Awaitable[bytes | tuple]],
    ) -> List[Envelope]:
        """Route one inbound ``ActionRequest`` through the gate.

        - ``request_<op>`` from *any* caller → stores the params, replies
          ``{"pending_id": ..., "action": ..., "ttl_secs": ...}``.
        - ``confirm_<op>`` with ``{"pending_id": ...}`` from an allowlisted
          caller → hands the stored params to ``executor`` and replies with
          its result. From any other caller → ``PermissionDenied`` error.
        - anything else → ``ActionNotFound``.

        Returns the response envelopes for the concurrent loop — a
        sequential ``Plugin.on_message`` implementation takes the single
        element.

        ``executor`` is ``async def (params: bytes) -> bytes`` on success
        or raises / returns error string on failure. Return value is sent
        as ``data_json`` on ``ACTION_OK``, or as ``error`` on
        ``ACTION_ERROR``.
        """
        action_id = req.action_id
        op = self._op

        if req.action.startswith("request_"):
            requested = req.action[len("request_") :]
            if requested != op:
                return _not_found(action_id)
            pending_id = self._store_request(req)
            ttl_secs = int(self._pending_ttl)
            data = json.dumps(
                {"pending_id": pending_id, "action": req.action, "ttl_secs": ttl_secs}
            ).encode()
            return [_response_ok(action_id, data)]

        if req.action.startswith("confirm_"):
            confirmed = req.action[len("confirm_") :]
            if confirmed != op:
                return _not_found(action_id)
            if not self.may_confirm(req.caller_plugin_id):
                return [
                    _response_err(
                        action_id,
                        f"permission denied: caller {req.caller_plugin_id} may not confirm {op} "
                        f"(approved callers: {', '.join(self._confirm_callers)})",
                    )
                ]
            try:
                pending_id = self._parse_pending_id(req.params_json)
            except ValueError as e:
                return [_response_err(action_id, str(e))]
            try:
                pending = self._take_pending(pending_id)
            except ValueError as e:
                return [_response_err(action_id, str(e))]
            # Execute with the *stored* params, never the confirm-time ones
            try:
                result = await executor(pending.params)
                if isinstance(result, bytes):
                    return [_response_ok(action_id, result)]
                if isinstance(result, tuple) and len(result) == 2:
                    # (ok, payload) convention
                    ok, val = result
                    if ok:
                        return [_response_ok(action_id, val if isinstance(val, bytes) else str(val).encode())]
                    return [_response_err(action_id, str(val))]
                # None or other → empty ok
                if result is None:
                    return [_response_ok(action_id, b"")]
                return [_response_ok(action_id, bytes(result))]  # type: ignore[arg-type]
            except Exception as e:
                return [_response_err(action_id, str(e))]

        return _not_found(action_id)

    # ── Allowlist ─────────────────────────────────────────────────────

    def may_confirm(self, caller_plugin_id: str) -> bool:
        """Whether ``caller_plugin_id`` is on the confirm allowlist."""
        for allowed in self._confirm_callers:
            if allowed.endswith(".*"):
                prefix = allowed[:-2]
                if caller_plugin_id.startswith(prefix) and len(
                    caller_plugin_id
                ) > len(prefix) and caller_plugin_id[len(prefix)] == ".":
                    return True
            elif caller_plugin_id == allowed:
                return True
        return False

    # ── Internal ──────────────────────────────────────────────────────

    def _store_request(self, req: ActionRequest) -> str:
        with self._lock:
            self._sweep_expired_locked()
            pending_id = f"pending-{int(time.time() * 1000)}-{_next_seq()}"
            self._pending[pending_id] = PendingAction(
                action=req.action,
                params=bytes(req.params_json),
                caller_plugin_id=req.caller_plugin_id,
                created_at=time.monotonic(),
            )
            return pending_id

    def _take_pending(self, pending_id: str) -> PendingAction:
        with self._lock:
            self._sweep_expired_locked()
            pending = self._pending.pop(pending_id, None)
            if pending is None:
                raise ValueError(f"no pending {self._op} request with id {pending_id}")
            return pending

    def _sweep_expired_locked(self) -> None:
        now = time.monotonic()
        stale = [
            pid for pid, p in self._pending.items() if now - p.created_at >= self._pending_ttl
        ]
        for pid in stale:
            del self._pending[pid]

    @staticmethod
    def _parse_pending_id(params_json: bytes) -> str:
        try:
            value = json.loads(params_json) if params_json else {}
        except Exception as e:
            raise ValueError(f"invalid confirm params: {e}") from e
        pid = value.get("pending_id") if isinstance(value, dict) else None
        if not isinstance(pid, str) or not pid:
            raise ValueError("confirm params must include a string pending_id")
        return pid


# ── Caller-side helpers ───────────────────────────────────────────────


async def send_confirmation_request(client, op: str, params_json: bytes) -> str:
    """Caller-side helper for the requesting side (e.g. the AI).

    Invokes ``request_<op>`` and returns the ``pending_id`` the plugin
    assigned. Raises on non-OK status or missing ``pending_id``.
    """
    from .errors import VeyronInternal

    resp = await client.send_action(f"request_{op}", params_json, 0)
    # ActionStatus.ACTION_OK == 1 (proto3 renumbered: 0 is UNKNOWN)
    if resp.status != 1:  # ActionStatus.ACTION_OK
        # Fallback: also accept any non-error string check
        try:
            from .vynkor_protocol_pb2 import ActionStatus as _AS

            if resp.status != _AS.ACTION_OK:
                raise VeyronInternal(f"request_{op} failed: {resp.error}")
        except ImportError:
            if resp.status != 1:
                raise VeyronInternal(f"request_{op} failed: {resp.error}")
    try:
        value = json.loads(resp.data_json) if resp.data_json else {}
    except Exception as e:
        raise VeyronInternal(f"invalid pending response: {e}") from e
    pid = value.get("pending_id") if isinstance(value, dict) else None
    if not isinstance(pid, str) or not pid:
        raise VeyronInternal("pending response missing pending_id")
    return pid


async def send_confirmation(client, op: str, pending_id: str):
    """Caller-side helper for the confirming side (e.g. the user's device).

    Invokes ``confirm_<op>`` with ``pending_id``. Returns the provider's
    ``ActionResponse`` as-is — inspect ``.status`` / ``.error`` yourself.
    """
    from .errors import VeyronInternal

    try:
        params = json.dumps({"pending_id": pending_id}).encode()
    except Exception as e:
        raise VeyronInternal(f"failed to encode confirm params: {e}") from e
    return await client.send_action(f"confirm_{op}", params, 0)
