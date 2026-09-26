"""Tests del backend kcd con un servidor de socket Unix falso.

No requiere kcd instalado: el servidor habla el protocolo JSON/NDJSON real
(peticion/respuesta + stream de watch) sobre un socket temporal.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from kdeconnect_mcp.config import Config
from kdeconnect_mcp.kcd_backend import (
    KcdBackend,
    KcdCommandError,
    KcdUnavailable,
    default_socket_path,
    map_notification,
    map_notification_canceled,
    map_pair_requested,
    map_sms,
    map_telephony,
)
from kdeconnect_mcp.listener import Ingestor
from kdeconnect_mcp.models import (
    KIND_CALL,
    KIND_NOTIFICATION,
    KIND_SMS,
    SUBTYPE_INCOMING,
    SUBTYPE_MISSED,
    SUBTYPE_OUTGOING,
)


class FakeKcdServer:
    """Servidor Unix minimo que implementa el protocolo IPC de kcd."""

    def __init__(self, tmp_path: Path) -> None:
        self.socket_path = tmp_path / "kcd.sock"
        self.responses: dict[str, Any] = {"devices": []}
        self.errors: dict[str, str] = {}
        self.requests: list[dict[str, Any]] = []
        # Una lista de eventos por sesion de watch (la ultima se reutiliza).
        self.watch_sessions: list[list[dict[str, Any]]] = []
        self.close_after_watch_session: set[int] = set()
        self.watch_count = 0
        self.connection_count = 0
        self._server: asyncio.AbstractServer | None = None
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> FakeKcdServer:
        self._server = await asyncio.start_unix_server(
            self._handle, path=str(self.socket_path)
        )
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for writer in list(self._writers):
            writer.close()
        await asyncio.sleep(0)
        for writer in list(self._writers):
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        self._writers.clear()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.connection_count += 1
        self._writers.add(writer)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                request = json.loads(line)
                self.requests.append(request)
                cmd = str(request.get("cmd"))
                if cmd == "watch":
                    await self._serve_watch(reader, writer)
                    return
                if cmd in self.errors:
                    response: dict[str, Any] = {"ok": False, "error": self.errors[cmd]}
                else:
                    response = {
                        "ok": True,
                        "data": self._resolve(cmd, request.get("payload") or {}),
                    }
                writer.write(json.dumps(response).encode("utf-8") + b"\n")
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()

    def _resolve(self, cmd: str, payload: dict[str, Any]) -> Any:
        value = self.responses.get(cmd, {})
        return value(payload) if callable(value) else value

    async def _serve_watch(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        index = self.watch_count
        self.watch_count += 1
        writer.write(b'{"ok": true}\n')
        await writer.drain()
        if index < len(self.watch_sessions):
            events = self.watch_sessions[index]
        elif self.watch_sessions:
            events = self.watch_sessions[-1]
        else:
            events = []
        for event in events:
            writer.write(json.dumps(event).encode("utf-8") + b"\n")
            await writer.drain()
        if index in self.close_after_watch_session:
            return
        # Sesion longeva: se mantiene hasta que el cliente cierre el socket.
        await reader.read()


def make_watch_event(event_type: str, payload: dict[str, Any], device: str = "dev-1") -> dict:
    return {
        "type": event_type,
        "timestamp": "2026-01-01T00:00:00Z",
        "deviceId": device,
        "payload": payload,
    }


# --------------------------------------------------------------------- mapeo
def test_map_notification_exact_payload():
    raw = map_notification(
        {"appName": "Signal", "title": "Ana", "text": "hola", "requestReplyId": "r7", "id": 42},
        "dev-1",
    )
    assert raw.device_id == "dev-1"
    assert raw.kind == KIND_NOTIFICATION
    assert raw.subtype == "posted"
    assert raw.app == "Signal"
    assert raw.title == "Ana"
    assert raw.body == "hola"
    assert raw.source_id == "42"
    assert raw.meta == {"reply_id": "r7"}


def test_map_notification_without_reply_id():
    raw = map_notification({"appName": "Correo", "title": "Aviso", "id": "9"}, "dev-1")
    assert raw.meta == {}
    assert raw.body is None
    assert raw.source_id == "9"


def test_map_notification_canceled_exact_payload():
    raw = map_notification_canceled({"id": 42}, "dev-1")
    assert raw.kind == KIND_NOTIFICATION
    assert raw.subtype == "removed"
    assert raw.source_id == "42"


def test_map_sms_exact_payload():
    raw = map_sms(
        {
            "body": "Hola",
            "sender": "+34600111222",
            "date": 1_700_000_000_000,
            "type": 1,
            "thread_id": 10,
            "read": True,
            "event": "sms.incoming",
            "u_id": 5,
            "sub_id": 1,
            "addresses": [{"address": "+34600111222"}],
            "attachments": [],
        },
        "dev-1",
    )
    assert raw.kind == KIND_SMS
    assert raw.subtype == SUBTYPE_INCOMING
    assert raw.body == "Hola"
    assert raw.address == "+34600111222"
    assert raw.occurred_at == 1_700_000_000.0
    assert raw.source_id == "10:5"
    assert raw.meta["thread_id"] == 10
    assert raw.meta["uid"] == 5
    assert raw.meta["read"] is True
    assert raw.meta["addresses"] == ["+34600111222"]
    assert raw.meta["attachment_count"] == 0


@pytest.mark.parametrize(
    ("message_type", "expected"),
    [(1, SUBTYPE_INCOMING), (2, SUBTYPE_OUTGOING), (4, SUBTYPE_OUTGOING), (5, SUBTYPE_OUTGOING), (6, SUBTYPE_OUTGOING), (9, "other")],
)
def test_map_sms_type_to_subtype(message_type: int, expected: str):
    raw = map_sms({"type": message_type, "thread_id": 1, "u_id": 2}, "dev-1")
    assert raw.subtype == expected


def test_map_sms_without_uid_has_no_source_id():
    raw = map_sms({"type": 1, "date": 5_000, "sender": "+34"}, "dev-1")
    assert raw.source_id is None
    assert raw.occurred_at == 5.0
    assert raw.address == "+34"


def test_map_telephony_payloads():
    ringing = map_telephony(
        "telephony.ringing",
        {"event": "ringing", "contactName": "Mama", "phoneNumber": "+34655667788", "isCancel": False},
        "dev-1",
    )
    assert ringing.kind == KIND_CALL
    assert ringing.subtype == "ringing"
    assert ringing.contact == "Mama"
    assert ringing.address == "+34655667788"

    missed = map_telephony("telephony.missed", {"event": "missed", "phoneNumber": "+34"}, "dev-1")
    assert missed.subtype == SUBTYPE_MISSED  # alias canonico que espera el Ingestor
    assert missed.contact is None

    talking = map_telephony("telephony.talking", {"contactName": "Ana"}, "dev-1")
    assert talking.subtype == "talking"  # sin payload.event se usa el sufijo del tipo

    canceled = map_telephony(
        "telephony.canceled", {"event": "canceled", "phoneNumber": "+34", "isCancel": True}, "dev-1"
    )
    assert canceled.subtype == "canceled"


def test_map_pair_requested_exact_payload():
    raw = map_pair_requested({"name": "Pixel", "type": "phone", "cert_fp": "aa"}, "dev-2")
    assert raw.kind == "system"
    assert raw.subtype == "pair.requested"
    assert raw.meta == {"name": "Pixel", "type": "phone"}


# --------------------------------------------------------------- socket path
def test_default_socket_path_priority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KDCONNECT_SOCKET", str(tmp_path / "custom.sock"))
    assert default_socket_path() == tmp_path / "custom.sock"

    monkeypatch.delenv("KDCONNECT_SOCKET")
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    assert default_socket_path() == tmp_path / "kcd" / "kcd.sock"

    monkeypatch.delenv("XDG_RUNTIME_DIR")
    assert default_socket_path() == Path(f"/run/user/{os.getuid()}/kcd/kcd.sock")


def test_socket_path_prefers_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KDCONNECT_SOCKET", str(tmp_path / "env.sock"))
    cfg = Config(data_dir=tmp_path, kcd_socket_path=tmp_path / "config.sock")
    assert KcdBackend(cfg).socket_path == tmp_path / "config.sock"
    assert (
        KcdBackend(cfg, socket_path=tmp_path / "explicit.sock").socket_path
        == tmp_path / "explicit.sock"
    )


# ------------------------------------------------------- peticion / respuesta
def test_devices_and_command_payloads(tmp_path: Path):
    async def scenario() -> FakeKcdServer:
        server = FakeKcdServer(tmp_path)
        server.responses["devices"] = [
            {
                "id": "a",
                "name": "Pixel",
                "type": "phone",
                "state": "paired",
                "connected": True,
                "cert_fp": "aa",
                "last_seen": 1_700_000_000,
            },
            {
                "id": "b",
                "name": "Tablet",
                "type": "tablet",
                "state": "unpaired",
                "connected": False,
                "cert_fp": "bb",
                "last_seen": None,
            },
        ]
        await server.start()
        backend = KcdBackend(socket_path=server.socket_path)
        try:
            await backend.connect()
            devices = await backend.list_devices()
            assert [(d.id, d.name, d.type) for d in devices] == [
                ("a", "Pixel", "phone"),
                ("b", "Tablet", "tablet"),
            ]
            assert devices[0].paired is True and devices[0].reachable is True
            assert devices[0].last_seen == 1_700_000_000.0
            assert devices[1].paired is False and devices[1].reachable is False

            paired = await backend.list_devices(only_paired=True)
            assert [d.id for d in paired] == ["a"]
            reachable = await backend.list_devices(
                only_reachable=True, only_paired=False
            )
            assert [d.id for d in reachable] == ["a"]
            unpaired = await backend.list_devices(include_unpaired=True)
            assert [d.id for d in unpaired] == ["a", "b"]
            cached = backend.cached_device("a")
            assert cached is not None and cached.name == "Pixel"

            await backend.request_pair("b")
            await backend.request_pair("b", accept=True)
            await backend.request_pair("b", accept=False)
            await backend.unpair("b")
            await backend.dismiss_notification("a", "42")
            await backend.reply_notification("a", "r7", "hola")
            await backend.send_sms("a", "+34600111222", "mensaje")
        finally:
            await backend.close()
            await server.stop()
        return server

    server = asyncio.run(scenario())
    requests = server.requests
    assert requests[0] == {"cmd": "devices"}  # devices va sin payload
    commands = [request for request in requests if request["cmd"] != "devices"]
    assert commands == [
        {"cmd": "pair", "payload": {"deviceId": "b"}},
        {"cmd": "pair", "payload": {"deviceId": "b", "accept": True}},
        {"cmd": "pair", "payload": {"deviceId": "b", "reject": True}},
        {"cmd": "unpair", "payload": {"deviceId": "b"}},
        {"cmd": "notify_dismiss", "payload": {"deviceId": "a", "notificationId": "42"}},
        {"cmd": "notify_reply", "payload": {"deviceId": "a", "replyId": "r7", "message": "hola"}},
        {
            "cmd": "send_sms",
            "payload": {"deviceId": "a", "phoneNumber": "+34600111222", "message": "mensaje"},
        },
    ]


def test_request_conversations_sends_ipc(tmp_path: Path):
    async def scenario() -> None:
        server = FakeKcdServer(tmp_path)
        server.responses["devices"] = [
            {
                "id": "a",
                "name": "Pixel",
                "type": "phone",
                "state": "paired",
                "connected": True,
                "cert_fp": "aa",
                "last_seen": 1_700_000_000,
            },
        ]
        await server.start()
        backend = KcdBackend(socket_path=server.socket_path)
        try:
            await backend.connect()
            assert await backend.request_conversations("a") == ["a"]
            assert await backend.request_conversations() == ["a"]
        finally:
            await backend.close()
            await server.stop()
        return server

    server = asyncio.run(scenario())
    commands = [r for r in server.requests if r["cmd"] == "sms_request_conversations"]
    assert commands == [
        {"cmd": "sms_request_conversations", "payload": {"deviceId": "a"}},
        {"cmd": "sms_request_conversations", "payload": {"deviceId": "a"}},
    ]


def test_command_error_raises(tmp_path: Path):
    async def scenario() -> None:
        server = FakeKcdServer(tmp_path)
        server.errors["pair"] = "device not found"
        await server.start()
        backend = KcdBackend(socket_path=server.socket_path)
        try:
            await backend.connect()
            with pytest.raises(KcdCommandError, match="device not found"):
                await backend.request_pair("ghost")
        finally:
            await backend.close()
            await server.stop()

    asyncio.run(scenario())


def test_connect_missing_socket_raises(tmp_path: Path):
    async def scenario() -> None:
        backend = KcdBackend(socket_path=tmp_path / "nope.sock")
        with pytest.raises(KcdUnavailable):
            await backend.connect()
        with pytest.raises(KcdUnavailable):
            await backend.list_devices()

    asyncio.run(scenario())


# --------------------------------------------------------------------- watch
def test_watch_maps_events_and_ignores_irrelevant(tmp_path: Path):
    async def scenario() -> tuple[FakeKcdServer, list, list]:
        server = FakeKcdServer(tmp_path)
        server.responses["devices"] = [
            {
                "id": "dev-1",
                "name": "Pixel",
                "type": "phone",
                "state": "paired",
                "connected": True,
                "cert_fp": "aa",
                "last_seen": None,
            }
        ]
        server.watch_sessions = [
            [
                make_watch_event(
                    "state.snapshot",
                    {"devices": [{"id": "dev-1", "state": "paired", "connected": True}]},
                ),
                make_watch_event(
                    "device.connected",
                    {"name": "Pixel", "type": "phone", "state": "paired", "connected": True},
                ),
                make_watch_event("battery.state", {"level": 90}),
                make_watch_event(
                    "notification",
                    {"appName": "Signal", "title": "Ana", "text": "hola", "requestReplyId": "r7", "id": 42},
                ),
                make_watch_event("notification.canceled", {"id": 42}),
                make_watch_event(
                    "sms.incoming",
                    {
                        "body": "Hola",
                        "sender": "+34600111222",
                        "date": 1_700_000_000_000,
                        "type": 1,
                        "thread_id": 10,
                        "read": True,
                        "u_id": 5,
                        "addresses": [{"address": "+34600111222"}],
                        "attachments": [],
                    },
                ),
                make_watch_event(
                    "telephony.ringing",
                    {"event": "ringing", "contactName": "Mama", "phoneNumber": "+34655667788", "isCancel": False},
                ),
                make_watch_event(
                    "pair.requested", {"name": "Nuevo", "type": "phone"}, device="dev-2"
                ),
            ]
        ]
        await server.start()
        backend = KcdBackend(socket_path=server.socket_path)
        events: list = []
        devices: list = []
        received = asyncio.Event()

        def on_event(raw) -> None:
            events.append(raw)
            if len(events) >= 5:
                received.set()

        await backend.subscribe(on_event, devices.append)
        try:
            await asyncio.wait_for(received.wait(), timeout=3)
        finally:
            await backend.close()
            await server.stop()
        return server, events, devices

    server, events, devices = asyncio.run(scenario())
    assert server.watch_count == 1

    notif, canceled, sms, call, pair = events
    assert notif.kind == KIND_NOTIFICATION and notif.subtype == "posted"
    assert (notif.app, notif.title, notif.body) == ("Signal", "Ana", "hola")
    assert notif.source_id == "42" and notif.meta == {"reply_id": "r7"}

    assert canceled.kind == KIND_NOTIFICATION
    assert canceled.subtype == "removed"
    assert canceled.source_id == "42"

    assert sms.kind == KIND_SMS and sms.subtype == SUBTYPE_INCOMING
    assert sms.address == "+34600111222"
    assert sms.occurred_at == 1_700_000_000.0
    assert sms.source_id == "10:5"
    assert sms.meta["addresses"] == ["+34600111222"]

    assert call.kind == KIND_CALL and call.subtype == "ringing"
    assert call.contact == "Mama" and call.address == "+34655667788"

    assert pair.kind == "system" and pair.subtype == "pair.requested"
    assert pair.device_id == "dev-2" and pair.meta["name"] == "Nuevo"

    # subscribe anuncia los emparejados, el watch reanuncia y device.connected actualiza.
    assert len(devices) == 3
    assert all(device.id == "dev-1" for device in devices)
    assert devices[-1].reachable is True and devices[-1].paired is True


def test_watch_reconnects_after_server_disconnect(tmp_path: Path):
    async def scenario() -> tuple[FakeKcdServer, list]:
        server = FakeKcdServer(tmp_path)
        server.watch_sessions = [
            [make_watch_event("notification", {"appName": "A", "title": "uno", "text": "x", "id": 1})],
            [make_watch_event("notification", {"appName": "A", "title": "dos", "text": "y", "id": 2})],
        ]
        server.close_after_watch_session = {0}
        await server.start()
        backend = KcdBackend(socket_path=server.socket_path)
        backend._reconnect_min = 0.01
        backend._reconnect_max = 0.02
        events: list = []
        received = asyncio.Event()

        def on_event(raw) -> None:
            events.append(raw)
            if len(events) >= 2:
                received.set()

        await backend.subscribe(on_event)
        try:
            await asyncio.wait_for(received.wait(), timeout=3)
        finally:
            await backend.close()
            await server.stop()
        return server, events

    server, events = asyncio.run(scenario())
    assert server.watch_count >= 2
    assert [event.source_id for event in events] == ["1", "2"]


def test_watch_backoff_defaults():
    backend = KcdBackend()
    assert backend._reconnect_min == 1.0
    assert backend._reconnect_max == 30.0


def test_close_cancels_watch(tmp_path: Path):
    async def scenario() -> None:
        server = FakeKcdServer(tmp_path)
        server.responses["devices"] = []
        await server.start()
        backend = KcdBackend(socket_path=server.socket_path)
        await backend.subscribe(lambda raw: None)
        task = backend._watch_task
        assert task is not None and not task.done()
        await backend.close()
        assert task.done()
        await server.stop()

    asyncio.run(scenario())


# --------------------------------------------------------- efectos en el store
def test_notification_canceled_marks_store_removed(tmp_path: Path):
    """notification.canceled debe llegar al store como mark_notification_removed."""
    cfg = Config(data_dir=tmp_path)
    cfg.ensure_dirs()
    store = Mock()
    store.mark_notification_removed.return_value = 1
    ingestor = Ingestor(cfg, store, Mock(), b"secret")

    raw = KcdBackend.map_event("notification.canceled", {"id": 42}, "dev-1")
    assert raw is not None
    outcome = ingestor.handle(raw)

    assert outcome.status == "removed"
    store.mark_notification_removed.assert_called_once_with("dev-1", "42")


def test_fetch_active_and_sync_return_empty():
    async def scenario() -> None:
        backend = KcdBackend()
        assert await backend.fetch_active_notifications(["dev-1"]) == []
        assert await backend.sync_conversations(wait_seconds=0.0) == []

    asyncio.run(scenario())
