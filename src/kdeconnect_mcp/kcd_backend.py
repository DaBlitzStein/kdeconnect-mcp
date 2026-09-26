"""Cliente del daemon kcd (IPC por socket Unix, JSON por linea).

kcd es un daemon Go headless que implementa el protocolo KDE Connect v8 y
expone un socket Unix con peticiones/respuestas JSON y un stream NDJSON para
`watch`. Sustituye a la conexion DBus (dbus_backend.py) manteniendo su API
publica, pero sin depender de dbus-next.

Protocolo (docs/IPC_PROTOCOL.md de kcd):
  - peticion:  {"cmd": "...", "payload": {...}}\\n
  - respuesta: {"ok": true, "data": ...}\\n o {"ok": false, "error": "..."}\\n
  - watch:     {"cmd": "watch"} responde {"ok": true} y despues emite NDJSON
               con envelope {"type", "timestamp", "deviceId", "payload"}.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import (
    KIND_CALL,
    KIND_NOTIFICATION,
    KIND_SMS,
    SUBTYPE_INCOMING,
    SUBTYPE_MISSED,
    SUBTYPE_OUTGOING,
    Device,
    RawEvent,
)

log = logging.getLogger(__name__)

# models.py no define (todavia) un kind para eventos de sistema/pairing.
KIND_SYSTEM = "system"

_SOCKET_DIR_NAME = "kcd"
_SOCKET_NAME = "kcd.sock"

# Backoff del watch: 1s -> 30s (configurable por instancia para los tests).
WATCH_RECONNECT_MIN = 1.0
WATCH_RECONNECT_MAX = 30.0

# Timeout de una peticion/respuesta normal; evita colgarse si kcd se atasca.
DEFAULT_REQUEST_TIMEOUT = 10.0

EventCallback = Callable[[RawEvent], Any]
DeviceCallback = Callable[[Device], Any]


class KcdError(RuntimeError):
    """Error generico hablando con kcd."""


class KcdUnavailable(KcdError):
    """kcd no esta corriendo o el socket no responde."""


class KcdCommandError(KcdError):
    """kcd respondio {"ok": false, "error": ...} a un comando."""


class KcdProtocolError(KcdError):
    """Respuesta de kcd con forma inesperada (no JSON o no dict)."""


class KcdTransportError(KcdUnavailable):
    """La conexion con kcd se perdio a mitad de una peticion (reintentable)."""


# Compatibilidad con el nombre que usa el backend DBus: los callers pueden
# capturar la misma clase al cambiar de backend.
KdeConnectUnavailable = KcdUnavailable


def default_socket_path() -> Path:
    """Ruta del socket de kcd: KDCONNECT_SOCKET > XDG_RUNTIME_DIR > /run/user/<uid>."""
    override = os.environ.get("KDCONNECT_SOCKET")
    if override:
        return Path(override).expanduser()
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(runtime) / _SOCKET_DIR_NAME / _SOCKET_NAME


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def _parse_last_seen(value: Any) -> float | None:
    """Normaliza last_seen (epoch s/ms o ISO-8601) a epoch seconds."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        stamp = float(value)
        return stamp / 1000.0 if stamp > 1e12 else stamp
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except ValueError:
        return None


def _is_paired(data: dict[str, Any], fallback: Device | None) -> bool:
    state = str(data.get("state") or "").strip().lower()
    if state:
        return state in {"paired", "trusted", "accepted"}
    if "paired" in data:
        return bool(data["paired"])
    return fallback.paired if fallback is not None else False


def device_from_data(
    device_id: str,
    data: dict[str, Any],
    *,
    fallback: Device | None = None,
    default_reachable: bool = False,
) -> Device:
    """Convierte una entrada de `devices`/evento de dispositivo en un Device.

    Los campos ausentes se heredan de `fallback` (cache local), para que un
    device.disconnected no borre nombre/tipo conocidos.
    """
    if data.get("connected") is not None:
        reachable = bool(data["connected"])
    elif "reachable" in data:
        reachable = bool(data["reachable"])
    else:
        reachable = default_reachable
    name = data.get("name")
    dtype = data.get("type")
    return Device(
        id=device_id,
        name=str(name) if name is not None else (fallback.name if fallback else ""),
        type=str(dtype) if dtype is not None else (fallback.type if fallback else ""),
        paired=_is_paired(data, fallback),
        reachable=reachable,
        last_seen=_parse_last_seen(data.get("last_seen"))
        if data.get("last_seen") is not None
        else (fallback.last_seen if fallback else None),
    )


# --------------------------------------------------------------------- mapeo
def map_notification(payload: dict[str, Any], device_id: str) -> RawEvent:
    reply_id = payload.get("requestReplyId")
    meta = {"reply_id": reply_id} if reply_id is not None else {}
    return RawEvent(
        device_id=device_id,
        kind=KIND_NOTIFICATION,
        subtype="posted",
        app=_text(payload.get("appName")),
        title=_text(payload.get("title")),
        body=_text(payload.get("text")),
        source_id=_text(payload.get("id")),
        meta=meta,
    )


def map_notification_canceled(payload: dict[str, Any], device_id: str) -> RawEvent:
    """Retirada de notificacion: el store la procesa via mark_notification_removed."""
    return RawEvent(
        device_id=device_id,
        kind=KIND_NOTIFICATION,
        subtype="removed",
        source_id=_text(payload.get("id")),
    )


def map_sms(payload: dict[str, Any], device_id: str) -> RawEvent:
    message_type = payload.get("type")
    if message_type == 1:
        subtype = SUBTYPE_INCOMING
    elif message_type in (2, 4, 5, 6):  # sent, outbox, failed, queued
        subtype = SUBTYPE_OUTGOING
    else:
        subtype = "other"

    addresses = [
        str(item["address"])
        for item in (payload.get("addresses") or [])
        if isinstance(item, dict) and item.get("address")
    ]
    sender = payload.get("sender")
    address = str(sender) if sender else (addresses[0] if addresses else None)

    date = payload.get("date")
    occurred_at = float(date) / 1000.0 if date else None

    thread_id = payload.get("thread_id")
    u_id = payload.get("u_id")
    # Misma convencion que dbus_backend: "thread:uid" estable para dedup.
    source_id = f"{thread_id}:{u_id}" if u_id is not None else None

    return RawEvent(
        device_id=device_id,
        kind=KIND_SMS,
        subtype=subtype,
        body=_text(payload.get("body")),
        address=address,
        occurred_at=occurred_at,
        source_id=source_id,
        meta={
            "thread_id": thread_id,
            "uid": u_id,
            "event_field": payload.get("event"),
            "read": payload.get("read"),
            "attachment_count": len(payload.get("attachments") or []),
            "addresses": addresses,
        },
    )


def _normalize_call_subtype(event: Any) -> str:
    if not event:
        return "unknown"
    name = str(event).strip()
    if name.lower().replace("-", "_") in {"missed", "missedcall", "missed_call"}:
        return SUBTYPE_MISSED
    return name


def map_telephony(event_type: str, payload: dict[str, Any], device_id: str) -> RawEvent:
    event = payload.get("event")
    if not event and "." in event_type:
        event = event_type.split(".", 1)[1]
    subtype = _normalize_call_subtype(event)
    contact = payload.get("contactName")
    number = payload.get("phoneNumber")
    return RawEvent(
        device_id=device_id,
        kind=KIND_CALL,
        subtype=subtype,
        contact=_text(contact),
        address=_text(number),
        meta={"event": event},
    )


def map_pair_requested(payload: dict[str, Any], device_id: str) -> RawEvent:
    # Whitelist: la verificationKey y el cert_fp no se persisten (PII/seguridad).
    return RawEvent(
        device_id=device_id,
        kind=KIND_SYSTEM,
        subtype="pair.requested",
        meta={
            "name": _text(payload.get("name")),
            "type": _text(payload.get("type")),
        },
    )


class KcdBackend:
    """Backend kcd con la misma API publica que KdeConnectBackend (DBus)."""

    def __init__(
        self,
        config: Any | None = None,
        *,
        socket_path: str | Path | None = None,
    ) -> None:
        self.config = config
        configured = getattr(config, "kcd_socket_path", None) if config is not None else None
        if socket_path is not None:
            self.socket_path = Path(socket_path)
        elif configured is not None:
            self.socket_path = Path(configured)
        else:
            self.socket_path = default_socket_path()

        self.request_timeout = DEFAULT_REQUEST_TIMEOUT
        self._request_reader: asyncio.StreamReader | None = None
        self._request_writer: asyncio.StreamWriter | None = None
        self._request_lock = asyncio.Lock()

        self._watch_reader: asyncio.StreamReader | None = None
        self._watch_writer: asyncio.StreamWriter | None = None
        self._watch_task: asyncio.Task | None = None
        self._watch_acked = False
        self._reconnect_min = WATCH_RECONNECT_MIN
        self._reconnect_max = WATCH_RECONNECT_MAX

        self._on_event: EventCallback | None = None
        self._on_device: DeviceCallback | None = None
        self._devices: dict[str, Device] = {}

    @staticmethod
    def default_socket_path() -> Path:
        """Espejo a nivel de clase de `default_socket_path()`."""
        return default_socket_path()

    # -------------------------------------------------------------- lifecycle
    async def connect(self) -> None:
        await self._ensure_connection()

    async def close(self) -> None:
        task = self._watch_task
        self._watch_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                log.debug("error esperando al watch de kcd", exc_info=True)
        for writer in (self._watch_writer, self._request_writer):
            await self._close_writer(writer)
        self._watch_reader = self._watch_writer = None
        self._request_reader = self._request_writer = None

    @staticmethod
    async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
        if writer is None:
            return
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            log.debug("error cerrando socket de kcd", exc_info=True)

    # ------------------------------------------------------------------ comms
    async def _ensure_connection(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        writer = self._request_writer
        if writer is not None and not writer.is_closing() and self._request_reader is not None:
            return self._request_reader, writer
        try:
            reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        except (OSError, ValueError) as exc:
            raise KcdUnavailable(
                f"No se puede conectar al socket de kcd en {self.socket_path}: {exc}"
            ) from exc
        self._request_reader, self._request_writer = reader, writer
        return reader, writer

    def _drop_request_connection(self) -> None:
        writer = self._request_writer
        self._request_reader = self._request_writer = None
        if writer is not None:
            writer.close()

    async def _request(self, cmd: str, payload: dict[str, Any] | None = None) -> Any:
        async with self._request_lock:
            last_exc: KcdUnavailable | None = None
            for attempt in range(2):
                reader, writer = await self._ensure_connection()
                message: dict[str, Any] = {"cmd": cmd}
                if payload:
                    message["payload"] = payload
                try:
                    writer.write((json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8"))
                    await writer.drain()
                except (ConnectionError, OSError) as exc:
                    self._drop_request_connection()
                    last_exc = KcdTransportError(f"kcd no acepta la peticion {cmd}: {exc}")
                    continue
                try:
                    return await self._read_response(cmd, reader)
                except KcdTransportError as exc:
                    last_exc = exc
                    if attempt == 0:
                        log.debug("reintento de %s tras perdida de conexion", cmd)
                        continue
                    raise
            assert last_exc is not None
            raise last_exc

    async def _read_response(self, cmd: str, reader: asyncio.StreamReader) -> Any:
        try:
            line = await asyncio.wait_for(reader.readline(), self.request_timeout)
        except TimeoutError as exc:
            self._drop_request_connection()
            raise KcdUnavailable(f"kcd no respondio a {cmd} en {self.request_timeout}s") from exc
        except (ConnectionError, OSError) as exc:
            self._drop_request_connection()
            raise KcdTransportError(f"conexion con kcd rota durante {cmd}: {exc}") from exc
        if not line:
            self._drop_request_connection()
            raise KcdTransportError(f"kcd cerro la conexion durante {cmd}")
        response = self._parse_response(line, cmd)
        if not response.get("ok"):
            raise KcdCommandError(str(response.get("error") or f"{cmd} fallo en kcd"))
        return response.get("data")

    def _parse_response(self, line: bytes, cmd: str) -> dict[str, Any]:
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            self._drop_request_connection()
            raise KcdProtocolError(f"respuesta no JSON de kcd a {cmd}: {line[:120]!r}") from exc
        if not isinstance(response, dict):
            self._drop_request_connection()
            raise KcdProtocolError(f"respuesta de kcd a {cmd} sin forma de objeto")
        return response

    # ---------------------------------------------------------------- devices
    async def list_devices(
        self,
        *,
        only_reachable: bool = False,
        only_paired: bool = False,
        include_unpaired: bool | None = None,
    ) -> list[Device]:
        """Lista dispositivos conocidos por kcd.

        `include_unpaired` es azucar sobre `only_paired` (False = trae todos),
        para los callers que usan esa convencion.
        """
        data = await self._request("devices")
        devices: list[Device] = []
        for item in data or []:
            if not isinstance(item, dict):
                continue
            device_id = item.get("id") or item.get("deviceId")
            if not device_id:
                continue
            device = device_from_data(str(device_id), item)
            self._devices[device.id] = device
            devices.append(device)
        if include_unpaired is not None:
            only_paired = not include_unpaired
        if only_paired:
            devices = [device for device in devices if device.paired]
        if only_reachable:
            devices = [device for device in devices if device.reachable]
        return devices

    async def request_pair(self, device_id: str, *, accept: bool | None = None) -> None:
        """Pide emparejar (accept=None) o responde a una solicitud entrante."""
        payload: dict[str, Any] = {"deviceId": device_id}
        if accept is True:
            payload["accept"] = True
        elif accept is False:
            payload["reject"] = True
        await self._request("pair", payload)

    async def unpair(self, device_id: str) -> None:
        await self._request("unpair", {"deviceId": device_id})

    async def request_conversations(self, device_id: str | None = None) -> list[str]:
        """Pide al movil sus conversaciones (kcd no las empuja por su cuenta).

        Los mensajes llegan despues como eventos `sms.incoming` por el watch.
        Devuelve los ids de dispositivo a los que se pidio.
        """
        if device_id:
            targets = [device_id]
        else:
            devices = await self.list_devices(only_paired=True, only_reachable=True)
            targets = [device.id for device in devices]
        requested: list[str] = []
        for target in targets:
            try:
                await self._request("sms_request_conversations", {"deviceId": target})
            except KcdError as exc:
                log.warning("kcd no acepto sms_request_conversations para %s: %s", target, exc)
                continue
            requested.append(target)
        return requested

    # ----------------------------------------------------------------- acciones
    async def dismiss_notification(self, device_id: str, notification_id: str) -> None:
        await self._request(
            "notify_dismiss",
            {"deviceId": device_id, "notificationId": notification_id},
        )

    async def reply_notification(self, device_id: str, reply_id: str, message: str) -> None:
        await self._request(
            "notify_reply",
            {"deviceId": device_id, "replyId": reply_id, "message": message},
        )

    async def send_sms(self, device_id: str, phone_number: str, message: str) -> None:
        await self._request(
            "send_sms",
            {"deviceId": device_id, "phoneNumber": phone_number, "message": message},
        )

    # ---------------------------------------------------------------- subscribe
    async def subscribe(
        self, on_event: EventCallback, on_device: DeviceCallback | None = None
    ) -> None:
        self._on_event = on_event
        self._on_device = on_device
        await self.connect()
        try:
            await self._announce_devices()
        except KcdError as exc:
            log.warning("kcd no devolvio la lista de dispositivos al suscribir: %s", exc)
        if self._watch_task is None or self._watch_task.done():
            self._watch_task = asyncio.ensure_future(self._watch_loop())

    async def _announce_devices(self) -> None:
        for device in await self.list_devices(only_reachable=True, only_paired=True):
            await self._dispatch_device(device)

    # ------------------------------------------------------------------- watch
    async def _watch_loop(self) -> None:
        delay = self._reconnect_min
        while True:
            self._watch_acked = False
            try:
                await self._watch_session()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - el watch debe sobrevivir a todo
                log.warning("watch de kcd caido: %s", exc)
            if self._watch_acked:
                delay = self._reconnect_min
            await asyncio.sleep(delay)
            delay = min(delay * 2, self._reconnect_max)

    async def _watch_session(self) -> None:
        try:
            reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        except (OSError, ValueError) as exc:
            raise KcdUnavailable(
                f"No se puede conectar al socket de kcd en {self.socket_path}: {exc}"
            ) from exc
        self._watch_reader, self._watch_writer = reader, writer
        try:
            writer.write(b'{"cmd": "watch"}\n')
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), self.request_timeout)
            if not line:
                raise KcdUnavailable("kcd cerro el stream de watch antes del ack")
            response = self._parse_response(line, "watch")
            if not response.get("ok"):
                raise KcdCommandError(str(response.get("error") or "watch rechazado"))
            self._watch_acked = True
            log.info("watch de kcd conectado (%s)", self.socket_path)
            try:
                await self._announce_devices()
            except KcdError as exc:
                log.warning("kcd no devolvio la lista de dispositivos: %s", exc)
            while True:
                line = await reader.readline()
                if not line:
                    raise KcdUnavailable("kcd cerro el stream de watch")
                envelope = self._parse_envelope(line)
                if envelope is not None:
                    await self._handle_watch_envelope(envelope)
        finally:
            self._watch_reader = self._watch_writer = None
            await self._close_writer(writer)

    def _parse_envelope(self, line: bytes) -> dict[str, Any] | None:
        try:
            envelope = json.loads(line)
        except json.JSONDecodeError:
            log.warning("evento de watch no JSON ignorado: %r", line[:120])
            return None
        if not isinstance(envelope, dict):
            log.warning("evento de watch no-objeto ignorado: %r", line[:120])
            return None
        return envelope

    async def _handle_watch_envelope(self, envelope: dict[str, Any]) -> None:
        event_type = str(envelope.get("type") or "")
        raw_payload = envelope.get("payload")
        payload = raw_payload if isinstance(raw_payload, dict) else {}
        device_id = str(envelope.get("deviceId") or payload.get("deviceId") or "")

        # El snapshot inicial no se usa: los dispositivos se refrescan con
        # `devices` al (re)conectar el watch.
        if event_type == "state.snapshot":
            log.debug("state.snapshot de kcd recibido; se ignora")
            return
        if event_type in ("device.connected", "device.disconnected"):
            connected = event_type == "device.connected"
            device = device_from_data(
                device_id,
                payload,
                fallback=self._devices.get(device_id),
                default_reachable=connected,
            )
            self._devices[device.id] = device
            await self._dispatch_device(device)
            return

        raw = self.map_event(event_type, payload, device_id)
        if raw is None:
            log.debug("evento de kcd ignorado: type=%s", event_type)
            return
        await self._dispatch_event(raw)

    @staticmethod
    def map_event(
        event_type: str, payload: dict[str, Any], device_id: str
    ) -> RawEvent | None:
        """Mapea un evento de watch a RawEvent (None = irrelevante)."""
        if event_type == "notification":
            return map_notification(payload, device_id)
        if event_type == "notification.canceled":
            return map_notification_canceled(payload, device_id)
        if event_type == "sms.incoming":
            return map_sms(payload, device_id)
        if event_type.startswith("telephony."):
            return map_telephony(event_type, payload, device_id)
        if event_type == "pair.requested":
            return map_pair_requested(payload, device_id)
        return None

    async def _dispatch_event(self, raw: RawEvent) -> None:
        callback = self._on_event
        if callback is None:
            return
        result = callback(raw)
        if inspect.isawaitable(result):
            await result

    async def _dispatch_device(self, device: Device) -> None:
        callback = self._on_device
        if callback is None:
            return
        result = callback(device)
        if inspect.isawaitable(result):
            await result

    # ------------------------------------------------------------- live helpers
    async def fetch_active_notifications(
        self, device_ids: list[str] | None = None
    ) -> list[RawEvent]:
        """kcd no mantiene cache de notificaciones activas: siempre []."""
        log.debug(
            "kcd no cachea notificaciones activas; fetch_active_notifications devuelve [] "
            "(device_ids=%s)",
            device_ids,
        )
        return []

    async def sync_conversations(self, wait_seconds: float = 5.0) -> list[RawEvent]:
        """kcd no guarda historial de conversaciones: siempre []."""
        log.info(
            "kcd no almacena historial de conversaciones; sync_conversations devuelve [] "
            "(wait_seconds=%.1f se ignora)",
            wait_seconds,
        )
        return []

    # ----------------------------------------------------------------- utilities
    def cached_device(self, device_id: str) -> Device | None:
        """Ultimo estado conocido del dispositivo (util para tools de solo lectura)."""
        return self._devices.get(device_id)
