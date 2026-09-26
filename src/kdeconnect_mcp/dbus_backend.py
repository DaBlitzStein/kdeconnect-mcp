"""Cliente DBus para KDE Connect (org.kde.kdeconnect).

Interfaces verificadas contra kdeconnect-kde master / v24.02:
  - daemon:        /modules/kdeconnect              org.kde.kdeconnect.daemon
  - device:        /modules/kdeconnect/devices/<id> org.kde.kdeconnect.device
  - telephony:     .../telephony                    org.kde.kdeconnect.device.telephony
                   signal callReceived(event, number, contactName)
  - notifications: .../notifications                org.kde.kdeconnect.device.notifications
                   signals notificationPosted/Removed/Updated(publicId)
  - notification:  .../notifications/<publicId>      org.kde.kdeconnect.device.notifications.notification
  - sms:           .../sms                          org.kde.kdeconnect.device.sms
  - conversations: .../sms                          org.kde.kdeconnect.device.conversations
                   signal conversationUpdated(QDBusVariant<struct>)
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from dbus_next import BusType, Message, Variant
from dbus_next.aio import MessageBus
from dbus_next.errors import DBusError

from .models import (
    KIND_CALL,
    KIND_NOTIFICATION,
    KIND_SMS,
    SUBTYPE_INCOMING,
    SUBTYPE_OUTGOING,
    Device,
    RawEvent,
)

log = logging.getLogger(__name__)

DAEMON_SERVICE = "org.kde.kdeconnect"
DAEMON_PATH = "/modules/kdeconnect"
DAEMON_IFACE = "org.kde.kdeconnect.daemon"
DEVICE_IFACE = "org.kde.kdeconnect.device"
PROPS_IFACE = "org.freedesktop.DBus.Properties"
TELEPHONY_IFACE = "org.kde.kdeconnect.device.telephony"
NOTIFICATIONS_IFACE = "org.kde.kdeconnect.device.notifications"
NOTIFICATION_IFACE = "org.kde.kdeconnect.device.notifications.notification"
SMS_IFACE = "org.kde.kdeconnect.device.sms"
CONVERSATIONS_IFACE = "org.kde.kdeconnect.device.conversations"

BASE_DEVICE_PATH = "/modules/kdeconnect/devices"

EventCallback = Callable[[RawEvent], None]
DeviceCallback = Callable[[Device], None]


class KdeConnectUnavailable(RuntimeError):
    """El servicio org.kde.kdeconnect no responde en el bus de sesion."""


def _unwrap(value: Any) -> Any:
    while isinstance(value, Variant):
        value = value.value
    return value


def parse_conversation_message(value: Any) -> dict[str, Any] | None:
    """Normaliza un ConversationMessage (struct o dict) a un dict plano.

    Struct segun conversationsdbusinterface: (event, body, addresses, date,
    type, read, threadID, uID, subID, attachments).
    """
    value = _unwrap(value)
    data: dict[str, Any] = {}
    if isinstance(value, (list, tuple)):
        if len(value) < 8:
            log.warning("ConversationMessage con %d campos; se ignora", len(value))
            return None
        fields = [
            "event_field",
            "body",
            "addresses",
            "date",
            "type",
            "read",
            "thread_id",
            "uid",
            "sub_id",
            "attachments",
        ]
        for name, item in zip(fields, value):
            data[name] = _unwrap(item)
    elif isinstance(value, dict):
        lookup = {
            "event_field": ("event_field", "eventField", "event"),
            "body": ("body",),
            "addresses": ("addresses",),
            "date": ("date",),
            "type": ("type",),
            "read": ("read",),
            "thread_id": ("thread_id", "threadID", "threadId"),
            "uid": ("uid", "uID", "uId"),
            "sub_id": ("sub_id", "subID", "subId"),
            "attachments": ("attachments",),
        }
        for target, keys in lookup.items():
            for key in keys:
                if key in value:
                    data[target] = _unwrap(value[key])
                    break
    else:
        log.warning("ConversationMessage con forma no soportada: %s", type(value).__name__)
        return None

    addresses = data.get("addresses") or []
    parsed_addresses: list[str] = []
    for address in addresses:
        address = _unwrap(address)
        if isinstance(address, (list, tuple)) and address:
            parsed_addresses.append(str(_unwrap(address[0])))
        elif isinstance(address, dict):
            parsed_addresses.append(str(address.get("address", "")))
        elif isinstance(address, str):
            parsed_addresses.append(address)
    data["addresses"] = [a for a in parsed_addresses if a]
    return data


class KdeConnectBackend:
    def __init__(self, config: Any | None = None) -> None:
        self.config = config
        self.bus: MessageBus | None = None
        self.daemon: Any | None = None
        self._proxies: dict[tuple[str, str], Any] = {}
        self._on_event: EventCallback | None = None
        self._on_device: DeviceCallback | None = None
        self._subscribed_devices: set[str] = set()
        self._tasks: set[asyncio.Task] = set()

    # -------------------------------------------------------------- lifecycle
    async def connect(self) -> None:
        try:
            self.bus = await MessageBus(bus_type=BusType.SESSION).connect()
        except Exception as exc:
            raise KdeConnectUnavailable(f"No hay bus de sesion DBus: {exc}") from exc
        try:
            proxy = await self._proxy(DAEMON_SERVICE, DAEMON_PATH)
            self.daemon = proxy.get_interface(DAEMON_IFACE)
            if self.daemon is None:
                raise KdeConnectUnavailable("Interfaz del daemon no encontrada")
        except DBusError as exc:
            raise KdeConnectUnavailable(
                "KDE Connect no esta corriendo (servicio org.kde.kdeconnect ausente)"
            ) from exc

    async def close(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()
        if self.bus is not None:
            try:
                self.bus.disconnect()
            except Exception:
                log.debug("error cerrando el bus DBus", exc_info=True)
            self.bus = None

    # ------------------------------------------------------------------ proxy
    async def _proxy(self, service: str, path: str) -> Any:
        key = (service, path)
        if key in self._proxies:
            return self._proxies[key]
        assert self.bus is not None
        introspection = await self.bus.introspect(service, path)
        proxy = self.bus.get_proxy_object(service, path, introspection)
        self._proxies[key] = proxy
        return proxy

    async def _props(self, service: str, path: str, interface: str) -> dict[str, Any]:
        """Lee todas las propiedades de una interfaz via org.freedesktop.DBus.Properties."""
        assert self.bus is not None
        message = Message(
            destination=service,
            path=path,
            interface=PROPS_IFACE,
            member="GetAll",
            signature="s",
            body=[interface],
        )
        reply = await self.bus.call(message)
        if reply.message_type.name == "ERROR":
            raise DBusError(reply.error_name, reply.body)
        raw = reply.body[0] if reply.body else {}
        return {name: _unwrap(value) for name, value in raw.items()}

    @staticmethod
    def _device_path(device_id: str) -> str:
        return f"{BASE_DEVICE_PATH}/{device_id}"

    # ------------------------------------------------------------------ devices
    async def list_devices(
        self, *, only_reachable: bool = False, only_paired: bool = False
    ) -> list[Device]:
        assert self.daemon is not None
        device_ids = await self.daemon.call_devices(only_reachable, only_paired)
        result: list[Device] = []
        for device_id in device_ids:
            try:
                props = await self._props(
                    DAEMON_SERVICE, self._device_path(device_id), DEVICE_IFACE
                )
            except DBusError:
                continue
            result.append(
                Device(
                    id=device_id,
                    name=str(props.get("name", device_id)),
                    type=str(props.get("type", "")),
                    paired=bool(props.get("isPaired", False)),
                    reachable=bool(props.get("isReachable", False)),
                )
            )
        return result

    async def request_pair(self, device_id: str) -> None:
        proxy = await self._proxy(DAEMON_SERVICE, self._device_path(device_id))
        iface = proxy.get_interface(DEVICE_IFACE)
        if iface is None:
            raise KdeConnectUnavailable(f"Dispositivo {device_id} sin interfaz device")
        await iface.call_request_pair()

    # ---------------------------------------------------------------- subscribe
    async def subscribe(
        self, on_event: EventCallback, on_device: DeviceCallback | None = None
    ) -> None:
        self._on_event = on_event
        self._on_device = on_device
        assert self.daemon is not None
        self.daemon.on_device_added(lambda did, name: self._spawn(self._on_device_added(did)))
        self.daemon.on_device_removed(lambda did: self._spawn(self._on_device_removed(did)))
        self.daemon.on_device_visibility_changed(
            lambda did, visible: self._spawn(self._on_device_added(did)) if visible else None
        )
        self.daemon.on_device_list_changed(
            lambda: self._spawn(self._refresh_devices())
        )
        await self._refresh_devices()

    async def _refresh_devices(self) -> None:
        for device in await self.list_devices(only_reachable=True, only_paired=True):
            if device.id in self._subscribed_devices:
                continue
            await self._subscribe_device(device)

    async def _on_device_added(self, device_id: str) -> None:
        try:
            devices = await self.list_devices(only_reachable=True, only_paired=True)
        except DBusError:
            return
        for device in devices:
            if device.id == device_id and device_id not in self._subscribed_devices:
                await self._subscribe_device(device)

    async def _on_device_removed(self, device_id: str) -> None:
        self._subscribed_devices.discard(device_id)
        for key in [k for k in self._proxies if k[1].startswith(self._device_path(device_id))]:
            self._proxies.pop(key, None)
        if self._on_device is not None:
            self._on_device(Device(id=device_id, reachable=False))

    async def _subscribe_device(self, device: Device) -> None:
        self._subscribed_devices.add(device.id)
        if self._on_device is not None:
            self._on_device(device)
        await self._subscribe_telephony(device.id)
        await self._subscribe_notifications(device.id)
        await self._subscribe_conversations(device.id)

    def _spawn(self, coro: Awaitable[Any]) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # --------------------------------------------------------------- telephony
    async def _subscribe_telephony(self, device_id: str) -> None:
        try:
            proxy = await self._proxy(
                DAEMON_SERVICE, f"{self._device_path(device_id)}/telephony"
            )
        except DBusError:
            return
        iface = proxy.get_interface(TELEPHONY_IFACE)
        if iface is None:
            return
        iface.on_call_received(
            lambda event, number, contact: self._emit_call(device_id, event, number, contact)
        )

    def _emit_call(
        self, device_id: str, event: str, number: str | None, contact: str | None
    ) -> None:
        if self._on_event is None:
            return
        self._on_event(
            RawEvent(
                device_id=device_id,
                kind=KIND_CALL,
                subtype=str(event or "unknown"),
                contact=contact or None,
                address=number or None,
                meta={"event": event},
            )
        )

    # ----------------------------------------------------------- notifications
    async def _subscribe_notifications(self, device_id: str) -> None:
        try:
            proxy = await self._proxy(
                DAEMON_SERVICE, f"{self._device_path(device_id)}/notifications"
            )
        except DBusError:
            return
        iface = proxy.get_interface(NOTIFICATIONS_IFACE)
        if iface is None:
            return
        iface.on_notification_posted(
            lambda public_id: self._spawn(self._emit_notification(device_id, public_id))
        )
        iface.on_notification_updated(
            lambda public_id: self._spawn(self._emit_notification(device_id, public_id))
        )
        iface.on_notification_removed(
            lambda public_id: self._emit_notification_removed(device_id, public_id)
        )
        iface.on_all_notifications_removed(
            lambda: self._emit_all_notifications_removed(device_id)
        )
        try:
            for public_id in await iface.call_active_notifications():
                await self._emit_notification(device_id, public_id)
        except DBusError:
            pass

    async def _notification_event(self, device_id: str, public_id: str) -> RawEvent | None:
        path = f"{self._device_path(device_id)}/notifications/{public_id}"
        try:
            props = await self._props(DAEMON_SERVICE, path, NOTIFICATION_IFACE)
        except DBusError:
            return None
        title = props.get("title") or props.get("ticker") or None
        body = props.get("text") or None
        app = props.get("appName") or None
        # No incluir aqui campos de texto (ticker, conversationTitle...): van
        # por title/body y se redactan; este meta lo sanea tambien el ingestor.
        meta = {
            "internal_id": props.get("internalId"),
            "dismissable": props.get("dismissable", props.get("isClearable")),
            "reply_id": props.get("replyId"),
            "silent": props.get("silent"),
        }
        return RawEvent(
            device_id=device_id,
            kind=KIND_NOTIFICATION,
            subtype="posted",
            app=str(app) if app else None,
            title=str(title) if title else None,
            body=str(body) if body else None,
            ticker=str(props.get("ticker")) if props.get("ticker") else None,
            source_id=str(public_id),
            meta={k: v for k, v in meta.items() if v is not None},
        )

    async def _emit_notification(self, device_id: str, public_id: str) -> None:
        if self._on_event is None:
            return
        event = await self._notification_event(device_id, public_id)
        if event is not None:
            self._on_event(event)

    def _emit_notification_removed(self, device_id: str, public_id: str) -> None:
        if self._on_event is None:
            return
        self._on_event(
            RawEvent(
                device_id=device_id,
                kind=KIND_NOTIFICATION,
                subtype="removed",
                source_id=str(public_id),
            )
        )

    def _emit_all_notifications_removed(self, device_id: str) -> None:
        if self._on_event is None:
            return
        self._on_event(
            RawEvent(
                device_id=device_id,
                kind=KIND_NOTIFICATION,
                subtype="all_removed",
            )
        )

    # ------------------------------------------------------------- conversations
    async def _subscribe_conversations(self, device_id: str) -> None:
        try:
            proxy = await self._proxy(DAEMON_SERVICE, f"{self._device_path(device_id)}/sms")
        except DBusError:
            return
        iface = proxy.get_interface(CONVERSATIONS_IFACE)
        if iface is None:
            return
        iface.on_conversation_updated(
            lambda variant: self._emit_conversation(device_id, variant)
        )
        iface.on_conversation_created(
            lambda variant: self._emit_conversation(device_id, variant)
        )
        sms_iface = proxy.get_interface(SMS_IFACE)
        if sms_iface is not None:
            try:
                await sms_iface.call_request_all_conversations()
            except DBusError:
                pass

    @staticmethod
    def _conversation_event(device_id: str, message: dict[str, Any]) -> RawEvent | None:
        message_type = message.get("type")
        if message_type == 1:
            subtype = SUBTYPE_INCOMING
        elif message_type in (2, 4, 5, 6):
            subtype = SUBTYPE_OUTGOING
        else:
            subtype = "other"
        addresses = message.get("addresses") or []
        date = message.get("date")
        uid = message.get("uid")
        thread_id = message.get("thread_id")
        return RawEvent(
            device_id=device_id,
            kind=KIND_SMS,
            subtype=subtype,
            body=str(message.get("body") or "") or None,
            address=addresses[0] if addresses else None,
            occurred_at=(float(date) / 1000.0) if date else None,
            source_id=f"{thread_id}:{uid}" if uid is not None else None,
            meta={
                "thread_id": thread_id,
                "uid": uid,
                "event_field": message.get("event_field"),
                "read": message.get("read"),
                "attachment_count": len(message.get("attachments") or []),
                "addresses": addresses,
            },
        )

    def _emit_conversation(self, device_id: str, variant: Any) -> None:
        if self._on_event is None:
            return
        message = parse_conversation_message(variant)
        if not message:
            return
        event = self._conversation_event(device_id, message)
        if event is not None:
            self._on_event(event)

    # ------------------------------------------------------------ live helpers
    async def fetch_active_notifications(
        self, device_ids: list[str] | None = None
    ) -> list[RawEvent]:
        devices = await self.list_devices(only_reachable=True, only_paired=True)
        result: list[RawEvent] = []
        for device in devices:
            if device_ids and device.id not in device_ids:
                continue
            try:
                proxy = await self._proxy(
                    DAEMON_SERVICE, f"{self._device_path(device.id)}/notifications"
                )
                iface = proxy.get_interface(NOTIFICATIONS_IFACE)
                if iface is None:
                    continue
                for public_id in await iface.call_active_notifications():
                    event = await self._notification_event(device.id, public_id)
                    if event is not None:
                        result.append(event)
            except DBusError:
                continue
        return result

    async def sync_conversations(self, wait_seconds: float = 5.0) -> list[RawEvent]:
        devices = await self.list_devices(only_reachable=True, only_paired=True)
        proxies: list[tuple[str, Any]] = []
        for device in devices:
            try:
                proxy = await self._proxy(
                    DAEMON_SERVICE, f"{self._device_path(device.id)}/sms"
                )
            except DBusError:
                continue
            sms_iface = proxy.get_interface(SMS_IFACE)
            if sms_iface is not None:
                try:
                    await sms_iface.call_request_all_conversations()
                except DBusError:
                    pass
            proxies.append((device.id, proxy))
        if wait_seconds > 0:
            await asyncio.sleep(wait_seconds)
        events: list[RawEvent] = []
        for device_id, proxy in proxies:
            iface = proxy.get_interface(CONVERSATIONS_IFACE)
            if iface is None:
                continue
            try:
                conversations = await iface.call_active_conversations()
            except DBusError:
                continue
            for variant in conversations:
                message = parse_conversation_message(variant)
                if not message:
                    continue
                event = self._conversation_event(device_id, message)
                if event is not None:
                    events.append(event)
        return events
