"""Backend simulado: genera eventos de un movil ficticio sin KDE Connect.

Util para desarrollo, demos y tests. Pasa por el mismo pipeline de redaccion
y almacenamiento que el backend real.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .models import (
    KIND_CALL,
    KIND_NOTIFICATION,
    KIND_SMS,
    SUBTYPE_INCOMING,
    SUBTYPE_MISSED,
    SUBTYPE_RINGING,
    Device,
    RawEvent,
)

FAKE_DEVICE = Device(
    id="fake-phone",
    name="Pixel de Prueba",
    type="phone",
    paired=True,
    reachable=True,
)


def script_events() -> list[RawEvent]:
    """Eventos deterministas que cubren los casos de PII."""
    return [
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_SMS,
            subtype=SUBTYPE_INCOMING,
            body="Recordatorio: tu cita es manana a las 10:00.",
            address="+34600123456",
            source_id="101:1",
            meta={"thread_id": 101, "uid": 1, "addresses": ["+34600123456"]},
        ),
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_SMS,
            subtype=SUBTYPE_INCOMING,
            body="BBVA: Tu codigo de autorizacion es 483920. No lo compartas con nadie.",
            address="+34911223344",
            source_id="102:2",
            meta={"thread_id": 102, "uid": 2},
        ),
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_NOTIFICATION,
            subtype="posted",
            app="Google Authenticator",
            title="Ana (cuenta personal)",
            body="Codigo de verificacion: 918273",
            source_id="9001",
            meta={"ticker": "Tu codigo de autorizacion es 555111"},
        ),
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_NOTIFICATION,
            subtype="posted",
            app="BBVA",
            title="Compra con tarjeta",
            body="Compra de 1.234,56 EUR con la tarjeta terminada en 4567.",
            source_id="9002",
        ),
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_NOTIFICATION,
            subtype="posted",
            app="Correos",
            title="Entrega pendiente",
            body="Tu codigo de entrega es 445566. Muestralo al repartidor.",
            source_id="9003",
        ),
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_NOTIFICATION,
            subtype="posted",
            app="Banco",
            title="Transferencia recibida",
            body="Abono en cuenta ES91 2100 0418 4502 0005 1332 por 250,00 EUR.",
            source_id="9004",
        ),
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_NOTIFICATION,
            subtype="posted",
            app="Amazon",
            title="Tu pedido",
            body="El pedido 407-1234567-8901234 va en camino.",
            source_id="9005",
        ),
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_NOTIFICATION,
            subtype="posted",
            app="WhatsApp",
            title="Ana",
            body="¿Comemos el jueves?",
            source_id="9006",
        ),
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_NOTIFICATION,
            subtype="removed",
            source_id="9006",
        ),
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_CALL,
            subtype=SUBTYPE_RINGING,
            contact="Mama",
            address="+34655667788",
        ),
        RawEvent(
            device_id=FAKE_DEVICE.id,
            kind=KIND_CALL,
            subtype=SUBTYPE_MISSED,
            contact="Mama",
            address="+34655667788",
        ),
    ]


class FakeBackend:
    def __init__(self, config: Any | None = None, delay: float = 0.05) -> None:
        self.config = config
        self.delay = delay
        self._on_event = None
        self._on_device = None
        self._task: asyncio.Task | None = None

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None

    async def list_devices(self, **_kwargs: Any) -> list[Device]:
        return [FAKE_DEVICE]

    async def subscribe(self, on_event, on_device=None) -> None:
        self._on_event = on_event
        self._on_device = on_device
        if on_device is not None:
            on_device(FAKE_DEVICE)
        self._task = asyncio.ensure_future(self._run())

    async def _run(self) -> None:
        try:
            for event in script_events():
                if self._on_event is not None:
                    self._on_event(event)
                await asyncio.sleep(self.delay)
        except asyncio.CancelledError:
            pass

    async def fetch_active_notifications(
        self, device_ids: list[str] | None = None
    ) -> list[RawEvent]:
        if device_ids and FAKE_DEVICE.id not in device_ids:
            return []
        removed = {e.source_id for e in script_events() if e.subtype == "removed"}
        return [
            e
            for e in script_events()
            if e.kind == KIND_NOTIFICATION and e.subtype == "posted" and e.source_id not in removed
        ]

    async def sync_conversations(self, wait_seconds: float = 0.0) -> list[RawEvent]:
        return [e for e in script_events() if e.kind == KIND_SMS]
