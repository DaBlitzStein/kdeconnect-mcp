"""Modelos de eventos normalizados.

Un `RawEvent` lleva texto sin redactar y solo vive en memoria: el pipeline de
ingesta lo convierte en un `StoredEvent` redactado antes de tocar SQLite.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

KIND_NOTIFICATION = "notification"
KIND_SMS = "sms"
KIND_CALL = "call"

SUBTYPE_INCOMING = "incoming"
SUBTYPE_OUTGOING = "outgoing"
SUBTYPE_RINGING = "ringing"
SUBTYPE_MISSED = "missedCall"


@dataclass
class RawEvent:
    """Evento tal y como sale del movil, SIN redactar."""

    device_id: str
    kind: str
    subtype: str | None = None
    app: str | None = None
    title: str | None = None
    body: str | None = None
    ticker: str | None = None
    contact: str | None = None
    address: str | None = None
    occurred_at: float | None = None
    source_id: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Device:
    id: str
    name: str = ""
    type: str = ""
    paired: bool = False
    reachable: bool = False
    last_seen: float | None = None
