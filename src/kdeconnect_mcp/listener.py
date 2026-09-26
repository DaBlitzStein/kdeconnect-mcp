"""Listener kcd (socket Unix): convierte eventos del movil en filas SQLite ya redactadas."""

from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config
from .models import (
    KIND_CALL,
    KIND_NOTIFICATION,
    KIND_SMS,
    SUBTYPE_MISSED,
    Device,
    RawEvent,
)
from .pii import Redactor
from .store import Store, compute_content_hash

log = logging.getLogger(__name__)

_TEXT_META_KEYS = ("ticker", "title", "body", "text", "conversation_title", "group_name")


def acquire_lock(path: str | Path):
    """Lock exclusivo no bloqueante; devuelve el fichero o None si ya hay listener."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # El fichero debe quedar abierto mientras el proceso es dueno del lock.
    handle = open(path, "w", encoding="utf-8")  # noqa: SIM115
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def probe_lock(path: str | Path) -> bool:
    """Indica si OTRO proceso mantiene el flock de `path` sin truncarlo ni retenerlo.

    Abre el fichero (O_RDWR|O_CREAT, sin truncar), intenta el flock exclusivo
    no bloqueante y lo libera si lo consigue. El fd se cierra siempre; si el
    fichero no se puede abrir se asume que no hay listener externo.
    """
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def load_secret(data_dir: str | Path) -> bytes:
    """Clave HMAC estable por instalacion (para hashes de deduplicacion)."""
    path = Path(data_dir) / "secret.key"
    if path.is_file():
        return path.read_bytes()
    secret = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(secret)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return secret


@dataclass(slots=True)
class IngestOutcome:
    status: str  # inserted | duplicate | merged | removed | skipped
    event_id: int | None = None


class Ingestor:
    """Redacta y persiste eventos. Unico punto de entrada a la base de datos."""

    def __init__(self, config: Config, store: Store, redactor: Redactor, secret: bytes) -> None:
        self.cfg = config
        self.store = store
        self.redactor = redactor
        self.secret = secret

    # ------------------------------------------------------------------ rules
    def _should_capture(self, raw: RawEvent) -> bool:
        capture = self.cfg.capture
        if raw.kind == KIND_SMS and not capture.sms:
            return False
        if raw.kind == KIND_CALL and not capture.calls:
            return False
        if raw.kind == KIND_NOTIFICATION and not capture.notifications:
            return False
        if raw.kind == KIND_NOTIFICATION and raw.subtype == "posted":
            app = (raw.app or "").casefold()
            if any(ignored and ignored in app for ignored in capture.ignore_apps):
                return False
            body = raw.body or raw.title or ""
            if len(body) < capture.min_body_chars:
                return False
        return True

    @staticmethod
    def _event_key(raw: RawEvent, content_hash: str | None, secret: bytes) -> str:
        if raw.kind == KIND_NOTIFICATION:
            return f"notif:{raw.device_id}:{raw.source_id or '-'}:{content_hash or '-'}"
        if raw.kind == KIND_SMS:
            if raw.source_id:
                return f"sms:{raw.device_id}:{raw.source_id}:{content_hash or '-'}"
            occurred = int(raw.occurred_at or time.time())
            return f"sms:{raw.device_id}:{occurred}:{content_hash or '-'}"
        address_hash = (compute_content_hash(secret, raw.address) or "-")[:16]
        stamp = int((raw.occurred_at or time.time()) * 1000)
        return f"call:{raw.device_id}:{raw.subtype}:{stamp}:{address_hash}"

    def sanitize_contact(self, contact: str | None) -> str | None:
        """KDE Connect envia el numero como contactName si no esta en agenda."""
        if not contact:
            return contact
        if len(re.sub(r"\D", "", contact)) >= 9:
            return self.redactor.mask_phone(contact)
        return self.redactor.redact(contact).text

    def sanitize_meta(self, meta: dict[str, Any] | None) -> dict[str, Any]:
        """Redacta/maskea valores sensibles dentro de meta (defensa en profundidad)."""
        clean: dict[str, Any] = {}
        for key, value in (meta or {}).items():
            if key in ("addresses", "address"):
                if isinstance(value, (list, tuple)):
                    clean[key] = [self.redactor.mask_phone(str(item)) for item in value]
                elif isinstance(value, str):
                    clean[key] = self.redactor.mask_phone(value)
                else:
                    clean[key] = value
            elif key in _TEXT_META_KEYS and isinstance(value, str):
                clean[key] = self.redactor.redact(value).text
            else:
                clean[key] = value
        return clean

    # ----------------------------------------------------------------- handle
    def handle(self, raw: RawEvent) -> IngestOutcome:
        if not self._should_capture(raw):
            return IngestOutcome("skipped")

        if raw.kind == KIND_NOTIFICATION and raw.subtype == "removed" and raw.source_id:
            changed = self.store.mark_notification_removed(raw.device_id, raw.source_id)
            return IngestOutcome("removed" if changed else "skipped")
        if raw.kind == KIND_NOTIFICATION and raw.subtype == "all_removed":
            self.store.mark_all_notifications_removed(raw.device_id)
            return IngestOutcome("removed")

        fields, redactions = self.redactor.redact_fields(
            app=raw.app,
            title=raw.title,
            body=raw.body,
            ticker=raw.ticker,
        )
        title = fields.get("title") or fields.get("ticker")
        body = fields.get("body")
        address = self.redactor.mask_phone(raw.address)
        content_hash = compute_content_hash(self.secret, raw.title, raw.body, raw.ticker)
        event_key = self._event_key(raw, content_hash, self.secret)

        if raw.kind == KIND_CALL and raw.subtype == SUBTYPE_MISSED:
            existing = self.store.find_recent_call(raw.device_id, address)
            if existing is not None:
                self.store.update_event(existing["id"], subtype=SUBTYPE_MISSED)
                return IngestOutcome("merged", existing["id"])

        event_id, inserted = self.store.insert_event(
            event_key=event_key,
            device_id=raw.device_id,
            kind=raw.kind,
            subtype=raw.subtype,
            app=raw.app,
            title=title,
            body=body,
            contact=self.sanitize_contact(raw.contact),
            address=address,
            occurred_at=raw.occurred_at,
            source_id=raw.source_id,
            redactions=redactions,
            content_hash=content_hash,
            meta=self.sanitize_meta(raw.meta),
        )
        outcome = "inserted" if inserted else "duplicate"
        log.info(
            "ingesta kind=%s subtype=%s device=%s app=%s redacciones=%s [%s]",
            raw.kind,
            raw.subtype,
            raw.device_id,
            raw.app,
            redactions or "-",
            outcome,
        )
        return IngestOutcome(outcome, event_id)


class Listener:
    def __init__(
        self,
        config: Config,
        store: Store,
        backend: Any,
        ingestor: Ingestor,
    ) -> None:
        self.cfg = config
        self.store = store
        self.backend = backend
        self.ingestor = ingestor
        self._stop = asyncio.Event()
        self._poll_task: asyncio.Task[None] | None = None

    async def run(self) -> None:
        delay = 1.0
        while not self._stop.is_set():
            try:
                await self.backend.connect()
                await self.backend.subscribe(self._on_raw_event, self._on_device)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - cualquier fallo del backend se reintenta
                log.warning("backend no disponible (%s); reintento en %.0fs", exc, delay)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except TimeoutError:
                    pass
                delay = min(delay * 2.0, 30.0)
                continue
            log.info("listener activo (backend=%s)", type(self.backend).__name__)
            self._poll_task = asyncio.ensure_future(self._sms_poll_loop())
            await self._stop.wait()
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            return

    async def _sms_poll_loop(self) -> None:
        """kcd no empuja los SMS: pide conversaciones al conectar y cada N segundos."""
        requester = getattr(self.backend, "request_conversations", None)
        interval = max(0, int(getattr(self.cfg.capture, "sms_poll_seconds", 0) or 0))
        if not self.cfg.capture.sms or interval <= 0 or requester is None:
            return
        await asyncio.sleep(min(10.0, float(interval)))
        while not self._stop.is_set():
            try:
                requested = await requester()
                if requested:
                    log.debug("poll SMS: conversaciones pedidas a %s", requested)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - el poll no debe tumbar el listener
                log.warning("poll de SMS fallo: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=float(interval))
            except TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()

    def _on_raw_event(self, raw: RawEvent) -> None:
        try:
            self.ingestor.handle(raw)
        except Exception:
            log.exception("fallo al ingerir evento kind=%s device=%s", raw.kind, raw.device_id)

    def _on_device(self, device: Device) -> None:
        try:
            self.store.upsert_device(
                device.id,
                name=device.name,
                dtype=device.type,
                paired=device.paired,
                reachable=device.reachable,
                last_seen=time.time() if device.reachable else None,
            )
        except Exception:
            log.exception("fallo al guardar dispositivo %s", device.id)
