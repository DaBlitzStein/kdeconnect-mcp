"""Servidor MCP (stdio) que expone la actividad del movil a agentes.

Diseno:
  - Un listener DBus (hilo aparte) captura eventos y los guarda redactados.
  - Las tools solo leen SQLite; las que hablan con el movil usan una conexion
    DBus efimera para no acoplarse al listener.
  - Toda salida vuelve a pasar por el redactor (defensa en profundidad).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any

from mcp.server.mcpserver import MCPServer

from .backends import (
    BACKEND_UNAVAILABLE,
    backend_label,
    build_backend,
    with_live_backend,
)
from .config import Config
from .fake_backend import FakeBackend
from .listener import Ingestor, Listener, acquire_lock, load_secret
from .models import KIND_CALL, KIND_NOTIFICATION, RawEvent
from .pii import Redactor
from .store import Store

log = logging.getLogger(__name__)

INSTRUCTIONS = """\
Servidor KDE Connect para agentes, con proteccion de PII.

Fuente de datos: un movil Android emparejado con KDE Connect en este escritorio
(plugins Notifications, SMS y Telephony activos). Expone llamadas, SMS y
notificaciones.

PII: los codigos de autorizacion/OTP, numeros de tarjeta, IBAN y telefonos se
redactan ANTES de guardarse. Veras marcadores como [REDACTADO:otp],
[REDACTADO:card], [REDACTADO:iban] o telefonos enmascarados (***678). Esos
valores no existen en la base de datos: no intentes recuperarlos ni pedirlos.
Los nombres de contacto y de app si son visibles.

Herramientas:
- get_status: estado del listener y de la captura.
- list_devices: dispositivos conocidos.
- get_activity: timeline (filtra por kind=sms|call|notification, app, tiempo).
- get_events: consumo incremental por cursor (after_id) del log de eventos.
- wait_for_events: long-poll hasta que llegue algo nuevo tras after_id.
- search_activity: busqueda de texto sobre lo redactado.
- get_conversation: hilo de SMS por telefono/contacto.
- get_call_log: historial de llamadas.
- list_active_notifications: notificaciones activas en el movil ahora.
- acknowledge_events: marca eventos como leidos.
- get_redaction_stats: cuantas redacciones por categoria.
- sync_sms_history: pide al movil sus conversaciones cacheadas.
- scan_devices / request_pair: emparejamiento (lanzar solicitud; el movil confirma).
- accept_pairing / reject_pairing: responder a una solicitud entrante (backend kcd).
"""


class Runtime:
    def __init__(self, cfg: Config) -> None:
        cfg.ensure_dirs()
        self.cfg = cfg
        self.redactor = Redactor(cfg.redaction)
        self.store = Store(cfg.db_path)
        self.secret = load_secret(cfg.data_dir)
        self.ingestor = Ingestor(cfg, self.store, self.redactor, self.secret)
        self._lock_handle = None
        self._thread: threading.Thread | None = None
        self._backend: Any = None
        self.backend_error: str | None = None
        self.started = False

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self.started:
            return
        self.started = True
        self._lock_handle = acquire_lock(self.cfg.lock_path)
        if self._lock_handle is None:
            log.info("Ya hay un listener activo; este proceso solo lee la base de datos.")
            return
        self._backend = build_backend(self.cfg)
        self._thread = threading.Thread(
            target=self._thread_main, name="kdeconnect-listener", daemon=True
        )
        self._thread.start()

    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        listener = Listener(self.cfg, self.store, self._backend, self.ingestor)
        try:
            loop.run_until_complete(listener.run())
        except BACKEND_UNAVAILABLE as exc:
            self.backend_error = str(exc)
            log.warning("Backend no disponible: %s", exc)
        except Exception as exc:
            self.backend_error = repr(exc)
            log.exception("listener detenido por error")
        finally:
            if self._backend is not None:
                try:
                    loop.run_until_complete(self._backend.close())
                except Exception:
                    log.debug("error cerrando el backend", exc_info=True)
            loop.close()

    # ------------------------------------------------------------- egress PII
    def present(self, event: dict[str, Any]) -> dict[str, Any]:
        for field in ("title", "body", "contact"):
            value = event.get(field)
            if value:
                event[field] = self.redactor.redact(value, app=event.get("app")).text
        if event.get("address"):
            event["address"] = self.redactor.mask_phone(event["address"])
        if event.get("meta"):
            event["meta"] = self.ingestor.sanitize_meta(event["meta"])
        return event

    def present_raw(self, raw: RawEvent) -> dict[str, Any]:
        fields, categories = self.redactor.redact_fields(
            app=raw.app, title=raw.title, body=raw.body, ticker=raw.ticker
        )
        return {
            "device_id": raw.device_id,
            "kind": raw.kind,
            "subtype": raw.subtype,
            "app": raw.app,
            "title": fields.get("title") or fields.get("ticker"),
            "body": fields.get("body"),
            "contact": (self.redactor.redact(raw.contact, app=raw.app).text if raw.contact else None),
            "address": self.redactor.mask_phone(raw.address),
            "occurred_at": raw.occurred_at,
            "received_at": time.time(),
            "source_id": raw.source_id,
            "meta": self.ingestor.sanitize_meta(raw.meta),
            "redactions": categories,
            "live": True,
        }

    def status(self) -> dict[str, Any]:
        stats = self.store.stats()
        owned = self._lock_handle is not None
        alive = bool(self._thread and self._thread.is_alive())
        external = False
        if not owned:
            probe = acquire_lock(self.cfg.lock_path)
            if probe is None:
                external = True
            else:
                probe.close()
        return {
            "server": "kdeconnect-mcp",
            "data_dir": str(self.cfg.data_dir),
            "db_path": str(self.cfg.db_path),
            "config_path": str(self.cfg.config_path) if self.cfg.config_path else "(defaults)",
            "backend": backend_label(self.cfg),
            "fake_backend": self.cfg.fake,
            "listener_owned": owned,
            "listener_alive": alive,
            "listener_external": external,
            "listener_active": bool(owned or alive or external),
            "listener_note": (
                "listener systemd activo (externo a este proceso)"
                if external
                else ("listener propio activo" if alive else "sin listener")
            ),
            "last_event_id": self.store.latest_event_id(),
            "last_event_at": self.store.last_event_at(),
            "backend_error": self.backend_error,
            "capture": {
                "sms": self.cfg.capture.sms,
                "calls": self.cfg.capture.calls,
                "notifications": self.cfg.capture.notifications,
                "ignore_apps": self.cfg.capture.ignore_apps,
            },
            "redaction": {
                "enabled": self.cfg.redaction.enabled,
                "phone_mode": self.cfg.redaction.phone.mode,
                "keywords": len(self.cfg.redaction.keywords),
                "sensitive_apps": self.cfg.redaction.sensitive_apps,
            },
            "stats": stats,
        }


def create_server(cfg: Config) -> MCPServer:
    runtime = Runtime(cfg)
    runtime.start()

    server = MCPServer(
        "kdeconnect-mcp",
        instructions=INSTRUCTIONS,
        log_level=cfg.log_level.upper(),
    )
    server.runtime = runtime  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ read
    @server.tool()
    def get_status() -> dict[str, Any]:
        """Estado del servidor: listener, configuracion de captura/PII y conteos."""
        return runtime.status()

    @server.tool()
    def list_devices() -> dict[str, Any]:
        """Dispositivos moviles vistos por el listener (desde la base de datos)."""
        devices = runtime.store.list_devices()
        return {"count": len(devices), "devices": devices}

    @server.tool()
    def get_activity(
        kind: str | None = None,
        device_id: str | None = None,
        app: str | None = None,
        since_minutes: int = 1440,
        limit: int = 50,
        offset: int = 0,
        unread_only: bool = False,
    ) -> dict[str, Any]:
        """Timeline unificado de actividad ya redactada.

        kind: 'sms', 'call' o 'notification' (None = todo).
        app: filtro parcial por nombre de app (ej. 'whatsapp').
        since_minutes: ventana temporal hacia atras (0 = sin limite).
        unread_only: solo eventos no reconocidos.
        """
        since = time.time() - since_minutes * 60 if since_minutes and since_minutes > 0 else None
        events = runtime.store.query_events(
            kind=kind,
            device_id=device_id,
            app=app,
            since=since,
            limit=limit,
            offset=offset,
            unacked_only=unread_only,
        )
        return {
            "count": len(events),
            "events": [runtime.present(event) for event in events],
            "pii_note": "Contenido ya redactado; [REDACTADO:*] no es recuperable.",
        }

    @server.tool()
    def get_events(
        after_id: int = 0, limit: int = 100, kind: str | None = None
    ) -> dict[str, Any]:
        """Consumo incremental por cursor: eventos con id > after_id, en orden de llegada.

        Devuelve next_after_id para la siguiente llamada (patron de stream/log).
        Las retiradas de notificacion actualizan la fila y no se reemiten.
        """
        events = runtime.store.get_events_after(after_id, limit=limit, kind=kind)
        next_after_id = events[-1]["id"] if events else after_id
        return {
            "count": len(events),
            "after_id": after_id,
            "next_after_id": next_after_id,
            "latest_id": runtime.store.latest_event_id(),
            "events": [runtime.present(e) for e in events],
        }

    @server.tool()
    async def wait_for_events(
        after_id: int = 0,
        timeout_seconds: float = 30.0,
        kind: str | None = None,
    ) -> dict[str, Any]:
        """Long-poll: espera (hasta timeout_seconds) a que haya eventos con id > after_id.

        Recomendado para consumo en vivo: guarda next_after_id y vuelvelo a pasar.
        """
        deadline = time.time() + max(1.0, min(float(timeout_seconds), 300.0))
        events: list[dict[str, Any]] = []
        while True:
            events = runtime.store.get_events_after(after_id, limit=100, kind=kind)
            if events or time.time() >= deadline:
                break
            await asyncio.sleep(0.5)
        next_after_id = events[-1]["id"] if events else after_id
        return {
            "count": len(events),
            "after_id": after_id,
            "next_after_id": next_after_id,
            "latest_id": runtime.store.latest_event_id(),
            "timed_out": not events,
            "events": [runtime.present(e) for e in events],
        }

    @server.tool()
    def search_activity(query: str, kind: str | None = None, limit: int = 50) -> dict[str, Any]:
        """Busca texto en titulo/cuerpo/app/contacto sobre lo ya redactado."""
        events = runtime.store.search_events(query, kind=kind, limit=limit)
        return {"count": len(events), "query": query, "events": [runtime.present(e) for e in events]}

    @server.tool()
    def get_conversation(
        address: str | None = None, contact: str | None = None, limit: int = 50
    ) -> dict[str, Any]:
        """Hilo de SMS filtrado por telefono (parcial) o nombre de contacto."""
        events = runtime.store.conversation(address=address, contact=contact, limit=limit)
        events.reverse()
        return {"count": len(events), "events": [runtime.present(e) for e in events]}

    @server.tool()
    def get_call_log(
        days: int = 7, only_missed: bool = False, limit: int = 50
    ) -> dict[str, Any]:
        """Historial de llamadas. only_missed=True para perdidas."""
        since = time.time() - days * 86400 if days > 0 else None
        events = runtime.store.query_events(
            kind=KIND_CALL,
            since=since,
            limit=limit,
            subtype="missedCall" if only_missed else None,
        )
        return {"count": len(events), "events": [runtime.present(e) for e in events]}

    @server.tool()
    async def list_active_notifications(device_id: str | None = None) -> dict[str, Any]:
        """Notificaciones activas en el movil ahora mismo (via DBus, redactadas)."""
        ids = [device_id] if device_id else None
        if runtime.cfg.fake:
            raws = await FakeBackend(runtime.cfg).fetch_active_notifications(ids)
            return {
                "source": "fake",
                "count": len(raws),
                "notifications": [runtime.present_raw(raw) for raw in raws],
            }
        if backend_label(runtime.cfg) == "kcd":
            events = runtime.store.query_events(kind=KIND_NOTIFICATION, limit=100)
            return {
                "source": "cache",
                "warning": "kcd no expone notificaciones activas; usa get_activity (captura en vivo).",
                "count": len(events),
                "notifications": [runtime.present(e) for e in events],
            }
        try:
            raws = await with_live_backend(
                runtime.cfg, lambda backend: backend.fetch_active_notifications(ids)
            )
        except BACKEND_UNAVAILABLE as exc:
            events = runtime.store.query_events(kind=KIND_NOTIFICATION, limit=100)
            return {
                "source": "cache",
                "warning": str(exc),
                "count": len(events),
                "notifications": [runtime.present(e) for e in events],
            }
        return {
            "source": "live",
            "count": len(raws),
            "notifications": [runtime.present_raw(raw) for raw in raws],
        }

    @server.tool()
    def acknowledge_events(
        ids: list[int] | None = None,
        before_minutes: int | None = None,
        kind: str | None = None,
    ) -> dict[str, Any]:
        """Marca eventos como reconocidos, por ids o por antiguedad."""
        before = None
        if before_minutes is not None:
            before = time.time() - before_minutes * 60
        if not ids and before is None:
            return {"ok": False, "error": "Indica ids o before_minutes"}
        changed = runtime.store.acknowledge(ids, before=before, kind=kind)
        return {"ok": True, "acknowledged": changed}

    @server.tool()
    def get_redaction_stats() -> dict[str, Any]:
        """Conteo de redacciones por categoria (otp, card, iban, phone)."""
        stats = runtime.store.stats()
        return {
            "redactions_by_category": stats["redactions_by_category"],
            "redaction_config": runtime.status()["redaction"],
            "total_events": stats["total_events"],
        }

    # ----------------------------------------------------------------- actions
    @server.tool()
    async def sync_sms_history(wait_seconds: float = 5.0) -> dict[str, Any]:
        """Pide al movil las conversaciones cacheadas y las ingesta (redactadas)."""
        if backend_label(runtime.cfg) == "kcd":
            return {
                "ok": False,
                "error": "kcd no soporta backfill de conversaciones; la captura es solo en vivo",
            }
        if runtime.cfg.fake:
            raws = await FakeBackend(runtime.cfg).sync_conversations()
        else:
            try:
                raws = await with_live_backend(
                    runtime.cfg, lambda backend: backend.sync_conversations(wait_seconds)
                )
            except BACKEND_UNAVAILABLE as exc:
                return {"ok": False, "error": str(exc)}
        inserted = duplicates = merged = 0
        for raw in raws:
            outcome = runtime.ingestor.handle(raw)
            if outcome.status == "inserted":
                inserted += 1
            elif outcome.status == "duplicate":
                duplicates += 1
            elif outcome.status == "merged":
                merged += 1
        return {
            "ok": True,
            "fetched": len(raws),
            "inserted": inserted,
            "duplicates": duplicates,
            "merged": merged,
        }

    @server.tool()
    async def scan_devices(include_unpaired: bool = True) -> dict[str, Any]:
        """Escanea dispositivos KDE Connect. include_unpaired para emparejar nuevos."""
        if runtime.cfg.fake:
            return {"count": 1, "devices": [{"id": "fake-phone", "name": "Pixel de Prueba", "paired": True, "reachable": True}]}
        try:
            devices = await with_live_backend(
                runtime.cfg,
                lambda backend: backend.list_devices(
                    only_reachable=include_unpaired,
                    only_paired=not include_unpaired,
                ),
            )
        except BACKEND_UNAVAILABLE as exc:
            return {"count": 0, "devices": [], "error": str(exc)}
        return {
            "count": len(devices),
            "devices": [
                {
                    "id": device.id,
                    "name": device.name,
                    "type": device.type,
                    "paired": device.paired,
                    "reachable": device.reachable,
                }
                for device in devices
            ],
        }

    @server.tool()
    async def request_pair(device_id: str) -> dict[str, Any]:
        """Pide emparejar un dispositivo; hay que confirmar en el movil."""
        if runtime.cfg.fake:
            return {"ok": True, "fake": True}
        try:
            await with_live_backend(runtime.cfg, lambda backend: backend.request_pair(device_id))
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "hint": "Acepta la solicitud en el movil para completar el emparejamiento."}

    @server.tool()
    async def accept_pairing(device_id: str) -> dict[str, Any]:
        """Acepta una solicitud de emparejamiento entrante (el movil la inicio). Requiere backend kcd."""
        if backend_label(runtime.cfg) != "kcd":
            return {"ok": False, "error": "accept_pairing solo esta disponible con backend kcd"}
        try:
            await with_live_backend(
                runtime.cfg, lambda backend: backend.request_pair(device_id, accept=True)
            )
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "hint": "Emparejamiento aceptado."}

    @server.tool()
    async def reject_pairing(device_id: str) -> dict[str, Any]:
        """Rechaza una solicitud de emparejamiento entrante. Requiere backend kcd."""
        if backend_label(runtime.cfg) != "kcd":
            return {"ok": False, "error": "reject_pairing solo esta disponible con backend kcd"}
        try:
            await with_live_backend(
                runtime.cfg, lambda backend: backend.request_pair(device_id, accept=False)
            )
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "hint": "Emparejamiento rechazado."}

    return server


def run_stdio(cfg: Config) -> None:
    server = create_server(cfg)
    server.run(transport="stdio")
