"""Fabrica de backends y helper de conexion efimera.

Centraliza la eleccion kcd (socket Unix) | dbus (legacy) | fake para que CLI y
servidor MCP no dupliquen imports ni ramas.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from .config import Config
from .dbus_backend import KdeConnectUnavailable as _DbusUnavailable
from .kcd_backend import KcdUnavailable as _KcdUnavailable

#: Excepciones de "backend no disponible" de cualquiera de los backends reales.
BACKEND_UNAVAILABLE: tuple[type[Exception], ...] = (_DbusUnavailable, _KcdUnavailable)


def backend_label(cfg: Config) -> str:
    """Nombre efectivo del backend configurado."""
    if cfg.fake or cfg.backend == "fake":
        return "fake"
    return cfg.backend


def build_backend(cfg: Config) -> Any:
    """Construye el backend configurado (kcd | dbus | fake)."""
    label = backend_label(cfg)
    if label == "fake":
        from .fake_backend import FakeBackend

        return FakeBackend(cfg)
    if label == "dbus":
        from .dbus_backend import KdeConnectBackend

        return KdeConnectBackend(cfg)
    from .kcd_backend import KcdBackend

    return KcdBackend(cfg)


async def with_live_backend(cfg: Config, action: Callable[[Any], Awaitable[Any]]) -> Any:
    """Ejecuta `action` con una conexion efimera del backend configurado."""
    backend = build_backend(cfg)
    await backend.connect()
    try:
        return await action(backend)
    finally:
        await backend.close()
