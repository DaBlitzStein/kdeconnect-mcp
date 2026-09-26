"""Test del reintento de arranque del listener cuando el backend no esta disponible."""

from __future__ import annotations

import asyncio

from kdeconnect_mcp.config import load_config
from kdeconnect_mcp.listener import Ingestor, Listener, load_secret
from kdeconnect_mcp.pii import Redactor
from kdeconnect_mcp.store import Store


class FlakyBackend:
    """Falla la primera conexion y funciona en la segunda."""

    def __init__(self) -> None:
        self.connect_calls = 0
        self.subscribed = asyncio.Event()

    async def connect(self) -> None:
        self.connect_calls += 1
        if self.connect_calls < 2:
            raise RuntimeError("kcd no arrancado")

    async def subscribe(self, on_event, on_device) -> None:
        self.subscribed.set()

    async def close(self) -> None:
        pass


def test_listener_retries_until_backend_is_available(tmp_path) -> None:
    cfg = load_config(fake=True, data_dir=tmp_path)
    store = Store(cfg.db_path)
    ingestor = Ingestor(cfg, store, Redactor(cfg.redaction), load_secret(cfg.data_dir))
    backend = FlakyBackend()
    listener = Listener(cfg, store, backend, ingestor)  # type: ignore[arg-type]

    async def scenario() -> None:
        task = asyncio.create_task(listener.run())
        await asyncio.wait_for(backend.subscribed.wait(), timeout=10)
        listener.stop()
        await asyncio.wait_for(task, timeout=5)

    try:
        asyncio.run(scenario())
    finally:
        store.close()

    assert backend.connect_calls == 2
