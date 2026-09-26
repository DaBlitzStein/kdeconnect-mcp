"""Tests de `Runtime.status()`: deteccion de listener externo sin truncar el lock."""

from __future__ import annotations

from pathlib import Path

from kdeconnect_mcp.config import load_config
from kdeconnect_mcp.listener import acquire_lock
from kdeconnect_mcp.server import Runtime


def test_status_without_listener(tmp_path) -> None:
    cfg = load_config(data_dir=tmp_path, fake=True)
    runtime = Runtime(cfg)
    try:
        status = runtime.status()
        assert status["listener_owned"] is False
        assert status["listener_external"] is False
        assert status["listener_active"] is False
        assert status["listener_note"] == "sin listener"
    finally:
        runtime.store.close()


def test_status_detects_external_listener_and_keeps_lock_content(tmp_path) -> None:
    cfg = load_config(data_dir=tmp_path, fake=True)
    handle = acquire_lock(cfg.lock_path)
    assert handle is not None
    try:
        content_before = Path(cfg.lock_path).read_text(encoding="utf-8")
        assert content_before  # pid del listener externo

        runtime = Runtime(cfg)
        try:
            status = runtime.status()
        finally:
            runtime.store.close()

        assert status["listener_owned"] is False
        assert status["listener_external"] is True
        assert status["listener_active"] is True
        assert "externo" in status["listener_note"]
        # probe_lock no debe truncar el fichero del listener real.
        assert Path(cfg.lock_path).read_text(encoding="utf-8") == content_before
    finally:
        handle.close()
