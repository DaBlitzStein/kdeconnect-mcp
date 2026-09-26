"""Tests de las tools MCP: catalogo y emparejamiento (fake + ruteo kcd)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from kdeconnect_mcp import server as server_module
from kdeconnect_mcp.config import load_config
from kdeconnect_mcp.models import KIND_NOTIFICATION, RawEvent


def _payload(result: Any) -> dict[str, Any]:
    structured = getattr(result, "structured_content", None)
    if structured:
        return structured
    return json.loads(result.content[0].text)


def test_tools_list_and_pairing_flow(tmp_path: Path, monkeypatch) -> None:
    cfg = load_config(data_dir=tmp_path, fake=True)
    server = server_module.create_server(cfg)

    calls: list[tuple[str, bool | None]] = []

    class StubBackend:
        async def request_pair(self, device_id: str, *, accept: bool | None = None) -> None:
            calls.append((device_id, accept))

    async def fake_live_backend(_cfg, action):
        return await action(StubBackend())

    # accept/reject solo se enrutan con etiqueta kcd; el backend vivo se stubea.
    monkeypatch.setattr(server_module, "backend_label", lambda _cfg: "kcd")
    monkeypatch.setattr(server_module, "with_live_backend", fake_live_backend)

    async def scenario() -> tuple[set[str], dict, dict, dict]:
        names = {tool.name for tool in await server.list_tools()}
        requested = _payload(
            await server.call_tool("request_pair", {"device_id": "dev-1"})
        )
        accepted = _payload(
            await server.call_tool("accept_pairing", {"device_id": "dev-1"})
        )
        rejected = _payload(
            await server.call_tool("reject_pairing", {"device_id": "dev-2"})
        )
        return names, requested, accepted, rejected

    names, requested, accepted, rejected = asyncio.run(scenario())

    assert {"request_pair", "accept_pairing", "reject_pairing"} <= names
    # request_pair en modo fake responde ok sin tocar ningun backend.
    assert requested["ok"] is True and requested["fake"] is True
    assert accepted["ok"] is True and rejected["ok"] is True
    assert calls == [("dev-1", True), ("dev-2", False)]


def test_list_active_notifications_cache_filters_device(tmp_path: Path, monkeypatch) -> None:
    """La rama cache kcd debe respetar device_id (antes lo ignoraba)."""
    monkeypatch.delenv("KDCONNECT_MCP_BACKEND", raising=False)
    monkeypatch.setenv("KDCONNECT_SOCKET", str(tmp_path / "missing.sock"))
    cfg = load_config(data_dir=tmp_path)
    assert cfg.backend == "kcd"
    server = server_module.create_server(cfg)

    for device, source in (("dev-1", "1"), ("dev-2", "2")):
        server.runtime.ingestor.handle(
            RawEvent(
                device_id=device,
                kind=KIND_NOTIFICATION,
                subtype="posted",
                app="Signal",
                title="Ana",
                body="hola",
                source_id=source,
            )
        )

    async def scenario() -> tuple[dict, dict]:
        everywhere = _payload(await server.call_tool("list_active_notifications", {}))
        only_one = _payload(
            await server.call_tool(
                "list_active_notifications", {"device_id": "dev-1"}
            )
        )
        return everywhere, only_one

    everywhere, only_one = asyncio.run(scenario())
    assert everywhere["count"] == 2
    assert only_one["count"] == 1
    assert only_one["notifications"][0]["device_id"] == "dev-1"
