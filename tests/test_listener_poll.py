"""Tests del poll periodico de SMS del listener (`_sms_poll_loop`)."""

from __future__ import annotations

import asyncio
import contextlib
import time
from types import SimpleNamespace

import pytest

from kdeconnect_mcp.config import Config
from kdeconnect_mcp.listener import Listener


class PollBackend:
    """Stub minimo que registra las llamadas a request_conversations."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    async def request_conversations(self) -> list[str]:
        self.calls += 1
        if self.fail:
            raise RuntimeError("kcd no responde")
        return ["dev-1"]


def make_listener(
    tmp_path, backend, *, sms: bool = True, interval: int = 1
) -> Listener:
    cfg = Config(data_dir=tmp_path, fake=True)
    cfg.capture.sms = sms
    cfg.capture.sms_poll_seconds = interval
    # store/ingestor no se usan en _sms_poll_loop: basta un stub.
    return Listener(cfg, SimpleNamespace(), backend, SimpleNamespace())  # type: ignore[arg-type]


def test_poll_requests_conversations_periodically(tmp_path) -> None:
    backend = PollBackend()
    listener = make_listener(tmp_path, backend, sms=True, interval=1)

    async def scenario() -> int:
        task = asyncio.create_task(listener._sms_poll_loop())
        deadline = time.monotonic() + 5.0
        while backend.calls < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        listener.stop()
        await asyncio.wait_for(task, timeout=2)
        return backend.calls

    calls = asyncio.run(scenario())
    assert calls >= 2


@pytest.mark.parametrize(("sms", "interval"), [(False, 1), (True, 0)])
def test_poll_disabled_does_not_call(tmp_path, sms: bool, interval: int) -> None:
    backend = PollBackend()
    listener = make_listener(tmp_path, backend, sms=sms, interval=interval)

    async def scenario() -> None:
        task = asyncio.create_task(listener._sms_poll_loop())
        await asyncio.sleep(0.1)
        assert task.done()  # retorna de inmediato sin pedir nada

    asyncio.run(scenario())
    assert backend.calls == 0


def test_poll_without_requester_returns(tmp_path) -> None:
    listener = make_listener(tmp_path, SimpleNamespace(), sms=True, interval=1)

    async def scenario() -> None:
        task = asyncio.create_task(listener._sms_poll_loop())
        await asyncio.sleep(0.1)
        assert task.done()

    asyncio.run(scenario())


def test_poll_survives_requester_failure(tmp_path) -> None:
    backend = PollBackend(fail=True)
    listener = make_listener(tmp_path, backend, sms=True, interval=1)

    async def scenario() -> int:
        task = asyncio.create_task(listener._sms_poll_loop())
        deadline = time.monotonic() + 5.0
        while backend.calls < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        assert not task.done()  # el fallo no tumba el loop
        listener.stop()
        await asyncio.wait_for(task, timeout=2)
        return backend.calls

    assert asyncio.run(scenario()) >= 2


def test_poll_stop_finishes_without_errors(tmp_path) -> None:
    backend = PollBackend()
    listener = make_listener(tmp_path, backend, sms=True, interval=1)

    async def scenario() -> None:
        task = asyncio.create_task(listener._sms_poll_loop())
        await asyncio.sleep(0.05)
        listener.stop()
        await asyncio.wait_for(task, timeout=3)  # sin excepcion

    asyncio.run(scenario())
    assert backend.calls == 0  # stop antes del primer poll


def test_poll_task_cancel_is_clean(tmp_path) -> None:
    """Mismo patron que Listener.run: cancel + await sin errores."""

    backend = PollBackend()
    listener = make_listener(tmp_path, backend, sms=True, interval=1)

    async def scenario() -> None:
        task = asyncio.create_task(listener._sms_poll_loop())
        await asyncio.sleep(0)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert task.done()

    asyncio.run(scenario())
