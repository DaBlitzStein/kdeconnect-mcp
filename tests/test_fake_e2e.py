import asyncio
import time
from pathlib import Path

from kdeconnect_mcp.config import Config
from kdeconnect_mcp.fake_backend import FakeBackend
from kdeconnect_mcp.listener import Ingestor, Listener, load_secret
from kdeconnect_mcp.pii import Redactor
from kdeconnect_mcp.store import Store

SECRETS = [
    b"483920",
    b"555111",
    b"918273",
    b"445566",
    b"407-1234567-8901234",
    b"ES91",
    b"655667788",
    b"600123456",
]

NAMES = [b"Ana", b"WhatsApp", b"Google Authenticator", b"Mama"]


def run_pipeline(tmp_path) -> Store:
    cfg = Config(data_dir=tmp_path)
    cfg.ensure_dirs()
    store = Store(cfg.db_path)
    secret = load_secret(cfg.data_dir)
    ingestor = Ingestor(cfg, store, Redactor(cfg.redaction), secret)
    backend = FakeBackend(cfg, delay=0.01)
    listener = Listener(cfg, store, backend, ingestor)

    async def main() -> None:
        task = asyncio.create_task(listener.run())
        deadline = time.time() + 5
        while time.time() < deadline:
            if store.stats()["total_events"] >= 9:
                break
            await asyncio.sleep(0.02)
        listener.stop()
        await task

    asyncio.run(main())
    return store


def test_fake_pipeline_end_to_end(tmp_path):
    store = run_pipeline(tmp_path)
    stats = store.stats()

    assert stats["by_kind"] == {"notification": 6, "sms": 2, "call": 1}
    assert stats["redactions_by_category"].get("otp") == 3
    assert stats["redactions_by_category"].get("card") == 1
    assert stats["redactions_by_category"].get("iban") == 1

    sms_addresses = {row["address"] for row in store.query_events(kind="sms")}
    assert sms_addresses == {"***456", "***344"}

    calls = store.query_events(kind="call")
    assert len(calls) == 1
    assert calls[0]["subtype"] == "missedCall"
    assert calls[0]["contact"] == "Mama"

    notifications = store.query_events(kind="notification")
    assert len(notifications) == 5
    assert all(row["source_id"] != "9006" for row in notifications)

    authenticator = next(row for row in notifications if row["source_id"] == "9001")
    assert "555111" not in str(authenticator["meta"])
    sms_meta = " ".join(str(row["meta"]) for row in store.query_events(kind="sms"))
    assert "600123456" not in sms_meta
    assert "***456" in sms_meta


def test_raw_secrets_never_hit_disk(tmp_path):
    store = run_pipeline(tmp_path)
    data_dir = Path(store.path).parent
    blobs = []
    for path in data_dir.iterdir():
        if path.is_file() and path.name.startswith(store.path.name):
            blobs.append(path.read_bytes())
    joined = b"\n".join(blobs)

    for secret in SECRETS:
        assert secret not in joined, f"secret leaked: {secret!r}"
    for name in NAMES:
        assert name in joined, f"name missing: {name!r}"
