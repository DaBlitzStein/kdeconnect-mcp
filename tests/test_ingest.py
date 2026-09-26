from pathlib import Path

from kdeconnect_mcp.config import Config
from kdeconnect_mcp.listener import Ingestor, load_secret
from kdeconnect_mcp.models import (
    KIND_CALL,
    KIND_NOTIFICATION,
    KIND_SMS,
    SUBTYPE_INCOMING,
    SUBTYPE_MISSED,
    SUBTYPE_RINGING,
    RawEvent,
)
from kdeconnect_mcp.pii import Redactor
from kdeconnect_mcp.store import Store


def build(tmp_path):
    cfg = Config(data_dir=tmp_path)
    cfg.ensure_dirs()
    store = Store(cfg.db_path)
    secret = load_secret(cfg.data_dir)
    ingestor = Ingestor(cfg, store, Redactor(cfg.redaction), secret)
    return cfg, store, ingestor


def test_otp_never_touches_disk(tmp_path):
    cfg, store, ingestor = build(tmp_path)
    outcome = ingestor.handle(
        RawEvent(
            device_id="dev",
            kind=KIND_SMS,
            subtype=SUBTYPE_INCOMING,
            body="Tu codigo de autorizacion es 483920",
            address="+34600123456",
        )
    )
    assert outcome.status == "inserted"
    row = store.query_events(kind=KIND_SMS)[0]
    assert "483920" not in row["body"]
    assert "[REDACTADO:otp]" in row["body"]
    assert row["address"] == "***456"
    assert row["redactions"] == {"otp": 1}

    for suffix in ("", "-wal"):
        path = Path(str(cfg.db_path) + suffix)
        if path.exists():
            assert b"483920" not in path.read_bytes()


def test_duplicate_event_is_ignored(tmp_path):
    _cfg, _store, ingestor = build(tmp_path)
    event = RawEvent(
        device_id="dev", kind=KIND_SMS, subtype=SUBTYPE_INCOMING, body="hola"
    )
    assert ingestor.handle(event).status == "inserted"
    assert ingestor.handle(event).status == "duplicate"


def test_call_ringing_then_missed_merges(tmp_path):
    _cfg, store, ingestor = build(tmp_path)
    ring = RawEvent(
        device_id="dev",
        kind=KIND_CALL,
        subtype=SUBTYPE_RINGING,
        contact="Mama",
        address="+34655667788",
    )
    missed = RawEvent(
        device_id="dev",
        kind=KIND_CALL,
        subtype=SUBTYPE_MISSED,
        contact="Mama",
        address="+34655667788",
    )
    assert ingestor.handle(ring).status == "inserted"
    assert ingestor.handle(missed).status == "merged"
    calls = store.query_events(kind=KIND_CALL)
    assert len(calls) == 1
    assert calls[0]["subtype"] == SUBTYPE_MISSED
    assert calls[0]["contact"] == "Mama"
    assert calls[0]["address"] == "***788"


def test_notification_removed_marks_row(tmp_path):
    _cfg, store, ingestor = build(tmp_path)
    ingestor.handle(
        RawEvent(
            device_id="dev",
            kind=KIND_NOTIFICATION,
            subtype="posted",
            app="WhatsApp",
            title="Ana",
            body="hey",
            source_id="7",
        )
    )
    ingestor.handle(
        RawEvent(
            device_id="dev",
            kind=KIND_NOTIFICATION,
            subtype="removed",
            source_id="7",
        )
    )
    assert store.query_events(kind=KIND_NOTIFICATION) == []
    assert len(store.query_events(kind=KIND_NOTIFICATION, include_removed=True)) == 1


def test_ignored_app_skipped(tmp_path):
    cfg, store, ingestor = build(tmp_path)
    cfg.capture.ignore_apps = ["facebook"]
    outcome = ingestor.handle(
        RawEvent(
            device_id="dev",
            kind=KIND_NOTIFICATION,
            subtype="posted",
            app="Facebook",
            body="algo",
        )
    )
    assert outcome.status == "skipped"
    assert store.query_events() == []


def test_unknown_sms_source_dedups_on_hash(tmp_path):
    _cfg, _store, ingestor = build(tmp_path)
    event = RawEvent(
        device_id="dev",
        kind=KIND_SMS,
        subtype=SUBTYPE_INCOMING,
        body="mismo texto",
        address="+34600111222",
        occurred_at=1_700_000_000.0,
    )
    assert ingestor.handle(event).status == "inserted"
    assert ingestor.handle(event).status == "duplicate"


def test_meta_sanitized_at_ingestion(tmp_path):
    _cfg, store, ingestor = build(tmp_path)
    ingestor.handle(
        RawEvent(
            device_id="dev",
            kind=KIND_NOTIFICATION,
            subtype="posted",
            app="BBVA",
            title="Aviso",
            body="hola",
            source_id="1",
            meta={"ticker": "Tu codigo es 445566", "addresses": ["+34600123456"]},
        )
    )
    row = store.query_events(kind=KIND_NOTIFICATION)[0]
    blob = str(row["meta"])
    assert "445566" not in blob
    assert "600123456" not in blob
    assert row["meta"]["addresses"] == ["***456"]


def test_presenter_sanitizes_meta_and_contact(tmp_path):
    import json

    from kdeconnect_mcp.server import Runtime

    cfg, _store, _ingestor = build(tmp_path)
    runtime = Runtime(cfg)
    event = {
        "kind": "notification",
        "app": "BBVA",
        "title": "Aviso",
        "body": "Tu codigo es 445566",
        "contact": "Ana",
        "address": "+34600123456",
        "meta": {"ticker": "Codigo 555111", "addresses": ["+34600123456"]},
    }
    out = runtime.present(dict(event))
    blob = json.dumps(out, ensure_ascii=False)
    assert "445566" not in blob
    assert "555111" not in blob
    assert "600123456" not in blob
    assert out["address"] == "***456"
    assert out["contact"] == "Ana"


def test_phone_as_contact_is_masked(tmp_path):
    _cfg, store, ingestor = build(tmp_path)
    ingestor.handle(
        RawEvent(
            device_id="dev",
            kind=KIND_CALL,
            subtype=SUBTYPE_RINGING,
            contact="+34655667788",
        )
    )
    row = store.query_events(kind=KIND_CALL)[0]
    assert row["contact"] == "***788"


def test_contact_name_is_kept(tmp_path):
    _cfg, store, ingestor = build(tmp_path)
    ingestor.handle(
        RawEvent(
            device_id="dev",
            kind=KIND_CALL,
            subtype=SUBTYPE_RINGING,
            contact="Mama",
        )
    )
    assert store.query_events(kind=KIND_CALL)[0]["contact"] == "Mama"


def test_present_raw_sanitizes_meta(tmp_path):
    import json

    from kdeconnect_mcp.server import Runtime

    cfg, _store, _ingestor = build(tmp_path)
    runtime = Runtime(cfg)
    raw = RawEvent(
        device_id="dev",
        kind=KIND_NOTIFICATION,
        subtype="posted",
        app="BBVA",
        title="Aviso",
        body="Tu codigo es 445566",
        address="+34600123456",
        meta={"ticker": "Codigo 555111", "addresses": ["+34600123456"]},
    )
    out = runtime.present_raw(raw)
    blob = json.dumps(out, ensure_ascii=False)
    assert "445566" not in blob
    assert "555111" not in blob
    assert "600123456" not in blob
    assert out["address"] == "***456"
    assert out["meta"]["addresses"] == ["***456"]
