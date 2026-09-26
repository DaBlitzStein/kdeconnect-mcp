import time

from kdeconnect_mcp.store import Store, compute_content_hash


def make_store(tmp_path) -> Store:
    return Store(tmp_path / "events.sqlite3")


def test_insert_dedup_and_query(tmp_path):
    store = make_store(tmp_path)
    event_id, inserted = store.insert_event(
        event_key="sms:1",
        device_id="dev",
        kind="sms",
        body="hola",
        address="***456",
        redactions={"phone": 1},
        content_hash="hash",
    )
    assert inserted is True and event_id

    same_id, inserted_again = store.insert_event(
        event_key="sms:1", device_id="dev", kind="sms", body="hola"
    )
    assert inserted_again is False and same_id == event_id

    events = store.query_events(kind="sms")
    assert len(events) == 1
    assert events[0]["body"] == "hola"
    assert events[0]["redactions"] == {"phone": 1}
    assert events[0]["acknowledged"] is False


def test_acknowledge(tmp_path):
    store = make_store(tmp_path)
    store.insert_event(event_key="a", device_id="d", kind="sms", body="uno")
    store.insert_event(event_key="b", device_id="d", kind="sms", body="dos")
    changed = store.acknowledge(before=time.time() + 1)
    assert changed == 2
    assert store.query_events(unacked_only=True) == []


def test_notification_removal(tmp_path):
    store = make_store(tmp_path)
    store.insert_event(
        event_key="n1",
        device_id="d",
        kind="notification",
        app="WhatsApp",
        body="hey",
        source_id="42",
    )
    assert len(store.query_events(kind="notification")) == 1
    assert store.mark_notification_removed("d", "42") == 1
    assert store.query_events(kind="notification") == []
    assert len(store.query_events(kind="notification", include_removed=True)) == 1


def test_search(tmp_path):
    store = make_store(tmp_path)
    store.insert_event(
        event_key="s1", device_id="d", kind="sms", body="recuerdame comprar pan"
    )
    hits = store.search_events("comprar")
    assert len(hits) == 1
    assert store.search_events("inexistente") == []


def test_stats_counts_redactions(tmp_path):
    store = make_store(tmp_path)
    store.insert_event(
        event_key="r1",
        device_id="d",
        kind="sms",
        body="[REDACTADO:otp]",
        redactions={"otp": 2, "card": 1},
    )
    stats = store.stats()
    assert stats["total_events"] == 1
    assert stats["redactions_by_category"] == {"otp": 2, "card": 1}


def test_call_merge_helper(tmp_path):
    store = make_store(tmp_path)
    store.insert_event(
        event_key="c1", device_id="d", kind="call", subtype="ringing", address="***788"
    )
    found = store.find_recent_call("d", "***788")
    assert found is not None
    store.update_event(found["id"], subtype="missedCall")
    assert store.find_recent_call("d", "***788") is None


def test_content_hash_never_plaintext():
    secret = b"secret"
    digest = compute_content_hash(secret, "483920")
    assert digest is not None
    assert "483920" not in digest
    assert compute_content_hash(secret, None, None) is None
