"""Tests del cursor de eventos (log append-only) sobre SQLite."""

from __future__ import annotations

import pathlib

from kdeconnect_mcp.store import Store


def make_store(tmp_path: pathlib.Path) -> Store:
    return Store(tmp_path / "events.sqlite3")


def insert(store: Store, key: str, kind: str = "sms", body: str = "hola") -> int:
    event_id, inserted = store.insert_event(
        event_key=key, device_id="dev1", kind=kind, body=body
    )
    assert inserted
    assert event_id is not None
    return event_id


def test_latest_event_id_empty(tmp_path: pathlib.Path) -> None:
    store = make_store(tmp_path)
    try:
        assert store.latest_event_id() == 0
        assert store.get_events_after(0) == []
    finally:
        store.close()


def test_cursor_ascending_and_incremental(tmp_path: pathlib.Path) -> None:
    store = make_store(tmp_path)
    try:
        ids = [insert(store, f"k{i}", body=f"msg {i}") for i in range(3)]
        first = store.get_events_after(0)
        assert [e["id"] for e in first] == ids
        assert store.latest_event_id() == ids[-1]
        second = store.get_events_after(ids[1])
        assert [e["id"] for e in second] == [ids[2]]
        assert store.get_events_after(ids[-1]) == []
    finally:
        store.close()


def test_cursor_kind_filter(tmp_path: pathlib.Path) -> None:
    store = make_store(tmp_path)
    try:
        insert(store, "sms1", kind="sms")
        insert(store, "call1", kind="call")
        insert(store, "sms2", kind="sms")
        only_calls = store.get_events_after(0, kind="call")
        assert [e["kind"] for e in only_calls] == ["call"]
    finally:
        store.close()


def test_cursor_ignores_duplicate_event_key(tmp_path: pathlib.Path) -> None:
    store = make_store(tmp_path)
    try:
        first_id = insert(store, "dup")
        event_id, inserted = store.insert_event(
            event_key="dup", device_id="dev1", kind="sms", body="hola"
        )
        assert inserted is False
        assert event_id == first_id
        assert len(store.get_events_after(0)) == 1
    finally:
        store.close()


def test_last_event_at(tmp_path: pathlib.Path) -> None:
    store = make_store(tmp_path)
    try:
        assert store.last_event_at() is None
        insert(store, "k1")
        value = store.last_event_at()
        assert value is not None and value > 0
    finally:
        store.close()
