"""Almacen SQLite (WAL) para eventos ya redactados.

Invariante: aqui solo entran textos redactados. `content_hash` es un HMAC del
texto original (deduplicacion/auditoria), nunca el texto.
"""

from __future__ import annotations

import hmac
import json
import sqlite3
import threading
import time
from collections.abc import Iterable
from hashlib import sha256
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT '',
    paired INTEGER NOT NULL DEFAULT 0,
    reachable INTEGER NOT NULL DEFAULT 0,
    last_seen REAL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL UNIQUE,
    device_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    subtype TEXT,
    app TEXT,
    title TEXT,
    body TEXT,
    contact TEXT,
    address TEXT,
    occurred_at REAL,
    received_at REAL NOT NULL,
    source_id TEXT,
    redactions TEXT,
    content_hash TEXT,
    meta TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    removed_at REAL
);

CREATE INDEX IF NOT EXISTS idx_events_kind_time ON events(kind, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_device_time ON events(device_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_address_time ON events(address, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(device_id, source_id);

CREATE TABLE IF NOT EXISTS redaction_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    count INTEGER NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_redaction_category ON redaction_log(category);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

_FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    title, body, app, contact, address,
    content='events', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, title, body, app, contact, address)
    VALUES (new.id, new.title, new.body, new.app, new.contact, new.address);
END;
CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, title, body, app, contact, address)
    VALUES ('delete', old.id, old.title, old.body, old.app, old.contact, old.address);
END;
CREATE TRIGGER IF NOT EXISTS events_au AFTER UPDATE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, title, body, app, contact, address)
    VALUES ('delete', old.id, old.title, old.body, old.app, old.contact, old.address);
    INSERT INTO events_fts(rowid, title, body, app, contact, address)
    VALUES (new.id, new.title, new.body, new.app, new.contact, new.address);
END;
"""


def compute_content_hash(secret: bytes, *parts: str | None) -> str | None:
    payload = "\x1f".join(p or "" for p in parts)
    if not payload.replace("\x1f", ""):
        return None
    return hmac.new(secret, payload.encode("utf-8", "replace"), sha256).hexdigest()


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(_SCHEMA)
            self._has_fts = self._init_fts()
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()

    def _init_fts(self) -> bool:
        try:
            self._conn.executescript(_FTS_SCHEMA)
            return True
        except sqlite3.OperationalError:
            return False

    # ---------------------------------------------------------------- devices
    def upsert_device(
        self,
        device_id: str,
        *,
        name: str = "",
        dtype: str = "",
        paired: bool = False,
        reachable: bool = False,
        last_seen: float | None = None,
    ) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO devices(id, name, type, paired, reachable, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    type=excluded.type,
                    paired=excluded.paired,
                    reachable=excluded.reachable,
                    last_seen=COALESCE(excluded.last_seen, devices.last_seen),
                    updated_at=excluded.updated_at
                """,
                (device_id, name, dtype, int(paired), int(reachable), last_seen, now),
            )
            self._conn.commit()

    def list_devices(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
        return [
            {
                "id": row["id"],
                "name": row["name"],
                "type": row["type"],
                "paired": bool(row["paired"]),
                "reachable": bool(row["reachable"]),
                "last_seen": row["last_seen"],
            }
            for row in rows
        ]

    # ----------------------------------------------------------------- events
    def insert_event(
        self,
        *,
        event_key: str,
        device_id: str,
        kind: str,
        received_at: float | None = None,
        subtype: str | None = None,
        app: str | None = None,
        title: str | None = None,
        body: str | None = None,
        contact: str | None = None,
        address: str | None = None,
        occurred_at: float | None = None,
        source_id: str | None = None,
        redactions: dict[str, int] | None = None,
        content_hash: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> tuple[int | None, bool]:
        now = time.time()
        received = received_at if received_at is not None else now
        redactions = redactions or {}
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT OR IGNORE INTO events(
                    event_key, device_id, kind, subtype, app, title, body, contact,
                    address, occurred_at, received_at, source_id, redactions,
                    content_hash, meta
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_key,
                    device_id,
                    kind,
                    subtype,
                    app,
                    title,
                    body,
                    contact,
                    address,
                    occurred_at,
                    received,
                    source_id,
                    json.dumps(redactions, ensure_ascii=False),
                    content_hash,
                    json.dumps(meta or {}, ensure_ascii=False),
                ),
            )
            if cursor.rowcount == 0:
                row = self._conn.execute(
                    "SELECT id FROM events WHERE event_key = ?", (event_key,)
                ).fetchone()
                self._conn.commit()
                return (row["id"] if row else None, False)
            event_id = cursor.lastrowid
            for category, count in redactions.items():
                if count:
                    self._conn.execute(
                        "INSERT INTO redaction_log(event_id, category, count, created_at) VALUES (?, ?, ?, ?)",
                        (event_id, category, int(count), now),
                    )
            self._conn.commit()
            return (event_id, True)

    def find_recent_call(
        self, device_id: str, address: str | None, *, within_seconds: float = 300.0
    ) -> dict[str, Any] | None:
        since = time.time() - within_seconds
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM events
                WHERE kind = 'call' AND device_id = ? AND COALESCE(address, '') = COALESCE(?, '')
                  AND received_at >= ? AND COALESCE(subtype, '') != 'missedCall'
                ORDER BY received_at DESC LIMIT 1
                """,
                (device_id, address, since),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_event(self, event_id: int, **fields: Any) -> None:
        allowed = {"subtype", "meta", "acknowledged", "removed_at", "content_hash"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        if "meta" in updates and isinstance(updates["meta"], dict):
            updates["meta"] = json.dumps(updates["meta"], ensure_ascii=False)
        assignments = ", ".join(f"{key} = ?" for key in updates)
        with self._lock:
            self._conn.execute(
                f"UPDATE events SET {assignments} WHERE id = ?",
                (*updates.values(), event_id),
            )
            self._conn.commit()

    def mark_notification_removed(self, device_id: str, source_id: str) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE events SET removed_at = ?
                WHERE device_id = ? AND source_id = ? AND kind = 'notification'
                  AND removed_at IS NULL
                """,
                (time.time(), device_id, str(source_id)),
            )
            self._conn.commit()
            return cursor.rowcount

    def mark_all_notifications_removed(self, device_id: str) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE events SET removed_at = ?
                WHERE device_id = ? AND kind = 'notification' AND removed_at IS NULL
                """,
                (time.time(), device_id),
            )
            self._conn.commit()
            return cursor.rowcount

    def acknowledge(self, ids: Iterable[int] | None = None, *, before: float | None = None, kind: str | None = None) -> int:
        with self._lock:
            if ids:
                id_list = [int(i) for i in ids]
                placeholders = ",".join("?" for _ in id_list)
                cursor = self._conn.execute(
                    f"UPDATE events SET acknowledged = 1 WHERE id IN ({placeholders})",
                    id_list,
                )
            elif before is not None:
                if kind:
                    cursor = self._conn.execute(
                        "UPDATE events SET acknowledged = 1 WHERE received_at <= ? AND kind = ?",
                        (before, kind),
                    )
                else:
                    cursor = self._conn.execute(
                        "UPDATE events SET acknowledged = 1 WHERE received_at <= ?",
                        (before,),
                    )
            else:
                return 0
            self._conn.commit()
            return cursor.rowcount

    # ------------------------------------------------------------------ query
    def query_events(
        self,
        *,
        kind: str | None = None,
        device_id: str | None = None,
        app: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 100,
        offset: int = 0,
        include_removed: bool = False,
        unacked_only: bool = False,
        address: str | None = None,
        contact: str | None = None,
        subtype: str | None = None,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if kind:
            where.append("kind = ?")
            params.append(kind)
        if subtype:
            where.append("subtype = ?")
            params.append(subtype)
        if device_id:
            where.append("device_id = ?")
            params.append(device_id)
        if app:
            where.append("LOWER(COALESCE(app, '')) LIKE ?")
            params.append(f"%{app.casefold()}%")
        if since is not None:
            where.append("received_at >= ?")
            params.append(since)
        if until is not None:
            where.append("received_at <= ?")
            params.append(until)
        if not include_removed:
            where.append("(removed_at IS NULL OR kind != 'notification')")
        if unacked_only:
            where.append("acknowledged = 0")
        if address:
            where.append("COALESCE(address, '') LIKE ?")
            params.append(f"%{address}%")
        if contact:
            where.append("LOWER(COALESCE(contact, '')) LIKE ?")
            params.append(f"%{contact.casefold()}%")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        sql = f"SELECT * FROM events {clause} ORDER BY received_at DESC LIMIT ? OFFSET ?"
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def search_events(
        self,
        query: str,
        *,
        kind: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = (query or "").strip()
        if not query:
            return []
        like = f"%{query.casefold()}%"
        with self._lock:
            if self._has_fts:
                phrase = '"' + query.replace('"', '""') + '"'
                kind_clause = "AND e.kind = ?" if kind else ""
                params: list[Any] = [phrase]
                if kind:
                    params.append(kind)
                params.append(max(1, min(int(limit), 500)))
                try:
                    rows = self._conn.execute(
                        f"""
                        SELECT e.* FROM events e
                        JOIN events_fts f ON f.rowid = e.id
                        WHERE events_fts MATCH ? {kind_clause}
                        ORDER BY e.received_at DESC LIMIT ?
                        """,
                        params,
                    ).fetchall()
                    return [self._row_to_dict(row) for row in rows]
                except sqlite3.OperationalError:
                    pass
            kind_clause = "AND kind = ?" if kind else ""
            params = [like, like, like, like, like]
            if kind:
                params.append(kind)
            params.append(max(1, min(int(limit), 500)))
            rows = self._conn.execute(
                f"""
                SELECT * FROM events
                WHERE (LOWER(COALESCE(title, '')) LIKE ?
                    OR LOWER(COALESCE(body, '')) LIKE ?
                    OR LOWER(COALESCE(app, '')) LIKE ?
                    OR LOWER(COALESCE(contact, '')) LIKE ?
                    OR COALESCE(address, '') LIKE ?)
                    {kind_clause}
                ORDER BY received_at DESC LIMIT ?
                """,
                params,
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def conversation(self, *, address: str | None = None, contact: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        return self.query_events(
            kind="sms",
            address=address,
            contact=contact,
            limit=limit,
            include_removed=True,
        )

    def latest_event_id(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COALESCE(MAX(id), 0) AS n FROM events").fetchone()
        return int(row["n"])

    def last_event_at(self) -> float | None:
        with self._lock:
            row = self._conn.execute("SELECT MAX(received_at) AS t FROM events").fetchone()
        return float(row["t"]) if row["t"] is not None else None

    def get_events_after(
        self,
        after_id: int = 0,
        *,
        limit: int = 100,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        """Cursor de eventos: filas con id > after_id, en orden de llegada.

        Nota: las retiradas de notificacion actualizan la fila existente
        (removed_at) y no se reemiten por el cursor.
        """
        where = ["id > ?"]
        params: list[Any] = [max(0, int(after_id))]
        if kind:
            where.append("kind = ?")
            params.append(kind)
        params.append(max(1, min(int(limit), 500)))
        sql = f"SELECT * FROM events WHERE {' AND '.join(where)} ORDER BY id ASC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
            by_kind = {
                row["kind"]: row["n"]
                for row in self._conn.execute(
                    "SELECT kind, COUNT(*) AS n FROM events GROUP BY kind"
                ).fetchall()
            }
            by_category = {
                row["category"]: row["total"]
                for row in self._conn.execute(
                    "SELECT category, SUM(count) AS total FROM redaction_log GROUP BY category"
                ).fetchall()
            }
            by_app = {
                row["app"]: row["n"]
                for row in self._conn.execute(
                    """
                    SELECT COALESCE(app, '(sin app)') AS app, COUNT(*) AS n
                    FROM events WHERE kind = 'notification'
                    GROUP BY COALESCE(app, '(sin app)') ORDER BY n DESC LIMIT 20
                    """
                ).fetchall()
            }
            unacked = self._conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE acknowledged = 0"
            ).fetchone()["n"]
        return {
            "total_events": total,
            "by_kind": by_kind,
            "unacknowledged": unacked,
            "redactions_by_category": by_category,
            "notifications_by_app": by_app,
        }

    # ------------------------------------------------------------------ helper
    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        for key in ("redactions", "meta"):
            if data.get(key):
                try:
                    data[key] = json.loads(data[key])
                except (TypeError, ValueError):
                    pass
            else:
                data[key] = {} if key in ("redactions", "meta") else data.get(key)
        data["acknowledged"] = bool(data.get("acknowledged"))
        if data.get("occurred_at") is None:
            data["occurred_at"] = data.get("received_at")
        return data

    def close(self) -> None:
        with self._lock:
            self._conn.close()
