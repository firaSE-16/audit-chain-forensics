"""ledgerd - append-only, hash-chained audit log stored in SQLite.

Every entry n is chained to entry n-1:

    hash(n) = SHA-256( hash(n-1) || canonical(n, ts, actor, action, target, detail) )

where hash(0) is GENESIS (32 zero bytes). The newest (seq, hash) pair is kept
in the meta table so that appends always extend the true head of the chain.

Usage:
    python3 ledgerd.py --db audit.db [--page-size N] [--encoding E]
                       [--journal-mode M] [--auto-vacuum A] [--secure-delete S]
                       append ACTOR ACTION [--target T] [--detail JSON]
    python3 ledgerd.py --db audit.db verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

GENESIS = bytes(32)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    detail    TEXT NOT NULL,
    prev_hash BLOB NOT NULL,
    hash      BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_actor ON events(actor, ts);
CREATE TABLE IF NOT EXISTS sessions (
    id     TEXT PRIMARY KEY,
    actor  TEXT NOT NULL,
    opened TEXT NOT NULL,
    closed TEXT,
    client TEXT
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value
);
"""

PAGE_SIZES = (1024, 2048, 4096, 8192, 16384, 32768, 65536)
ENCODINGS = ("UTF-8", "UTF-16le", "UTF-16be")
JOURNAL_MODES = ("WAL", "DELETE", "TRUNCATE", "PERSIST")
AUTO_VACUUM = ("NONE", "INCREMENTAL")
SECURE_DELETE = ("DEFAULT", "ON", "OFF", "FAST")  # DEFAULT keeps the SQLite build's default


@dataclass(frozen=True)
class Config:
    page_size: int = 4096
    encoding: str = "UTF-8"
    journal_mode: str = "WAL"
    auto_vacuum: str = "NONE"
    secure_delete: str = "DEFAULT"

    def __post_init__(self) -> None:
        if self.page_size not in PAGE_SIZES:
            raise ValueError(f"page_size must be one of {PAGE_SIZES}")
        if self.encoding not in ENCODINGS:
            raise ValueError(f"encoding must be one of {ENCODINGS}")
        if self.journal_mode not in JOURNAL_MODES:
            raise ValueError(f"journal_mode must be one of {JOURNAL_MODES}")
        if self.auto_vacuum not in AUTO_VACUUM:
            raise ValueError(f"auto_vacuum must be one of {AUTO_VACUUM}")
        if self.secure_delete not in SECURE_DELETE:
            raise ValueError(f"secure_delete must be one of {SECURE_DELETE}")


def canonical(seq: int, ts: str, actor: str, action: str,
              target: str | None, detail: str) -> bytes:
    return json.dumps([seq, ts, actor, action, target, detail],
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def entry_hash(prev_hash: bytes, seq: int, ts: str, actor: str, action: str,
               target: str | None, detail: str) -> bytes:
    return hashlib.sha256(prev_hash + canonical(seq, ts, actor, action, target, detail)).digest()


def verify_row(row) -> bool:
    """row = (seq, ts, actor, action, target, detail, prev_hash, hash)"""
    seq, ts, actor, action, target, detail, prev_hash, stored = row
    return entry_hash(prev_hash, seq, ts, actor, action, target, detail) == stored


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def connect(path: str, cfg: Config = Config()) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)
    # page_size, auto_vacuum and encoding only take effect while the file is new.
    conn.execute(f"PRAGMA page_size = {cfg.page_size}")
    conn.execute(f"PRAGMA auto_vacuum = {cfg.auto_vacuum}")
    conn.execute(f"PRAGMA encoding = '{cfg.encoding}'")
    conn.executescript(SCHEMA)
    conn.execute(f"PRAGMA journal_mode = {cfg.journal_mode}")
    if cfg.secure_delete != "DEFAULT":
        conn.execute(f"PRAGMA secure_delete = {cfg.secure_delete}")
    return conn


class Ledger:
    def __init__(self, path: str, cfg: Config = Config()):
        self.cfg = cfg
        self.conn = connect(path, cfg)

    def close(self) -> None:
        self.conn.close()

    def _head(self) -> tuple[int, bytes]:
        rows = dict(self.conn.execute(
            "SELECT key, value FROM meta WHERE key IN ('head_seq', 'head_hash')"))
        return rows.get("head_seq", 0), rows.get("head_hash", GENESIS)

    def append(self, actor: str, action: str, target: str | None = None,
               detail: dict | None = None, ts: str | None = None) -> int:
        detail_text = json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)
        ts = ts or utc_now()
        c = self.conn
        c.execute("BEGIN IMMEDIATE")
        try:
            seq, prev = self._head()
            seq += 1
            h = entry_hash(prev, seq, ts, actor, action, target, detail_text)
            c.execute("INSERT INTO events (seq, ts, actor, action, target, detail, prev_hash, hash)"
                      " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (seq, ts, actor, action, target, detail_text, prev, h))
            c.executemany("INSERT INTO meta (key, value) VALUES (?, ?)"
                          " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                          [("head_seq", seq), ("head_hash", h)])
            c.execute("COMMIT")
        except BaseException:
            c.execute("ROLLBACK")
            raise
        return seq

    def open_session(self, session_id: str, actor: str, client: str, ts: str | None = None) -> None:
        self.conn.execute("INSERT INTO sessions (id, actor, opened, client) VALUES (?, ?, ?, ?)",
                          (session_id, actor, ts or utc_now(), client))

    def close_session(self, session_id: str, ts: str | None = None) -> None:
        self.conn.execute("UPDATE sessions SET closed = ? WHERE id = ?", (ts or utc_now(), session_id))

    def prune_sessions(self, closed_before: str) -> int:
        cur = self.conn.execute("DELETE FROM sessions WHERE closed IS NOT NULL AND closed < ?",
                                (closed_before,))
        return cur.rowcount

    def verify(self) -> list[str]:
        problems = []
        expected = 1
        for row in self.conn.execute(
                "SELECT seq, ts, actor, action, target, detail, prev_hash, hash FROM events ORDER BY seq"):
            if row[0] != expected:
                problems.append(f"missing seq {expected}..{row[0] - 1}")
            if not verify_row(row):
                problems.append(f"seq {row[0]}: hash mismatch")
            expected = row[0] + 1
        head_seq, _ = self._head()
        if head_seq >= expected:
            problems.append(f"missing seq {expected}..{head_seq}")
        return problems


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ledgerd")
    p.add_argument("--db", required=True)
    p.add_argument("--page-size", type=int, default=4096)
    p.add_argument("--encoding", default="UTF-8")
    p.add_argument("--journal-mode", default="WAL")
    p.add_argument("--auto-vacuum", default="NONE")
    p.add_argument("--secure-delete", default="DEFAULT")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("append")
    a.add_argument("actor")
    a.add_argument("action")
    a.add_argument("--target")
    a.add_argument("--detail", default="{}")
    sub.add_parser("verify")
    args = p.parse_args(argv)

    cfg = Config(args.page_size, args.encoding, args.journal_mode.upper(), args.auto_vacuum.upper(),
                 args.secure_delete.upper())
    ledger = Ledger(args.db, cfg)
    try:
        if args.cmd == "append":
            print(ledger.append(args.actor, args.action, args.target, json.loads(args.detail)))
            return 0
        problems = ledger.verify()
        for line in problems:
            print(line)
        return 1 if problems else 0
    finally:
        ledger.close()


if __name__ == "__main__":
    sys.exit(main())
