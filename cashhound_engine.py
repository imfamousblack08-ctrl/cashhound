#!/usr/bin/env python3
"""CashHound Engine: zero-sum, hash-chained money ledger in one file.

RECONSTRUCTION from the owner's description (the original file was not available); see README.md.

Spine
  * Every block: hash = sha256(canonical_json({"prev_hash": prev, "payload": payload})),
    canonical_json = json.dumps(sort_keys=True, separators=(",", ":")).
  * Genesis is seq 0 with no entries; its prev_hash = sha256(b"GENESIS_ZERO_SUM_SPINE").hexdigest().
  * Every block's entries sum to exactly 0 (integer credits, no floats) or nothing is written.
Backends
  * SQLite (default; DATABASE_URL unset, a path, or sqlite:///path): WAL + BEGIN IMMEDIATE.
  * Postgres (DATABASE_URL=postgresql://...): psycopg 3, one transaction + pg_advisory_xact_lock.
HTTP
  GET  /healthz             GET /ledger/verify          GET /ledger/balance (X-API-Key)
  POST /webhook/stripe      (Stripe-Signature, HMAC-SHA256, 300 s tolerance)
  POST /ledger/commit       (X-API-Key; {"inflow": int, "allocations": {account: int}, "memo"?})
CLI
  python cashhound_engine.py serve [--host H] [--port P]   (needs STRIPE_WEBHOOK_SECRET)
  python cashhound_engine.py verify                         (exit 0 ok, 1 broken)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GENESIS_SEED = "GENESIS_ZERO_SUM_SPINE"
GENESIS_PREV = hashlib.sha256(GENESIS_SEED.encode()).hexdigest()
MINT_CREDITS = 500
KEY_PREFIX = "ch_live_"
STRIPE_TOLERANCE = 300
LOCK_ID = 0x0CA5_4011D  # pg_advisory_xact_lock key: one writer at a time on the chain
MAX_BODY = 64 * 1024
ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
RESERVED = ("key:", "sys:")  # system accounts; never a target of /ledger/commit


class Reject(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def block_hash(prev_hash: str, payload: dict) -> str:
    return hashlib.sha256(canon({"prev_hash": prev_hash, "payload": payload}).encode()).hexdigest()


def now_ms() -> int:
    return int(time.time() * 1000)


def is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


# ---------------------------------------------------------------- db shim (one code path, two drivers)
class DB:
    def __init__(self, url: str | None = None):
        url = url if url is not None else os.environ.get("DATABASE_URL", "cashhound.sqlite3")
        self.url, self.pg = url, url.startswith(("postgres://", "postgresql://"))
        if self.pg:
            import psycopg  # optional dependency, only for Postgres
            self._connect = lambda: psycopg.connect(url)
        else:
            path = url[len("sqlite:///"):] if url.startswith("sqlite:///") else url
            self._connect = lambda: sqlite3.connect(path, timeout=30, isolation_level=None)
        self.backend = "postgres" if self.pg else "sqlite"

    def tx(self, write: bool = True) -> "Tx":
        return Tx(self, write)


class Tx:
    def __init__(self, db: DB, write: bool):
        self.db, self.write = db, write

    def __enter__(self) -> "Tx":
        self.conn = self.db._connect()
        if self.db.pg:
            if self.write:
                self.conn.execute("SELECT pg_advisory_xact_lock(%s)", (LOCK_ID,))
        else:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA busy_timeout=30000")
            self.conn.execute("BEGIN IMMEDIATE" if self.write else "BEGIN")
        return self

    def __exit__(self, exc_type, *_):
        try:
            if exc_type is None:
                self.conn.commit() if self.db.pg else self.conn.execute("COMMIT")
            else:
                self.conn.rollback() if self.db.pg else self.conn.execute("ROLLBACK")
        finally:
            self.conn.close()
        return False

    def execute(self, sql: str, params=()):
        return self.conn.execute(sql.replace("?", "%s") if self.db.pg else sql, params)

    def one(self, sql, params=()):
        return self.execute(sql, params).fetchone()

    def all(self, sql, params=()):
        return self.execute(sql, params).fetchall()


# ---------------------------------------------------------------- schema (idempotent, versioned)
SCHEMA = {
    1: [  # core spine
        """CREATE TABLE IF NOT EXISTS blocks (
             seq BIGINT PRIMARY KEY, kind TEXT NOT NULL, prev_hash TEXT NOT NULL UNIQUE,
             hash TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, created_at BIGINT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS entries (
             seq BIGINT NOT NULL REFERENCES blocks(seq), account TEXT NOT NULL,
             amount BIGINT NOT NULL, PRIMARY KEY (seq, account))""",
        "CREATE INDEX IF NOT EXISTS ix_entries_account ON entries(account)",
        """CREATE TABLE IF NOT EXISTS api_keys (
             key_hash TEXT PRIMARY KEY, account TEXT NOT NULL UNIQUE, created_at BIGINT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS stripe_events (
             event_id TEXT PRIMARY KEY, seq BIGINT NOT NULL REFERENCES blocks(seq))""",
    ],
}


def init_db(db: DB) -> None:
    with db.tx() as tx:  # writer lock held: safe against concurrent first boots
        tx.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
        done = {r[0] for r in tx.all("SELECT version FROM schema_version")}
        for version in sorted(SCHEMA):
            if version not in done:
                for stmt in SCHEMA[version]:
                    tx.execute(stmt)
                tx.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
        if tx.one("SELECT 1 FROM blocks WHERE seq = 0") is None:
            payload = {"seq": 0, "kind": "genesis", "created_at": 0, "entries": []}
            tx.execute("INSERT INTO blocks (seq, kind, prev_hash, hash, payload, created_at) VALUES (0, 'genesis', ?, ?, ?, 0)",
                       (GENESIS_PREV, block_hash(GENESIS_PREV, payload), canon(payload)))


# ---------------------------------------------------------------- ledger core
def append_block(tx: Tx, kind: str, body: dict, entries=()) -> dict:
    """Append one block on the chain head. Caller holds the writer lock (db.tx())."""
    entries = sorted([str(a), int(n)] for a, n in entries)
    if sum(n for _, n in entries) != 0:
        raise Reject(400, "zero-sum violation: entries do not sum to 0")
    seq, prev = tx.one("SELECT seq, hash FROM blocks ORDER BY seq DESC LIMIT 1")
    seq += 1
    payload = {**body, "seq": seq, "kind": kind, "created_at": now_ms(), "entries": entries}
    h = block_hash(prev, payload)
    tx.execute("INSERT INTO blocks (seq, kind, prev_hash, hash, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
               (seq, kind, prev, h, canon(payload), payload["created_at"]))
    for account, amount in entries:
        tx.execute("INSERT INTO entries (seq, account, amount) VALUES (?, ?, ?)", (seq, account, amount))
    return {"seq": seq, "hash": h, "prev_hash": prev}


def balance(tx: Tx, account: str) -> int:
    return int(tx.one("SELECT COALESCE(SUM(amount), 0) FROM entries WHERE account = ?", (account,))[0])


def authenticate(tx: Tx, presented: str | None) -> str:
    if not presented or not presented.startswith(KEY_PREFIX):
        raise Reject(401, "missing or invalid X-API-Key")
    row = tx.one("SELECT account FROM api_keys WHERE key_hash = ?", (hashlib.sha256(presented.encode()).hexdigest(),))
    if row is None:
        raise Reject(401, "missing or invalid X-API-Key")
    return row[0]


def commit(tx: Tx, account: str, body: dict) -> dict:
    """inflow is drawn from the key's credit account and must equal sum(allocations)."""
    inflow, allocations, memo = body.get("inflow"), body.get("allocations"), body.get("memo", "")
    if not is_int(inflow) or inflow <= 0:
        raise Reject(400, "inflow must be a positive integer")
    if not isinstance(allocations, dict) or not allocations:
        raise Reject(400, "allocations must be a non-empty object {account: credits}")
    for acct, amt in allocations.items():
        if not ACCOUNT_RE.match(acct) or acct.startswith(RESERVED):
            raise Reject(400, f"bad allocation account {acct!r}")
        if not is_int(amt) or amt <= 0:
            raise Reject(400, f"allocation for {acct!r} must be a positive integer")
    if sum(allocations.values()) != inflow:
        raise Reject(400, f"unbalanced: inflow {inflow} != allocations {sum(allocations.values())}")
    if not isinstance(memo, str) or len(memo) > 500:
        raise Reject(400, "memo must be a string of at most 500 chars")
    if balance(tx, account) < inflow:
        raise Reject(402, "insufficient credits")
    entries = [[account, -inflow]] + [[a, n] for a, n in allocations.items()]
    return append_block(tx, "tx", {"inflow": inflow, "memo": memo, "by": account}, entries)


def verify_chain(tx: Tx) -> tuple[bool, str, int]:
    rows = tx.all("SELECT seq, kind, prev_hash, hash, payload FROM blocks ORDER BY seq")
    stored: dict[int, list] = {}
    for seq, account, amount in tx.all("SELECT seq, account, amount FROM entries ORDER BY seq, account"):
        stored.setdefault(int(seq), []).append([account, int(amount)])
    prev = GENESIS_PREV
    for i, (seq, kind, prev_hash, h, raw) in enumerate(rows):
        payload = json.loads(raw)
        if seq != i or payload.get("seq") != seq or payload.get("kind") != kind:
            return False, f"seq/kind mismatch at block {seq}", len(rows)
        if prev_hash != prev:
            return False, f"broken link at block {seq}", len(rows)
        if block_hash(prev_hash, payload) != h:
            return False, f"hash mismatch at block {seq}", len(rows)
        entries = payload.get("entries", [])
        if sum(n for _, n in entries) != 0 or any(not is_int(n) for _, n in entries):
            return False, f"zero-sum violation at block {seq}", len(rows)
        if sorted(entries) != stored.get(seq, []):
            return False, f"entries table disagrees with block {seq}", len(rows)
        prev = h
    if not rows or rows[0][1] != "genesis":
        return False, "genesis missing", len(rows)
    extra = set(stored) - {r[0] for r in rows}
    if extra:
        return False, f"orphan entries for seq {sorted(extra)}", len(rows)
    return True, "ok", len(rows)


# ---------------------------------------------------------------- Stripe
def verify_stripe_signature(payload: bytes, header: str | None, secret: str, now: int | None = None) -> None:
    if not header:
        raise Reject(400, "missing Stripe-Signature")
    parts = [p.split("=", 1) for p in header.split(",") if "=" in p]
    ts = [v for k, v in parts if k.strip() == "t"]
    sigs = [v.strip() for k, v in parts if k.strip() == "v1"]
    if len(ts) != 1 or not ts[0].strip().isdigit() or not sigs:
        raise Reject(400, "malformed Stripe-Signature")
    t = int(ts[0])
    if abs((now if now is not None else int(time.time())) - t) > STRIPE_TOLERANCE:
        raise Reject(400, "Stripe-Signature timestamp outside tolerance")
    expected = hmac.new(secret.encode(), f"{t}.".encode() + payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, s) for s in sigs):
        raise Reject(400, "bad Stripe-Signature")


def handle_stripe_event(db: DB, event: dict) -> dict:
    event_id, etype = event.get("id"), event.get("type")
    if not isinstance(event_id, str) or not event_id:
        raise Reject(400, "event id missing")
    if etype != "checkout.session.completed":
        return {"received": True, "ignored": etype}
    with db.tx() as tx:
        if tx.one("SELECT seq FROM stripe_events WHERE event_id = ?", (event_id,)):
            return {"received": True, "duplicate": True}
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        account = "key:" + key_hash[:24]
        tx.execute("INSERT INTO api_keys (key_hash, account, created_at) VALUES (?, ?, ?)", (key_hash, account, now_ms()))
        block = append_block(tx, "tx", {"inflow": MINT_CREDITS, "memo": "stripe checkout mint", "stripe_event": event_id},
                             [["sys:stripe_clearing", -MINT_CREDITS], [account, MINT_CREDITS]])
        tx.execute("INSERT INTO stripe_events (event_id, seq) VALUES (?, ?)", (event_id, block["seq"]))
    # Shown exactly once; only its sha256 is stored. (Buyer delivery path: see README "Open questions".)
    return {"received": True, "api_key": key, "credits": MINT_CREDITS, "seq": block["seq"]}


# ---------------------------------------------------------------- HTTP
def make_handler(db: DB, stripe_secret: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CashHound"

        def log_message(self, *a):  # quiet; set CASHHOUND_LOG=1 to see request lines
            if os.environ.get("CASHHOUND_LOG"):
                super().log_message(*a)

        def _send(self, status: int, obj: dict):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0 or n > MAX_BODY:
                raise Reject(413, "body too large")
            return self.rfile.read(n)

        def _json(self, raw: bytes) -> dict:
            try:
                obj = json.loads(raw or b"{}")
            except ValueError:
                raise Reject(400, "invalid JSON")
            if not isinstance(obj, dict):
                raise Reject(400, "JSON body must be an object")
            return obj

        def _run(self, fn):
            try:
                self._send(*fn())
            except Reject as r:
                self._send(r.status, {"error": r.msg})
            except Exception as e:  # never leak a half-written block: tx already rolled back
                self._send(500, {"error": f"internal: {type(e).__name__}"})

        def do_GET(self):
            def route():
                if self.path == "/healthz":
                    return 200, {"ok": True, "backend": db.backend}
                if self.path == "/ledger/verify":
                    with db.tx(write=False) as tx:
                        ok, msg, n = verify_chain(tx)
                    return (200 if ok else 500), {"ok": ok, "detail": msg, "blocks": n}
                if self.path == "/ledger/balance":
                    with db.tx(write=False) as tx:
                        acct = authenticate(tx, self.headers.get("X-API-Key"))
                        return 200, {"account": acct, "credits": balance(tx, acct)}
                raise Reject(404, "not found")
            self._run(route)

        def do_POST(self):
            def route():
                if self.path == "/webhook/stripe":
                    raw = self._body()
                    verify_stripe_signature(raw, self.headers.get("Stripe-Signature"), stripe_secret)
                    return 200, handle_stripe_event(db, self._json(raw))
                if self.path == "/ledger/commit":
                    body = self._json(self._body())
                    with db.tx() as tx:
                        acct = authenticate(tx, self.headers.get("X-API-Key"))
                        return 200, {"ok": True, **commit(tx, acct, body)}
                raise Reject(404, "not found")
            self._run(route)

    return Handler


def make_server(db: DB, stripe_secret: str, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    if not stripe_secret:
        raise SystemExit("STRIPE_WEBHOOK_SECRET is required (no default secret)")
    init_db(db)
    return ThreadingHTTPServer((host, port), make_handler(db, stripe_secret))


# ---------------------------------------------------------------- CLI
def _opt(args: list, name: str, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


def main(argv: list[str]) -> int:
    cmd, args = (argv[0] if argv else "serve"), argv[1:]
    db = DB()
    if cmd == "serve":
        srv = make_server(db, os.environ.get("STRIPE_WEBHOOK_SECRET", ""),
                          _opt(args, "--host", "127.0.0.1"), int(_opt(args, "--port", os.environ.get("PORT", "8080"))))
        print(f"CashHound on {srv.server_address} backend={db.backend}", flush=True)
        srv.serve_forever()
        return 0
    if cmd == "verify":
        init_db(db)
        with db.tx(write=False) as tx:
            ok, msg, n = verify_chain(tx)
        print(json.dumps({"ok": ok, "detail": msg, "blocks": n}))
        return 0 if ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
