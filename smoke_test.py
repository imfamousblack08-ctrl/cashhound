"""CashHound smoke tests: the same cases on SQLite and on Postgres.

  python smoke_test.py -v                                    # SQLite (temp file per test)
  CASHHOUND_TEST_PG_ADMIN=postgresql://postgres@127.0.0.1:PORT/postgres python smoke_test.py -v
      # Postgres: a fresh scratch database per test, dropped afterwards
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

import cashhound_engine as ch

SECRET = "whsec_test_" + "s" * 24
PG_ADMIN = os.environ.get("CASHHOUND_TEST_PG_ADMIN")
BACKEND = "postgres" if PG_ADMIN else "sqlite"


def sign(payload: bytes, secret: str = SECRET, t: int | None = None) -> str:
    t = int(time.time()) if t is None else t
    return f"t={t},v1=" + hmac.new(secret.encode(), f"{t}.".encode() + payload, hashlib.sha256).hexdigest()


class Base(unittest.TestCase):
    _n = 0

    def setUp(self):
        Base._n += 1
        if PG_ADMIN:
            import psycopg
            self.dbname = f"ch_smoke_{os.getpid()}_{Base._n}"
            with psycopg.connect(PG_ADMIN, autocommit=True) as c:
                c.execute(f"DROP DATABASE IF EXISTS {self.dbname}")
                c.execute(f"CREATE DATABASE {self.dbname}")
            self.url = PG_ADMIN.rsplit("/", 1)[0] + "/" + self.dbname
        else:
            self.tmp = tempfile.TemporaryDirectory()
            self.url = os.path.join(self.tmp.name, "ch.sqlite3")
        self.db = ch.DB(self.url)
        self.srv = ch.make_server(self.db, SECRET, "127.0.0.1", 0)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        if PG_ADMIN:
            import psycopg
            with psycopg.connect(PG_ADMIN, autocommit=True) as c:
                c.execute(f"DROP DATABASE IF EXISTS {self.dbname} WITH (FORCE)")
        else:
            self.tmp.cleanup()

    # -- helpers
    def req(self, method, path, body=None, headers=None):
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def webhook(self, event_id="evt_1", etype="checkout.session.completed", sig=None):
        raw = json.dumps({"id": event_id, "type": etype, "data": {"object": {"id": "cs_" + event_id}}}).encode()
        return self.req("POST", "/webhook/stripe", raw, {"Stripe-Signature": sig(raw) if sig else sign(raw)})

    def mint(self, event_id="evt_1") -> str:
        st, body = self.webhook(event_id)
        self.assertEqual(st, 200, body)
        return body["api_key"]

    def commit(self, key, body):
        return self.req("POST", "/ledger/commit", body, {"X-API-Key": key} if key else {})

    def counts(self):
        with self.db.tx(write=False) as tx:
            return tuple(tx.one(f"SELECT COUNT(*) FROM {t}")[0] for t in ("blocks", "entries", "api_keys"))

    def verify(self):
        with self.db.tx(write=False) as tx:
            return ch.verify_chain(tx)

    def credits(self, key):
        st, body = self.req("GET", "/ledger/balance", headers={"X-API-Key": key})
        self.assertEqual(st, 200, body)
        return body["credits"]


class Core(Base):
    def test_01_genesis_present_and_chain_verifies(self):
        with self.db.tx(write=False) as tx:
            seq, kind, prev, h, payload = tx.one("SELECT seq, kind, prev_hash, hash, payload FROM blocks WHERE seq = 0")
        self.assertEqual((seq, kind), (0, "genesis"))
        self.assertEqual(prev, hashlib.sha256(b"GENESIS_ZERO_SUM_SPINE").hexdigest())
        self.assertEqual(json.loads(payload)["entries"], [])
        self.assertEqual(h, ch.block_hash(prev, json.loads(payload)))
        self.assertEqual(self.verify(), (True, "ok", 1))
        self.assertEqual(self.req("GET", "/healthz"), (200, {"ok": True, "backend": BACKEND}))
        self.assertEqual(self.req("GET", "/ledger/verify")[1]["ok"], True)
        cli = subprocess.run([sys.executable, "cashhound_engine.py", "verify"], capture_output=True, text=True,
                             env={**os.environ, "DATABASE_URL": self.url}, cwd=os.path.dirname(os.path.abspath(__file__)))
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertTrue(json.loads(cli.stdout)["ok"])

    def test_02_refuses_to_start_without_webhook_secret(self):
        with self.assertRaises(SystemExit):
            ch.make_server(self.db, "", "127.0.0.1", 0)

    def test_03_webhook_valid_signature_mints_key_with_500_credits(self):
        key = self.mint()
        self.assertTrue(key.startswith("ch_live_"))
        self.assertEqual(self.credits(key), 500)
        with self.db.tx(write=False) as tx:
            stored = [r[0] for r in tx.all("SELECT key_hash FROM api_keys")]
            self.assertEqual(ch.balance(tx, "sys:stripe_clearing"), -500)
        self.assertEqual(stored, [hashlib.sha256(key.encode()).hexdigest()])  # only the hash is stored
        self.assertTrue(self.verify()[0])

    def test_04_webhook_bad_signature_rejected(self):
        before = self.counts()
        cases = {
            "wrong secret": lambda raw: sign(raw, "whsec_wrong"),
            "stale timestamp": lambda raw: sign(raw, t=int(time.time()) - 301),
            "garbage": lambda raw: "t=abc,v1=zz",
        }
        for name, sig in cases.items():
            st, body = self.webhook(sig=sig)
            self.assertEqual(st, 400, f"{name}: {body}")
        raw = b'{"id":"evt_x","type":"checkout.session.completed"}'
        self.assertEqual(self.req("POST", "/webhook/stripe", raw)[0], 400)  # missing header
        st, _ = self.req("POST", "/webhook/stripe", raw + b" ", {"Stripe-Signature": sign(raw)})  # body altered
        self.assertEqual(st, 400)
        self.assertEqual(self.counts(), before)

    def test_05_webhook_replay_credits_only_once(self):
        key = self.mint("evt_replay")
        for _ in range(3):
            st, body = self.webhook("evt_replay")
            self.assertEqual((st, body.get("duplicate"), "api_key" in body), (200, True, False))
        self.assertEqual(self.counts(), (2, 2, 1))
        self.assertEqual(self.credits(key), 500)
        st, body = self.webhook("evt_other", etype="invoice.paid")
        self.assertEqual((st, body.get("ignored")), (200, "invoice.paid"))
        self.assertEqual(self.counts(), (2, 2, 1))

    def test_06_balanced_commit_accepted(self):
        key = self.mint()
        st, body = self.commit(key, {"inflow": 100, "allocations": {"ops": 60, "reserve": 40}, "memo": "split"})
        self.assertEqual(st, 200, body)
        self.assertEqual(body["seq"], 2)
        self.assertEqual(self.credits(key), 400)
        with self.db.tx(write=False) as tx:
            self.assertEqual((ch.balance(tx, "ops"), ch.balance(tx, "reserve")), (60, 40))
            self.assertEqual(tx.one("SELECT COALESCE(SUM(amount),0) FROM entries")[0], 0)  # zero-sum spine
        self.assertEqual(self.verify(), (True, "ok", 3))

    def test_07_unbalanced_commit_rejected_nothing_written(self):
        key = self.mint()
        before = self.counts()
        bad = [
            {"inflow": 100, "allocations": {"ops": 60, "reserve": 39}},   # unbalanced
            {"inflow": 100, "allocations": {"ops": 101}},                 # unbalanced the other way
            {"inflow": 10.0, "allocations": {"ops": 10}},                 # float
            {"inflow": 10, "allocations": {"ops": 10.0}},                 # float
            {"inflow": 10, "allocations": {"ops": -5, "x": 15}},          # negative allocation
            {"inflow": 0, "allocations": {"ops": 0}},
            {"inflow": 10, "allocations": {}},
            {"inflow": 10, "allocations": {"key:someone": 10}},           # reserved account
            {"inflow": 10, "allocations": {"sys:stripe_clearing": 10}},   # reserved account
        ]
        for b in bad:
            st, body = self.commit(key, b)
            self.assertEqual(st, 400, f"{b}: {body}")
        st, body = self.commit(key, {"inflow": 501, "allocations": {"ops": 501}})  # more than the key holds
        self.assertEqual(st, 402, body)
        self.assertEqual(self.req("POST", "/ledger/commit", b"{not json", {"X-API-Key": key})[0], 400)
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.credits(key), 500)
        self.assertTrue(self.verify()[0])

    def test_08_bad_or_missing_api_key_rejected(self):
        self.mint()
        before = self.counts()
        good = {"inflow": 1, "allocations": {"ops": 1}}
        for key in (None, "", "sk_live_nope", "ch_live_" + "A" * 43):
            st, body = self.commit(key, good)
            self.assertEqual(st, 401, f"{key!r}: {body}")
        self.assertEqual(self.req("GET", "/ledger/balance", headers={"X-API-Key": "ch_live_x"})[0], 401)
        self.assertEqual(self.counts(), before)

    def test_09_tampering_makes_verify_fail(self):
        key = self.mint()
        self.assertEqual(self.commit(key, {"inflow": 50, "allocations": {"ops": 50}})[0], 200)
        self.assertTrue(self.verify()[0])
        with self.db.tx(write=False) as tx:
            orig = tx.one("SELECT payload FROM blocks WHERE seq = 2")[0]
        tampers = [
            ("UPDATE blocks SET payload = ? WHERE seq = 2", (orig.replace('"memo":""', '"memo":"x"'),), "hash mismatch at block 2"),
            ("UPDATE entries SET amount = 49 WHERE seq = 2 AND account = 'ops'", (), "entries table disagrees with block 2"),
            ("UPDATE blocks SET prev_hash = ? WHERE seq = 2", ("0" * 64,), "broken link at block 2"),
        ]
        undo = ["UPDATE blocks SET payload = ? WHERE seq = 2", "UPDATE entries SET amount = 50 WHERE seq = 2 AND account = 'ops'", None]
        for (sql, params, expect), u in zip(tampers, undo):
            with self.db.tx() as tx:
                prev_hash = tx.one("SELECT prev_hash FROM blocks WHERE seq = 2")[0]
                tx.execute(sql, params)
            ok, msg, _ = self.verify()
            self.assertFalse(ok)
            self.assertEqual(msg, expect)
            self.assertEqual(self.req("GET", "/ledger/verify")[0], 500)
            with self.db.tx() as tx:  # restore for the next tamper
                if u == undo[0]:
                    tx.execute(u, (orig,))
                elif u:
                    tx.execute(u)
                else:
                    tx.execute("UPDATE blocks SET prev_hash = ? WHERE seq = 2", (prev_hash,))
            self.assertTrue(self.verify()[0])

    def test_10_concurrent_commits_keep_chain_valid(self):
        key = self.mint()
        workers, per = 8, 10
        results, errors = [], []

        def worker(i):
            for j in range(per):
                st, body = self.commit(key, {"inflow": 5, "allocations": {f"w{i}": 3, "pool": 2}})
                (results if st == 200 else errors).append((st, body))

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errors, [])
        self.assertEqual(sorted(r[1]["seq"] for r in results), list(range(2, 2 + workers * per)))
        self.assertEqual(self.credits(key), 500 - 5 * workers * per)
        ok, msg, n = self.verify()
        self.assertEqual((ok, msg, n), (True, "ok", 2 + workers * per))
        with self.db.tx(write=False) as tx:
            self.assertEqual(tx.one("SELECT COUNT(DISTINCT prev_hash) FROM blocks")[0], n)  # no forks
            self.assertEqual(ch.balance(tx, "pool"), 2 * workers * per)


if __name__ == "__main__":
    print(f"backend={BACKEND} python={sys.version.split()[0]} started={time.strftime('%F %T %Z')}", flush=True)
    unittest.main(verbosity=2)
