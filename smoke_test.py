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
import socket
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

    def raw_get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    @staticmethod
    def sid(event_id):  # a well-formed Checkout Session id derived from the event id
        return "cs_test_" + hashlib.sha256(event_id.encode()).hexdigest()[:40]

    def webhook(self, event_id="evt_1", etype="checkout.session.completed", sig=None, session=None, status="paid"):
        raw = json.dumps({"id": event_id, "type": etype,
                          "data": {"object": {"id": session or self.sid(event_id), "payment_status": status}}}).encode()
        return self.req("POST", "/webhook/stripe", raw, {"Stripe-Signature": sig(raw) if sig else sign(raw)})

    def claim(self, session):
        st, headers, page = self.raw_get("/claim?session_id=" + session)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertTrue(headers.get("Content-Type", "").startswith("text/html"))
        return st, page

    @staticmethod
    def key_in(page):
        found = [w for w in page.replace("<", " ").replace(">", " ").split() if w.startswith("ch_live_")]
        return found[0] if found else None

    def mint(self, event_id="evt_1") -> str:
        st, body = self.webhook(event_id)
        self.assertEqual(st, 200, body)
        self.assertNotIn("api_key", body)  # the webhook response goes to Stripe, never the key
        st, page = self.claim(self.sid(event_id))
        self.assertEqual(st, 200, page)
        return self.key_in(page)

    def head(self):
        with self.db.tx(write=False) as tx:
            return tx.one("SELECT seq, hash FROM blocks ORDER BY seq DESC LIMIT 1")

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
            self.assertEqual(tx.all("SELECT api_key FROM key_reveals"), [(None,)])  # plaintext gone after claim
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


class KeyDelivery(Base):
    def test_11_claim_reveals_key_once_with_usage_copy(self):
        self.assertEqual(self.webhook("evt_c1")[0], 200)
        st, page = self.claim(self.sid("evt_c1"))
        self.assertEqual(st, 200, page)
        key = self.key_in(page)
        self.assertTrue(key and key.startswith("ch_live_"))
        for text in ("shown only once", "Credits on this key: 500", "X-API-Key", "/ledger/commit"):
            self.assertIn(text, page)
        self.assertEqual(self.credits(key), 500)
        self.assertEqual(self.commit(key, {"inflow": 10, "allocations": {"ops": 10}})[0], 200)
        with self.db.tx(write=False) as tx:
            api_key, claimed_at = tx.one("SELECT api_key, claimed_at FROM key_reveals WHERE session_id = ?", (self.sid("evt_c1"),))
        self.assertIsNone(api_key)
        self.assertIsNotNone(claimed_at)

    def test_12_second_claim_refused_even_when_concurrent(self):
        self.webhook("evt_c2")
        st, page = self.claim(self.sid("evt_c2"))
        self.assertEqual(st, 200)
        for _ in range(2):
            st, page2 = self.claim(self.sid("evt_c2"))
            self.assertEqual(st, 410)
            self.assertIn("already shown once", page2)
            self.assertIsNone(self.key_in(page2))
        self.webhook("evt_c2b")
        out = []
        ts = [threading.Thread(target=lambda: out.append(self.claim(self.sid("evt_c2b")))) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sorted(st for st, _ in out), [200] + [410] * 7)
        self.assertEqual(sum(1 for _, p in out if self.key_in(p)), 1)

    def test_13_unknown_or_pending_404_and_malformed_400(self):
        sid = self.sid("evt_late")
        st, page = self.claim(sid)
        self.assertEqual(st, 404)
        self.assertIn("refresh in a few seconds", page)
        for bad in ("", "pi_123456789012", "cs_short", "cs_test_abc%27%3Cscript%3E1234567", "cs_test_" + "a" * 300,
                    sid + "&session_id=" + sid):
            st, page = self.claim(bad)
            self.assertEqual(st, 400, bad)
        self.assertEqual(self.raw_get("/claim")[0], 400)
        self.webhook("evt_late")  # webhook arrives after the buyer landed: refresh now works
        st, page = self.claim(sid)
        self.assertEqual(st, 200)
        raw = json.dumps({"id": "evt_badsess", "type": "checkout.session.completed", "data": {"object": {"id": "pi_x"}}}).encode()
        before = self.counts()
        self.assertEqual(self.req("POST", "/webhook/stripe", raw, {"Stripe-Signature": sign(raw)})[0], 400)
        self.assertEqual(self.counts(), before)

    def test_14_unclaimed_reveal_expires_and_is_purged(self):
        self.webhook("evt_old")
        self.webhook("evt_old2")
        with self.db.tx() as tx:
            tx.execute("UPDATE key_reveals SET expires_at = ? WHERE session_id = ?", (ch.now_ms() - 1, self.sid("evt_old")))
            tx.execute("UPDATE key_reveals SET created_at = ?, expires_at = ? WHERE session_id = ?",
                       (ch.now_ms() - ch.REVEAL_TTL_MS - 5, ch.now_ms() - 5, self.sid("evt_old2")))
        self.assertEqual(ch.REVEAL_TTL_MS, 24 * 3600 * 1000)
        st, page = self.claim(self.sid("evt_old"))
        self.assertEqual(st, 410)
        self.assertIn("24-hour", page)
        self.assertIsNone(self.key_in(page))
        with self.db.tx(write=False) as tx:  # the claim purged BOTH expired rows, not only the one asked for
            self.assertEqual(tx.one("SELECT COUNT(*) FROM key_reveals")[0], 0)
        self.webhook("evt_fresh")  # a later webhook also purges, and fresh reveals survive
        with self.db.tx(write=False) as tx:
            self.assertEqual([r[0] for r in tx.all("SELECT session_id FROM key_reveals")], [self.sid("evt_fresh")])
        self.assertTrue(self.verify()[0])

    def test_15_plaintext_never_in_chain(self):
        self.webhook("evt_p")
        with self.db.tx(write=False) as tx:
            key = tx.one("SELECT api_key FROM key_reveals")[0]
            payloads = [r[0] for r in tx.all("SELECT payload FROM blocks")]
            hashes = [r[0] for r in tx.all("SELECT key_hash FROM api_keys")]
        self.assertTrue(key.startswith("ch_live_"))
        self.assertEqual(hashes, [hashlib.sha256(key.encode()).hexdigest()])
        self.assertFalse(any(key in p or key[len("ch_live_"):] in p or "ch_live_" in p for p in payloads))
        self.assertIn(self.sid("evt_p"), payloads[-1])  # the session id (not secret) is on the chain for audit
        self.assertEqual(self.key_in(self.claim(self.sid("evt_p"))[1]), key)
        with self.db.tx(write=False) as tx:
            dump = json.dumps([tx.all(f"SELECT * FROM {t}") for t in
                               ("blocks", "entries", "api_keys", "stripe_events", "stripe_mints", "key_reveals")], default=str)
        self.assertNotIn(key, dump)  # after the claim the plaintext is nowhere in the database

    def test_16_distinct_events_same_session_mint_once(self):
        sess = self.sid("evt_A")
        self.assertEqual(self.webhook("evt_A", session=sess)[0], 200)
        before, head = self.counts(), self.head()
        st, body = self.webhook("evt_B", session=sess)
        self.assertEqual((st, body.get("duplicate"), "api_key" in body), (200, True, False))
        self.assertEqual(self.webhook("evt_B", session=sess)[1].get("duplicate"), True)  # replay of the 2nd event too
        out = []
        ts = [threading.Thread(target=lambda i=i: out.append(self.webhook(f"evt_C{i}", session=sess))) for i in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual([(st, b.get("duplicate")) for st, b in out], [(200, True)] * 8)
        self.assertEqual((self.counts(), self.head()), (before, head))  # nothing new on the chain
        with self.db.tx(write=False) as tx:
            self.assertEqual(tx.one("SELECT COUNT(*) FROM stripe_mints")[0], 1)
            self.assertEqual(tx.one("SELECT COUNT(*) FROM key_reveals")[0], 1)
            self.assertEqual(ch.balance(tx, "sys:stripe_clearing"), -500)
        for et in ch.MINT_EVENTS:  # the UNIQUE (session_id) constraint itself holds, whatever the event type
            with self.assertRaises(Exception):
                with self.db.tx() as tx:
                    tx.execute("INSERT INTO stripe_mints (session_id, event_type, event_id, seq) VALUES (?, ?, 'evt_Z', 1)",
                               (sess, et))
        self.assertEqual(self.claim(sess)[0], 200)
        self.assertTrue(self.verify()[0])

    def test_17_healthz_and_serve_honors_port_and_requires_secret(self):
        self.assertEqual(self.req("GET", "/healthz"), (200, {"ok": True, "backend": BACKEND}))
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        here = os.path.dirname(os.path.abspath(__file__))
        env = {**os.environ, "DATABASE_URL": self.url, "PORT": str(port)}
        env.pop("STRIPE_WEBHOOK_SECRET", None)
        r = subprocess.run([sys.executable, "cashhound_engine.py", "serve"], env=env, cwd=here, capture_output=True,
                           text=True, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("STRIPE_WEBHOOK_SECRET is required", r.stderr)
        proc = subprocess.Popen([sys.executable, "cashhound_engine.py", "serve"], env={**env, "STRIPE_WEBHOOK_SECRET": SECRET},
                                cwd=here, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as resp:
                        self.assertEqual(json.loads(resp.read()), {"ok": True, "backend": BACKEND})
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                self.fail("serve did not come up on $PORT")
        finally:
            proc.terminate()
            proc.communicate(timeout=10)


class PaidGate(Base):
    OK_ = "checkout.session.async_payment_succeeded"
    FAIL_ = "checkout.session.async_payment_failed"

    def mints(self):
        with self.db.tx(write=False) as tx:
            return (tx.one("SELECT COUNT(*) FROM stripe_mints")[0], tx.one("SELECT COUNT(*) FROM key_reveals")[0],
                    ch.balance(tx, "sys:stripe_clearing"))

    def test_18_unpaid_completed_mints_nothing(self):
        before, head = self.counts(), self.head()
        for status in ("unpaid", "no_payment_required", None):
            st, body = self.webhook("evt_u_" + str(status), session=self.sid("s_u"), status=status)
            self.assertEqual((st, body.get("pending"), "api_key" in body), (200, True, False), status)
        st, body = self.webhook("evt_f", etype=self.FAIL_, session=self.sid("s_u"), status="unpaid")
        self.assertEqual((st, body.get("payment_failed")), (200, True))
        self.assertEqual((self.counts(), self.head(), self.mints()), (before, head, (0, 0, 0)))
        st, page = self.claim(self.sid("s_u"))
        self.assertEqual(st, 404)
        self.assertIsNone(self.key_in(page))

    def test_19_unpaid_then_async_succeeded_mints_exactly_once(self):
        sess = self.sid("s_async")
        self.assertEqual(self.webhook("evt_c", session=sess, status="unpaid")[1].get("pending"), True)
        st, body = self.webhook("evt_ok", etype=self.OK_, session=sess)
        self.assertEqual((st, body.get("credits"), body.get("duplicate")), (200, 500, None))
        for eid, et in (("evt_ok", self.OK_), ("evt_ok2", self.OK_), ("evt_c", "checkout.session.completed")):
            self.assertEqual(self.webhook(eid, etype=et, session=sess)[1].get("duplicate"), True, eid)
        self.assertEqual(self.mints(), (1, 1, -500))
        key = self.key_in(self.claim(sess)[1])
        self.assertEqual(self.credits(key), 500)
        self.assertTrue(self.verify()[0])

    def test_20_completed_paid_plus_async_succeeded_mints_once_either_order(self):
        a, b = self.sid("s_ab"), self.sid("s_ba")
        self.assertEqual(self.webhook("evt_ab1", session=a)[1].get("credits"), 500)
        before, head = self.counts(), self.head()
        self.assertEqual(self.webhook("evt_ab2", etype=self.OK_, session=a)[1].get("duplicate"), True)
        self.assertEqual((self.counts(), self.head()), (before, head))
        self.assertEqual(self.webhook("evt_ba1", etype=self.OK_, session=b)[1].get("credits"), 500)
        self.assertEqual(self.webhook("evt_ba2", session=b)[1].get("duplicate"), True)
        out = []  # both event types racing for one fresh session: still a single mint
        ts = [threading.Thread(target=lambda i=i: out.append(self.webhook(
            f"evt_r{i}", etype=(self.OK_ if i % 2 else "checkout.session.completed"), session=self.sid("s_race"))))
            for i in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sorted(b.get("duplicate", False) for _, b in out), [False] + [True] * 7)
        self.assertEqual(self.mints(), (3, 3, -1500))
        self.assertTrue(self.verify()[0])


if __name__ == "__main__":
    print(f"backend={BACKEND} python={sys.version.split()[0]} started={time.strftime('%F %T %Z')}", flush=True)
    unittest.main(verbosity=2)
