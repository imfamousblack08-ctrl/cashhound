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



class BotActions(Base):
    """Port of agent-lab bot-action-ledger 73128c7 (migration 0007): start / finish / end-of-turn."""

    def bot(self, key, route, body):
        return self.req("POST", "/bot/" + route, body, {"X-API-Key": key} if key else {})

    def blocks(self):
        with self.db.tx(write=False) as tx:
            return [(r[0], r[1], r[2], r[3], json.loads(r[4])) for r in
                    tx.all("SELECT seq, kind, prev_hash, hash, payload FROM blocks ORDER BY seq")]

    def test_11_start_finish_turn_end_chain_correctly(self):
        key = self.mint()
        entries_before = self.counts()[1]
        st, s1 = self.bot(key, "start", {"bot": "Project Keeper", "action": "commit_made", "detail": "commit fix"})
        self.assertEqual(st, 200, s1)
        self.assertRegex(s1["start_id"], r"^start_[0-9a-f]{32}$")
        st, s2 = self.bot(key, "start", {"bot": "Project Keeper", "action": "check_run", "detail": "smoke"})
        st, f1 = self.bot(key, "finish", {"bot": "Project Keeper", "start_id": s1["start_id"], "detail": "commit 5524752"})
        self.assertEqual(st, 200, f1)
        st, te = self.bot(key, "turn-end", {"bot": "Project Keeper", "detail": "turn done",
                                            "start_ids": [s1["start_id"], s2["start_id"]]})
        self.assertEqual(st, 200, te)
        self.assertEqual(te["open"], [s2["start_id"]])  # the unfinished start is reported, not hidden
        b = self.blocks()
        self.assertEqual([x[1] for x in b[2:]], ["bot_start", "bot_start", "bot_finish", "turn_end"])
        for prev, cur in zip(b, b[1:]):
            self.assertEqual(cur[2], prev[3])  # every block links to the one before it
        self.assertEqual(b[4][4]["start_id"], s1["start_id"])
        self.assertEqual(b[4][4]["action"], "commit_made")  # finish inherits the start's action
        self.assertEqual(b[5][4]["start_ids"], [s1["start_id"], s2["start_id"]])
        self.assertEqual(b[2][4]["by"], self.req("GET", "/ledger/balance", headers={"X-API-Key": key})[1]["account"])
        self.assertTrue(all(x[4]["entries"] == [] for x in b[2:]))
        self.assertEqual(self.counts()[1], entries_before)  # zero-value: no money moved
        self.assertEqual(self.credits(key), 500)
        self.assertEqual(self.verify(), (True, "ok", 6))

    def test_12_finish_unknown_or_duplicate_start_rejected(self):
        key = self.mint()
        st, s1 = self.bot(key, "start", {"bot": "Side Assistant", "action": "file_changed", "detail": "a.py"})
        self.assertEqual(self.bot(key, "finish", {"bot": "Side Assistant", "start_id": s1["start_id"], "detail": "ok"})[0], 200)
        before = self.counts(), len(self.blocks())
        cases = [
            ("finish", {"bot": "Side Assistant", "start_id": s1["start_id"], "detail": "again"}, 409),         # duplicate
            ("finish", {"bot": "Side Assistant", "start_id": "start_" + "0" * 32, "detail": "x"}, 404),       # unknown
            ("finish", {"bot": "Side Assistant", "start_id": "'; DROP TABLE blocks;--", "detail": "x"}, 404), # malformed
            ("finish", {"bot": "Side Assistant", "detail": "x"}, 404),                                       # missing
            ("turn-end", {"bot": "Side Assistant", "detail": "x", "start_ids": ["start_" + "1" * 32]}, 404),
            ("turn-end", {"bot": "Side Assistant", "detail": "x", "start_ids": "nope"}, 400),
            ("start", {"bot": "Side Assistant", "action": "Bad Action!", "detail": "x"}, 400),
            ("start", {"bot": "", "action": "check_run", "detail": "x"}, 400),
            ("start", {"bot": "Side Assistant", "action": "check_run", "detail": ""}, 400),
        ]
        for route, body, code in cases:
            st, resp = self.bot(key, route, body)
            self.assertEqual(st, code, f"{route} {body}: {resp}")
        st, s2 = self.bot(key, "start", {"bot": "C1 Claims Wording", "action": "check_run", "detail": "x"})
        before = self.counts(), len(self.blocks())
        st, resp = self.bot(key, "finish", {"bot": "Side Assistant", "start_id": s2["start_id"], "detail": "steal"})
        self.assertEqual(st, 409, resp)  # another bot's start
        self.assertEqual(self.bot(None, "start", {"bot": "x", "action": "check_run", "detail": "x"})[0], 401)
        self.assertEqual(self.bot("ch_live_bogus", "finish", {"bot": "C1 Claims Wording", "start_id": s2["start_id"], "detail": "x"})[0], 401)
        self.assertEqual((self.counts(), len(self.blocks())), before)
        self.assertTrue(self.verify()[0])

    def test_13_bot_block_tampering_makes_verify_fail(self):
        key = self.mint()
        _, s1 = self.bot(key, "start", {"bot": "Project Keeper", "action": "status_update", "detail": "go"})
        _, f1 = self.bot(key, "finish", {"bot": "Project Keeper", "start_id": s1["start_id"], "detail": "done"})
        with self.db.tx(write=False) as tx:
            orig = tx.one("SELECT payload FROM blocks WHERE seq = ?", (f1["seq"],))[0]
        # 1) edit the finish detail: hash mismatch
        with self.db.tx() as tx:
            tx.execute("UPDATE blocks SET payload = ? WHERE seq = ?", (orig.replace('"done"', '"forged"'), f1["seq"]))
        self.assertEqual(self.verify()[1], f"hash mismatch at block {f1['seq']}")
        # 2) re-point the finish (the chain tail) at a start that never existed AND recompute its hash:
        #    the hash chain is then internally consistent, so only the start/finish pairing check catches it
        p = json.loads(orig)
        p["start_id"] = "start_" + "f" * 32
        with self.db.tx() as tx:
            tx.execute("UPDATE blocks SET payload = ?, hash = ? WHERE seq = ?",
                       (ch.canon(p), ch.block_hash(f1["prev_hash"], p), f1["seq"]))
        ok, msg, _ = self.verify()
        self.assertFalse(ok)
        self.assertIn("finish does not pair", msg)
        # 3) restore the block, then delete the finish row from the side table: tables disagree with chain
        with self.db.tx() as tx:
            tx.execute("UPDATE blocks SET payload = ?, hash = ? WHERE seq = ?", (orig, f1["hash"], f1["seq"]))
        self.assertTrue(self.verify()[0])
        with self.db.tx() as tx:
            tx.execute("DELETE FROM bot_finishes WHERE start_id = ?", (s1["start_id"],))
        self.assertEqual(self.verify()[1], "bot_starts/bot_finishes tables disagree with the chain")

    def test_14_cli_start_finish_turn_end(self):
        env = {**os.environ, "DATABASE_URL": self.url}
        here = os.path.dirname(os.path.abspath(__file__))
        run = lambda *a: subprocess.run([sys.executable, "cashhound_engine.py", *a], capture_output=True, text=True, env=env, cwd=here)
        r = run("start", "--bot", "Ledger Durability", "--action", "check_run", "--detail", "pytest")
        self.assertEqual(r.returncode, 0, r.stderr)
        sid = r.stdout.strip()
        self.assertRegex(sid, r"^start_[0-9a-f]{32}$")
        self.assertEqual(run("finish", "--bot", "Ledger Durability", "--start-id", sid, "--detail", "9 passed").returncode, 0)
        self.assertEqual(run("finish", "--bot", "Ledger Durability", "--start-id", sid, "--detail", "again").returncode, 2)
        self.assertEqual(run("finish", "--bot", "Ledger Durability", "--start-id", "start_" + "a" * 32, "--detail", "x").returncode, 2)
        r = run("turn-end", "--bot", "Ledger Durability", "--detail", "turn done", "--start-ids", sid)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["open"], [])
        self.assertEqual([x[4]["by"] for x in self.blocks()[1:]], ["cli", "cli", "cli"])
        self.assertEqual(run("verify").returncode, 0)

    def test_15_concurrent_bots_and_commits_keep_chain_valid(self):
        key = self.mint()
        bots, per, errors = ["C3 Security Fix", "C1 Claims Wording", "Ledger Durability",
                             "Proof Path Vertical", "Side Assistant", "Project Keeper"], 5, []

        def worker(bot):
            sids = []
            for j in range(per):
                st, s = self.bot(key, "start", {"bot": bot, "action": "check_run", "detail": f"{bot} {j}"})
                st2, _ = self.bot(key, "finish", {"bot": bot, "start_id": s.get("start_id"), "detail": "ok"})
                st3, _ = self.commit(key, {"inflow": 1, "allocations": {"ops": 1}})
                sids.append(s.get("start_id"))
                errors.extend(x for x in (st, st2, st3) if x != 200)
            st, te = self.bot(key, "turn-end", {"bot": bot, "detail": "turn", "start_ids": sids})
            if st != 200 or te["open"]:
                errors.append((st, te))

        ts = [threading.Thread(target=worker, args=(b,)) for b in bots]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errors, [])
        ok, msg, n = self.verify()
        self.assertEqual((ok, msg, n), (True, "ok", 2 + len(bots) * (3 * per + 1)))
        self.assertEqual(self.credits(key), 500 - len(bots) * per)
        with self.db.tx(write=False) as tx:
            self.assertEqual(tx.one("SELECT COUNT(*) FROM bot_finishes")[0], len(bots) * per)

    def test_16_schema_step_is_idempotent_and_upgrades_a_v1_ledger(self):
        for _ in range(2):
            ch.init_db(self.db)
        with self.db.tx(write=False) as tx:
            self.assertEqual(sorted(r[0] for r in tx.all("SELECT version FROM schema_version")), [1, 2])
        # Roll this DB back to a pre-bot-action ledger (version 1 only) holding a money block...
        with self.db.tx() as tx:
            tx.execute("DROP TABLE bot_finishes")
            tx.execute("DROP TABLE bot_starts")
            tx.execute("DELETE FROM schema_version WHERE version = 2")
            ch.append_block(tx, "tx", {"memo": "pre-0007"}, [["a", -1], ["b", 1]])
        # ...then the next boot applies the 0007 step and the old chain still verifies.
        ch.init_db(self.db)
        with self.db.tx(write=False) as tx:
            self.assertEqual(sorted(r[0] for r in tx.all("SELECT version FROM schema_version")), [1, 2])
        with self.db.tx() as tx:
            ch.bot_start(tx, {"bot": "Project Keeper", "action": "status_update", "detail": "after upgrade"}, "test")
        self.assertEqual(self.verify(), (True, "ok", 3))

if __name__ == "__main__":
    print(f"backend={BACKEND} python={sys.version.split()[0]} started={time.strftime('%F %T %Z')}", flush=True)
    unittest.main(verbosity=2)
