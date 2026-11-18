# CashHound Engine

This `cashhound_engine.py` was rebuilt from the owner's description; the earlier original was never available to diff.
On 2026-11-20 the owner (John Handy) confirmed this rebuild as the authoritative version.

One file, Python stdlib only (`http.server`, `sqlite3`, `hashlib`, `hmac`, `json`, `secrets`), plus the
optional `psycopg` (v3) import used only when `DATABASE_URL` is a Postgres URL.

## Spine
- Blocks: `hash = sha256(canonical_json({"prev_hash": prev, "payload": payload}))`, canonical JSON =
  `json.dumps(sort_keys=True, separators=(",", ":"))`.
- Genesis: seq 0, no entries, `prev_hash = sha256("GENESIS_ZERO_SUM_SPINE").hexdigest()`
  = `2c255404c1858208b640993d8faa9ba6f73000c43c2284308b4ba10fde9ff1ce`.
- Every block's entries sum to 0 (integer credits only) or nothing is written. Balances are sums over `entries`.
- `verify` re-walks the chain: seq continuity, prev links, hashes, zero-sum, and that the `entries` table matches each block.

## Backends
- SQLite (default; `DATABASE_URL` unset → `./cashhound.sqlite3`, or a path / `sqlite:///path`): WAL, `BEGIN IMMEDIATE`.
- Postgres (`DATABASE_URL=postgresql://...`): one transaction per write, `pg_advisory_xact_lock` serializes appends.
- One small `DB`/`Tx` shim; the SQL is shared (`?` placeholders are rewritten for psycopg).
- Schema is an idempotent, versioned step inside the file (`schema_version` table + `CREATE TABLE IF NOT EXISTS`).

## HTTP
| Route | What |
|---|---|
| `GET /healthz` | `{"ok": true, "backend": ...}` |
| `GET /ledger/verify` | chain check (200 ok / 500 broken) |
| `GET /ledger/balance` | `X-API-Key` → credits left on that key |
| `POST /webhook/stripe` | `Stripe-Signature` (`t=`, `v1=`, HMAC-SHA256 over `t.payload`, 300 s tolerance, `hmac.compare_digest`). On `checkout.session.completed`: mint `ch_live_` + `token_urlsafe(32)`, store only its sha256, commit `sys:stripe_clearing -500 / key:<hash24> +500`. Idempotent on the Stripe event id. Other event types: 200, ignored. |
| `POST /ledger/commit` | `X-API-Key`; body `{"inflow": int, "allocations": {"acct": int, ...}, "memo"?: str}`. `inflow` is drawn from the key's credits and must equal `sum(allocations)`; otherwise 400 and nothing written. 402 if the key holds fewer credits than `inflow`. |

## Bot actions (branch `bot-action-ledger`)
Lean port of agent-lab branch `bot-action-ledger` commit `73128c7` (Alembic migration `0007_bot_action_ledger`
on top of `0006`), per `BOT_WIRING.md`. Any bot touching this ledger records its work on the **same hash chain**
as zero-value blocks (no entries, so zero-sum is untouched):

| Step | HTTP (`X-API-Key`) | CLI (direct DB access) | Block kind |
|---|---|---|---|
| action starts | `POST /bot/start {"bot","action","detail"}` → `start_id` | `SID=$(python cashhound_engine.py start --bot B --action A --detail D)` | `bot_start` |
| action done | `POST /bot/finish {"bot","start_id","detail"}` | `python cashhound_engine.py finish --bot B --start-id "$SID" --detail D` | `bot_finish` |
| end of turn | `POST /bot/turn-end {"bot","detail","start_ids"?}` | `python cashhound_engine.py turn-end --bot B --detail D [--start-ids S1,S2]` | `turn_end` |

- `start_id` = `start_` + 32 hex, one per start. A finish must name an existing start of the **same bot**
  (unknown → 404, another bot's → 409) and each start can be finished **once** (second finish → 409).
  The finish copies the start's `action`. `turn_end` lists the turn's start ids and records which are still `open`.
- Every bot block records `by` = the API key's account (or `cli`), so HTTP posts are tied to a paying key.
- Migration 0007 is schema step 2 inside the file: `bot_starts` (start_id PK, seq, bot, action) and
  `bot_finishes` (start_id PK → bot_starts, seq), created idempotently and recorded in `schema_version`.
  A version-1 ledger gains it on next boot.
- `verify` also checks pairing from the chain itself (each finish follows a start of the same bot, at most one
  finish per start, turn_end ids belong to the bot, bot blocks carry no entries) and that the two side tables
  agree with the chain.

Deliberately left out of the port (and why):
- **Closed list of six bot names and five action kinds** (0007 CHECK / SQLite trigger): those are agent-lab team
  names; CashHound accepts any bot name (1–80 chars) and any `snake_case` action, so "any bot" can post.
- **Separate second hash chain for starts** (`imblabs_bot_starts` with its own genesis): starts live on the one
  CashHound chain instead, which is leaner and links starts and finishes by position as well as ID.
- **Tenants, FORCE RLS, `imblabs_app_runtime` role, SECURITY DEFINER trigger functions, owner/superuser
  UPDATE/DELETE/TRUNCATE triggers**: generic multi-tenant hardening outside CashHound's single-ledger scope.
  Tampering is detected by `verify`, not prevented in the database.
- **Downgrade that refuses while starts exist**: there is no down-migration; schema steps only go forward.
- **`live` / `latest` / `list` read commands**: generic agent-dashboard features; the data is in `blocks`
  (`kind IN ('bot_start','bot_finish','turn_end')`) for anyone who needs to query it.
- Same honest limits as the original: nothing forces a bot to post, a start never finished stays open
  (no expiry), and `bot` is a claim; on HTTP it is at least tied to an API key, on the CLI it is not.

## Run
```bash
export STRIPE_WEBHOOK_SECRET=whsec_...      # required: the server refuses to start without it
python cashhound_engine.py serve --port 8080
python cashhound_engine.py verify           # exit 0 ok, 1 broken
```

Results of the last run are in `smoke_sqlite.txt` and `smoke_postgres.txt`.

## Tests
```bash
python smoke_test.py -v                                                          # SQLite
CASHHOUND_TEST_PG_ADMIN=postgresql://postgres@127.0.0.1:PORT/postgres python smoke_test.py -v   # Postgres (needs psycopg)
```

## Open questions for the diff against the original
- How the buyer receives the minted key. Here it is returned once in the webhook response body (which goes to Stripe, not the buyer); the original may have used a success-page reveal or email.
- Whether `/ledger/commit` spends the key's credits (chosen here) or records an external inflow unrelated to credits.
- Body field names (`inflow`, `allocations`), account naming (`key:`, `sys:` reserved), status codes.
- No append-only DB triggers / row-level security: tampering is detected by `verify`, not prevented.
- `negative_control_pg_no_lock.txt`: with the Postgres advisory lock removed, the two concurrency tests fail (the lock is what serializes appends).
