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
| `GET /claim?session_id=cs_...` | One-time HTML reveal of the key minted for that Checkout Session (see "Buyer key delivery"). |
| `POST /webhook/stripe` | `Stripe-Signature` (`t=`, `v1=`, HMAC-SHA256 over `t.payload`, 300 s tolerance, `hmac.compare_digest`). On `checkout.session.completed`: mint `ch_live_` + `token_urlsafe(32)`, store its sha256 in `api_keys`, commit `sys:stripe_clearing -500 / key:<hash24> +500` (block records event id + session id, never the key), and park the plaintext in `key_reveals` for `/claim`. The key is **not** in the webhook response (that goes to Stripe). Idempotent on the Stripe event id **and** on `(data.object.id, event.type)` (UNIQUE in `stripe_mints`): a second, distinct event for the same session returns `200 {"duplicate": true}` and writes nothing to the chain. `data.object.id` must look like `cs_...` (else 400). Other event types: 200, ignored. |
| `POST /ledger/commit` | `X-API-Key`; body `{"inflow": int, "allocations": {"acct": int, ...}, "memo"?: str}`. `inflow` is drawn from the key's credits and must equal `sum(allocations)`; otherwise 400 and nothing written. 402 if the key holds fewer credits than `inflow`. |

## Buyer key delivery
- Set the Stripe Payment Link's success URL (after-payment redirect) to
  `https://<host>/claim?session_id={CHECKOUT_SESSION_ID}` (Stripe fills in the literal `{CHECKOUT_SESSION_ID}`).
- The plaintext key is kept only in the `key_reveals` table, outside every block payload, until it is claimed.
- `GET /claim` shows the key, its credits, and how to send it as `X-API-Key` to `POST /ledger/commit`, then sets the
  stored plaintext to NULL in the same transaction. Responses carry `Cache-Control: no-store`,
  `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`.
- 200 = revealed (once) · 410 = already claimed, or minted but the 24 h window passed · 400 = malformed `session_id`
  (`^cs_(test_|live_)?[A-Za-z0-9]{8,250}$`) · 404 = no mint for that session yet: the page says "payment processing,
  refresh in a few seconds". The engine has no Stripe API key, so it cannot tell "webhook not arrived yet" from
  "unknown id"; both are 404 with that page.
- Unclaimed reveals expire after 24 h and are purged on the next webhook or claim. After that the key still works
  but nobody can see it again (no recovery path yet).

## Run
```bash
export STRIPE_WEBHOOK_SECRET=whsec_...      # required: the server refuses to start without it
python cashhound_engine.py serve --port 8080
python cashhound_engine.py verify           # exit 0 ok, 1 broken
```
Environment: `STRIPE_WEBHOOK_SECRET` (required), `DATABASE_URL` (default `./cashhound.sqlite3`; Postgres URL needs
`psycopg`), `PORT` (used when `--port` is not given; default 8080), `HOST` (used when `--host` is not given; default
`127.0.0.1`; set `HOST=0.0.0.0` on Render or any container host), `CASHHOUND_LOG` (optional, request logging).

## Tests
```bash
python smoke_test.py -v                                                          # SQLite
CASHHOUND_TEST_PG_ADMIN=postgresql://postgres@127.0.0.1:PORT/postgres python smoke_test.py -v   # Postgres (needs psycopg)
```

## Open questions for the diff against the original
- Whether `/ledger/commit` spends the key's credits (chosen here) or records an external inflow unrelated to credits.
- Body field names (`inflow`, `allocations`), account naming (`key:`, `sys:` reserved), status codes.
- No append-only DB triggers / row-level security: tampering is detected by `verify`, not prevented.
