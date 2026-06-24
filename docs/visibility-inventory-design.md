# C1 — Visibility foundation: unified inventory + risk intelligence

Design for Phase C1 of the Commercial roadmap. This is the data spine the later
phases (alerting, policy, crypto-agility) read from.

## Goal

One normalized view of **every certificate Certinel knows about**, regardless of
where it came from, each annotated with risk flags and a composite score, exposed
via API (and, in a follow-up task, a UI).

## Sources (existing tables, today)

The inventory is a **source-agnostic aggregation** — it does not introduce a new
authoritative cert store; it reads the tables that already exist and normalizes
them:

| Source key | Table | What it is | Has PEM? |
|---|---|---|---|
| `managed` | `jobs` | Certs issued/managed through Certinel | `cert_pem` (when issued) |
| `fleet` | `fleet_certs` | Certs found by the fleet cert-scan | `pem` (sometimes) + parsed cols |
| `acme` | `acme_certs` | Certs issued by the built-in ACME server | `pem` |

`fleet_certs` already carries `cn / sans_json / issuer / serial / not_before /
expires_at / fingerprint`, so it ingests directly; `managed` and `acme` parse
their PEM via the existing `import_certs.parse_cert()` helper (no new crypto code).

## Source-adapter interface (how discovery plugs in)

The in-progress **discovery add-on** is a *future source*, not a rewrite. Each
source is a callable returning normalized records:

```python
# inventory.py
def _source_managed() -> list[dict]: ...
def _source_fleet()   -> list[dict]: ...
def _source_acme()    -> list[dict]: ...

SOURCES = [_source_managed, _source_fleet, _source_acme]   # discovery appends here
```

When discovery lands it registers `SOURCES.append(_source_discovery)` (or writes
into `fleet_certs`, which the `fleet` adapter already reads) — **no change to the
inventory or risk code**. This keeps C1 decoupled from the parallel discovery work.

## Normalized record

```
{
  "id":          "<source>:<natural-id>",   # e.g. "managed:<jobs.id>", "fleet:<rowid>"
  "source":      "managed|fleet|acme|discovery",
  "cn":          str|None,
  "sans":        [str, ...],
  "issuer":      str|None,
  "serial":      str|None,
  "fingerprint": str|None,                  # sha256, lowercase, colons stripped
  "not_before":  epoch|None,
  "expires_at":  epoch|None,
  "location":    str|None,                  # target_host / fleet host:path / "acme"
  "key_type":    "RSA|EC|...|None",
  "key_bits":    int|None,
  "sig_algo":    str|None,
  "self_signed": bool,
  "risk": { "level": "ok|low|medium|high|critical", "score": int, "flags": [str, ...] }
}
```

Records are deduped by `fingerprint` (a cert seen by multiple sources collapses to
one row, keeping the union of locations).

## Risk scoring (C1 ruleset)

Pure function `score(record, now, warn_days)`; weighted flags → level:

| Flag | Trigger | Weight |
|---|---|---|
| `expired` | `expires_at < now` | critical |
| `expiring_soon` | `0 ≤ expires_at-now ≤ warn_days` (default 30) | high |
| `weak_key` | RSA < 2048, or EC < 256 | high |
| `sha1_signature` | sig algo contains `sha1` | high |
| `self_signed` | issuer == subject and not a known CA | medium |
| `long_validity` | validity span > 398 days | low |
| `no_san` | zero SANs | low |

Level = highest-weight flag present (`critical` > `high` > `medium` > `low` > `ok`);
`score` = summed weights for sorting. `broken_chain` is **out of scope for C1**
(needs trust-store path building) and arrives in C2 alongside alerting.

`key_type / key_bits / sig_algo` come from one supplemental `openssl` read in
`inventory.py` (parse_cert intentionally omits the public key).

## API (`routes_inventory.py`, premium blueprint)

All gated by the `visibility.inventory` capability (build tier + license); a
build/license without it returns `402` with an upsell payload, consistent with
other premium routes.

- `GET /api/inventory` — list; query params `q` (cn/san/issuer substring),
  `source`, `risk` (min level), `expires_within` (days). Admin/auth required.
- `GET /api/inventory/summary` — counts by risk level, by source, and expiry
  buckets (expired / ≤7d / ≤30d / ≤90d). Feeds the dashboard tiles + C2 alerts.
- `GET /api/inventory/<id>` — single normalized record + raw PEM if available.

## Capability + packaging

- New capability `visibility.inventory` in `capabilities.py`, added to
  `COMMERCIAL_CAPABILITIES` (so Commercial + Government builds include it, license
  required to activate).
- `inventory.py` + `routes_inventory.py` added to `deploy.sh` / `verify.sh`
  manifests on Commercial/Government; blueprint joins the premium soft-import loop
  in `app.py`.
- Tests: `tests/test_inventory.py` marked `@pytest.mark.tier(1)` — risk-scoring is
  a pure function and is unit-tested without a DB.

## Out of scope for this phase (tracked for later C1 tasks / C2)

- Inventory **UI** (tiles + table + filters) — follow-up C1 task once the API is in.
- Per-cert **owner assignment / mute** — introduced with C2 alerting (small
  `inventory_meta` table).
- **Chain validation** (`broken_chain`) — C2, uses the trust store.
- **Discovery source adapter** — added when the discovery add-on merges.
