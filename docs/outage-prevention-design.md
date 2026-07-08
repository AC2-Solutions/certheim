# C2 — Outage prevention: alerting, ownership, escalation, CT-log monitoring

Design for Phase C2 of the Commercial roadmap. C1 gave us a unified inventory with
risk scoring; C2 makes it *act* — so a cert that's about to expire reaches the
person who can fix it before it takes a service down.

This phase also absorbs the two items deferred from C1: per-cert **ownership/mute**
and **chain validation** (`broken_chain`), because both pair naturally with
alerting (you route alerts to owners; a broken chain is an alertable condition).

## What already exists (and what C2 generalizes)

A `certinel-expiry-warn` systemd timer runs `run_expiry_warnings()`
(`routes_admin.py`), which warns on soon-to-expire `fleet_certs` using an
`expiry_warned` flag to avoid re-warning, sending via `notify.py` (email) and the
chat path. C2 **generalizes this single pass into an inventory-wide alerting
engine** with tiers, escalation, ownership routing, and proper alert-state
tracking — and keeps the existing timer as its scheduler.

## Increment C2.1 — Ownership, mute, and chain validation *(this increment)*

The routing + enrichment foundation the alerting engine needs.

- **`inventory_meta` table** keyed by cert fingerprint:
  `fingerprint TEXT PRIMARY KEY, owner TEXT, owner_email TEXT, muted INTEGER,
   notes TEXT, updated_at REAL, updated_by TEXT`.
  Keyed by fingerprint (not source row id) so ownership follows the *cert*, even
  when it's seen by multiple sources or re-discovered.
- **Inventory enrichment**: `inventory.collect()` left-joins `inventory_meta`, so
  every record carries `owner`, `owner_email`, `muted`, `notes`.
- **Chain validation** (`broken_chain` flag): for records with a PEM, verify
  against the trust-store bundle (`truststore` module) via `openssl verify`;
  cache the verdict in `inventory_meta` (`chain_ok`, `chain_checked_at`) so we
  don't re-run openssl on every list call. Flag weight: medium. Unverifiable
  (no PEM) → no flag, not a failure.
- **API** (admin, gated by `visibility.inventory`):
  `POST /api/inventory/<id>/owner` `{owner, owner_email}`,
  `POST /api/inventory/<id>/mute` `{muted}`.
  Muted certs keep their risk score but are excluded from alerts (C2.2).
- **UI**: owner column + inline "Assign owner" and "Mute" actions in the
  inventory table; a `muted` visual treatment.
- Tests: meta upsert + enrichment join + chain-flag logic (tier(1)).

## Increment C2.2 — Alerting engine + escalation

- **`alerts.py`**: an inventory-wide pass (replaces the fleet-only warn loop).
  Tiers by days-to-expiry (default `30, 14, 7, 1`, admin-configurable) plus an
  `expired` tier and a `risk` tier (critical/high non-expiry findings, e.g.
  `broken_chain`, `weak_key`). Each (fingerprint, tier) fires **once** — tracked
  in an **`alert_state`** table (`fingerprint, tier, first_alerted, last_alerted,
  acknowledged`) so we never re-spam, and an escalating tier is a new, louder
  alert rather than a repeat.
- **Routing**: to the cert's `inventory_meta.owner_email` if set, else the
  source's contact (`fleet_certs.notify_email` / `jobs.requester_email`), else the
  admin default recipients — over the existing `notify.py` email + chat channels.
- **Escalation**: when a cert crosses into a nearer tier (30→7→1→expired) without
  being renewed/acknowledged, the alert escalates (priority + optionally a wider
  recipient set / different channel).
- **SLA tracking**: record time-in-tier; surface "N certs past their renewal SLA"
  in the summary and the digest.
- **Admin config** (`routes_admin` settings): tier thresholds, channels per tier,
  escalation recipients, quiet hours. Scheduler stays the `certinel-expiry-warn`
  timer (renamed/aliased to a general alerts pass).

## Increment C2.3 — Scheduled expiry digests

- A periodic **per-owner digest** (daily/weekly, admin-configurable) summarizing
  that owner's at-risk certs — a calm rollup that complements the per-event
  alerts, over email/chat. Owners with nothing at risk get nothing.

## Increment C2.4 — CT-log / shadow-cert monitoring

- Poll **Certificate Transparency** (e.g. crt.sh / a CT API) for the org's
  configured domains; surface certs **issued for your domains that Certheim
  didn't issue and isn't tracking** as a new inventory source (`ct`) and an
  alertable finding (possible mis-issuance / shadow IT).
- Admin config: monitored domains, poll cadence; gated as an
  `egress_internet` capability (air-gapped builds simply don't offer it).

## Packaging (every increment)

- Premium, under the existing `visibility.inventory` capability (alerting is part
  of the same Commercial visibility bundle); CT-log adds an `egress_internet`
  env requirement.
- New modules/tables added to `deploy.sh`/`verify.sh` manifests and the premium
  soft-import path; tier(1) tests; bottom-up propagation Commercial → Government.

## Out of scope (later phases)

- Renewal *automation* triggered by an alert — `lifecycle.auto_renew` already
  exists; C2 links to it ("renew now") but the policy lives in C4.
- Multi-tenant alert routing by team — lands with C3 RBAC; C2 routes by
  per-cert owner + source contact + admin default.
