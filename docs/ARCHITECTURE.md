# Certinel — Architecture & Repo Map

A guide for orienting quickly in the codebase. The app is a Flask + SQLite
service (gunicorn behind nginx) that manages certificate-request jobs through
their lifecycle, with optional notification/chat integrations and a
capability/feature-flag layer for deployment-flexible packaging.

> **Convention (enforced going forward):** code is organized into small,
> single-responsibility files grouped by domain. Route handlers live in
> `routes_<domain>.py` Flask blueprints; shared logic lives in cohesive helper
> modules. No new monoliths — features are added in the file that owns their
> domain, or a new blueprint. Every structural refactor is behavior-preserving
> and proven (see *Refactoring safety* below).

## Request flow

```
client ──TLS──> nginx ──> gunicorn ──> app.py (Flask)
                                         ├─ before_request: auth (CAC mTLS headers
                                         │                  or local session) + CSRF
                                         └─ dispatch to a blueprint route
                                              └─ helpers in app.py core / notify / capabilities
                                                   └─ SQLite (jobs.db)  +  shell helper (openssl/CA)
```

Two auth modes, one per box: **mtls/CAC** (trusts `X-Client-Verify` /
`X-Client-DN` headers from nginx) or **local** (username/password session).
CSRF is enforced via the `X-Requested-With: certinel` header on writes.

## Backend (`backend/`)

### Core
| file | responsibility |
|---|---|
| `app.py` | Flask app wiring + the shared **core**: env/config loading, constant tables (cert types, key algos, seeded templates), the DB connection, `before_request` auth/CSRF, decorators (`require_auth`/`require_admin`/`require_csrf`), identity/session + local-auth helpers, `get_setting`/`set_setting`, the webhook/chat notification engine, `init_db` (schema), and blueprint registration at the tail. Blueprints `from app import (...)` the helpers they need. |
| `notify.py` | Multi-method email (SMG / SMTP / Mailgun / SendGrid / none); secrets masked on read, preserved on blank save. |
| `capabilities.py` | Capability/feature-flag resolver: `available(cap) = entitled (license, offline-verifiable, no phone-home) AND env_supports (detected: egress/fips/selinux/openbao…)`. UI shows on / off / not-licensed / unavailable-here. |
| `sign.py` | Certificate-signing **provider registry** (the CA-signing seam): `manual` / `openbao` (live) / `cyberark` (slot). `sign_csr`/`revoke_cert`/`test_connection` dispatch by provider; `provider_meta()` drives the admin UI. The CA key never resides on the app host (scoped AppRole credential, env-only). |
| `csr_subject.py` | Configurable CSR **subject DN**: org profiles, suggested OU tags, value sanitization, render to the helper's `subject.conf` (parsed, never sourced), DN preview. |

### Route blueprints (one domain each)
| file | mounts | domain |
|---|---|---|
| `routes_auth.py` | `/api/health`, `/api/login` … | health + local-auth endpoints |
| `routes_requests.py` | `/api/rhel/*`, `/api/external/submit` | CSR/key **intake**: certlist, generate, session-key download, external CSR submit |
| `routes_jobs.py` | `/api/jobs/*`, `/api/signing-queue/*` | **job lifecycle**: list/get, csr/cert/key, group reassign, cert upload, cancel/renew, bulk-cancel, mark-failed, export, csr/cert-info |
| `routes_groups.py` | `/api/groups/*`, `/api/my-groups` | self-service group membership |
| `routes_me.py` | `/api/me`, `/api/me/prefs` | current-user profile/prefs |
| `routes_admin.py` | `/api/admin/*`, `/api/fleet-certs/*` | admin: users, groups, templates, audit, fleet certs, email config, cleanup, stats |
| `routes_integrations.py` | `/api/admin/webhooks/*`, `/api/slack/*`, `/api/admin/capabilities` | webhooks CRUD/test, Slack config + signed interactivity callback, capability readout |
| `routes_feedback.py` | `/api/feedback*` | feedback submit + admin triage |
| `routes_signing.py` | `/api/jobs/<id>/sign`, `/api/jobs/<id>/revoke`, `/api/admin/signing-config*` | v2 in-UI signing: approve-&-sign, revoke, provider config + test |

### Standalone / optional
| file | responsibility |
|---|---|
| `slack_listener.py` | Optional Socket Mode listener (outbound-only). Packaged as an installer toggle, not core. |
| `gitlab_integration.py` | Homelab GitLab inbound hook (dormant). |
| `import_certs.py` | One-off cert import utility. |

## Frontend (`frontend/`)
Static SPA served by nginx. `app.js` is split into ordered, independently-parsing pieces:
`app.1-core.js` (auth/bootstrap/api), `app.2-jobs.js` (job views), `app.3-admin.js`
(admin UI + capability hints), `app.4-misc-boot.js` (misc + final `bootstrapAuth()`).
Styles in `app.css`; markup in `index.html`.

## Ops & packaging
- `deploy.sh` — installs repo files to live paths from a `MANIFEST` (idempotent, validates units/nginx, restarts `certinel-api`, checks served VERSION). **Edit the MANIFEST by hand** (a quoting slip via `sed` once corrupted the array).
- `verify.sh` — diffs a repo clone against the live box (`PAIRS`); `ok / missing / drift` counts.
- `tests/test_smoke.py` — Flask test-client smoke net: asserts route **registration** (url_map) + auth + response shapes across every blueprint. Run: `python -m pytest tests/test_smoke.py -q`.
- `.gitlab-ci.yml` — `lint` (py_compile `backend/*.py`, bash -n, node --check JS) + `test` (**hard** smoke-tests gate).
- `helper/`, `systemd/`, `nginx/`, `config/`, `install/`, `make-offline-bundle.sh` — the shell helper (openssl/CA ops), units, web server config, env examples, and the air-gapped bundle builder.

## Refactoring safety (how the blueprint split stayed honest)
Any structural refactor must prove it changed no behavior:
1. **url_map route+method set identical** pre/post (import old vs new, diff the rule list).
2. **pyflakes clean** — no undefined names (catches a helper that didn't move with its caller).
3. **smoke harness 24/24** green.
4. deploy to **csr-dev** → `verify.sh` clean (`missing=0 drift=0`) → certinel-api active.

## Deployment modes (design floor = air-gapped)
A customer runs exactly one: SaaS/cloud, on-prem-with-internet, or air-gapped/STIG.
Every "connected" convenience (chat, email APIs, Slack interactivity) is an
**optional capability** that degrades gracefully; if a feature can't work
offline it is never core. See `docs/product-architecture.md`.
