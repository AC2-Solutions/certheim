# Changelog

All notable changes to the CSR Dashboard. Versions track the `VERSION` file
(the app reports it at `/api/health` and on the admin Overview tile).

## 2.4.0 — 2026-06-18

### Added / Changed
- (signing) cloud DNS-01 solvers for ACME (Cloudflare/Route53/Azure) [phase 2]

## 2.3.0 — 2026-06-18

### Added / Changed
- (signing) ACME (RFC 8555) client provider [phase 1]

## 2.2.0 — 2026-06-18

### Added / Changed
- (renew) automated certificate renewal loop

### Fixed
- (audit) make log_event safe outside a request context
- (deploy) ship backend/renew.py in the deploy + verify manifests

## 2.1.0 — 2026-06-18

### Added / Changed
- (fleet) auto-track issued certs in fleet monitoring
- (signing) Windows CA (AD CS) provider — sign via certreq over SSH

### Fixed
- (groups) assign a user to multiple groups in one Save (user-edit modal)
- (audit) missing sqlite3/Path imports (500s) + unregistered webhook events

## 2.0.0

In-UI certificate **signing** (the cert is produced by a CA backend, not just
an out-of-band upload), a configurable **organization identity**, and a large
internal restructure. See `RELEASE-NOTES-v2.0.0.md` for the narrative.

### Added
- **In-UI CA signing (OpenBao PKI)** — approval-gated `POST /api/jobs/<id>/sign`:
  a signer/admin approves and the cert is issued via the CA backend, feeding the
  same verify → `issued` → filesystem-drop → webhook → email path as a manual
  upload. New `backend/sign.py` provider seam; the CA key never touches the app
  (scoped AppRole credential, env-only). Admin **Signing / CA** tab + per-job
  **Approve & sign** with cert-chain download.
- **Pluggable signing providers** — provider registry (manual / OpenBao /
  CyberArk slot); admins pick the provider and set its connection in the UI.
  OpenBao fully implemented; CyberArk is a configurable slot pending an instance.
- **Per-template signing policy + auto-sign** — `jobs.template_id`;
  `resolve_signing_policy()` lets a template override the global default
  (backend/role/TTL) or inherit it; `auto_sign` issues on request. Admin
  template editor gains a Signing column.
- **Certificate revocation + CRL/OCSP** — `POST /api/jobs/<id>/revoke`
  (signer/admin), a `revoked` job state, a Revoke button on issued jobs; CRL/OCSP
  distribution points surfaced.
- **Configurable CSR subject / organization identity** — the subject DN
  (`C/ST/L/O/OUs/domain`) is no longer hardcoded; an admin **CSR Subject** tab
  with org-profile presets (DoD + services, Federal Civilian, Commercial),
  add/remove **OU tags**, a live DN preview, and a first-run (OOBE) prompt. The
  helper parses (never sources) an admin-written `subject.conf`.
- **Capability / feature-flag layer** (`backend/capabilities.py`) — features
  resolve as entitled (offline, no phone-home) AND env-supported; the UI shows
  on / off / not-licensed / unavailable-here.
- **Endpoint smoke harness** (`tests/test_smoke.py`) gating every change, run as
  a hard CI stage.

### Changed
- **`app.py` decomposed into Flask blueprints** —
  `routes_{auth,jobs,requests,groups,me,admin,integrations,feedback,signing}.py`
  (app.py 5,248 → ~1,700-line core). Behavior-preserving (url_map identical).
- Multi-method email (SMG/SMTP/Mailgun/SendGrid/none), chat integrations
  (Slack/Teams/Discord/webhook) with rich messages, Slack interactivity
  (HTTP Request URL + Socket Mode), and a configurable login banner.
- Frontend `app.js` split into ordered pieces + extracted `app.css`.

### Schema (additive, auto-migrated)
- `jobs`: `approved_by_dn`, `approved_at`, `signed_via`, `template_id`,
  `revoked_at`, `revoked_by_dn`.
- `cert_templates`: `signer_backend`, `openbao_role`, `max_ttl`, `auto_sign`.

## 1.2.0

### Added
- **Admin user deletion** — `DELETE /api/admin/users` (admin + CSRF). Guards:
  cannot delete yourself, cannot delete the last remaining admin, 404 if
  absent. Removes the user + their group memberships; **retains their jobs**
  (historical). `?purge=1` also detaches owned cert templates (`owner_dn` →
  NULL). UI: a Delete button in the user-edit modal (hidden for your own
  account) that requires typing the user's CN to confirm.
- **First-admin bootstrap** — `CSR_BOOTSTRAP_FIRST_ADMIN=1` makes the first
  user to log in on an empty database an admin; self-disables once any user
  exists. Default off. Only safe under real CAC mTLS. (`_env_bool` helper.)
- **`csr-bootstrap-admin` CLI** — promote a DN to admin directly in the DB
  (no prior login needed); `--list` shows current admins. Installed to
  `/usr/local/sbin`.
- **CA trust portal** — publish root/intermediate CA certs so clients can
  download them to build trust. Public unauthenticated `GET /api/trust` +
  `/api/trust/<name>`; admin upload/delete validates the file is a CA cert
  (`CA:TRUE`) and **rejects private keys**. New admin **Trust** panel.
- **CAC mTLS as an installer option** — `ENABLE_MTLS` (+ `DOD_CA_BUNDLE`).
  The generated nginx server block carries the enforcing lines active (yes)
  or commented with `optional_no_ca` (no). The offline installer auto-publishes
  the DoD bundle to the trust portal when mTLS is enabled.
- **Guided offline installer** — `offline-install.sh` prompts (domain,
  hostname, optional email, mTLS, first-admin, DB restore) with a confirm
  summary; `--unattended` reads `START_HERE`; `--help` works as non-root.
  Email is optional; domain/hostname are templated into the deployed files.
- **UI domain badge** — bare-hostname suffix shown as a highlighted
  `.suffix-badge` with a worked example.

### Changed
- **nginx `30-csr.conf` is now a location fragment** (no `server{}` wrapper),
  included inside a server block — matching the rcdn01 layout. Uses
  `root /var/www` (not `alias`). The installers generate a standalone server
  block (`conf.d/csr-dashboard.conf`) for fresh/air-gapped boxes.
- **`deploy.sh`** verifies the running version against `VERSION` after a
  restart (a failed loopback curl is "couldn't check", not an error), and uses
  `reload-or-restart` for nginx.

### Fixed
- **Orphan-certs 500** — the admin orphan-certs listing read
  `/home/ansible/issued` directly, which 500s when csrapi can't read it on a
  STIG box. Now routed through a root helper subcommand `list-issued`.
- **`csr-api.service`** — `/etc/csr-dashboard` added to `ReadWritePaths` so
  the admin UI can persist `email.conf` / `integrations.conf` under
  `ProtectSystem=full` (every save previously 500'd "read-only file system").
- **`/home/ansible/issued`** is created csrapi-writable by the installers (the
  cert drop was hitting EACCES).

## 1.1.0

### Added
- **Pluggable email providers** — admin picks one delivery method (dropdown):
  SMG relay (plain SMTP:25), standard **SMTP** (STARTTLS/SSL + auth), or
  **Mailgun** HTTP API (US/EU). Only the selected provider is active; secrets
  are masked and preserved across saves.
- **GitLab issue-driven signing loop** — a new CSR job opens a GitLab issue
  (CSR pasted in, assigned to signers, labeled); a signer pastes/attaches the
  signed cert in the issue and the dashboard attaches it to the job (inbound
  `POST /api/webhooks/gitlab`, validated by `X-Gitlab-Token`). Admin **GitLab**
  panel + test-connection.

## 1.0.1

### Added / Fixed (offline + repo hygiene)
- Restructured the repo from a flat dump into the real tree the scripts expect.
- Added the missing pinned `requirements.txt` and the production
  `nginx/30-csr.conf`.
- Added `install/online-install.sh` (connected/non-STIG installer).
- Documented the STIG offline install failures + fixes (venv `g+rX`, fapolicyd
  exec-by-path, single-line systemd `ExecStart`, firewalld 443, etc.).

## 1.0.0
- Initial CSR Dashboard: Flask/SQLite certificate request + lifecycle
  dashboard for the RHEL fleet, behind nginx with DoD PKI CAC mTLS.
