# CSR Dashboard — Operations Runbook

Flask/SQLite certificate request + lifecycle dashboard for a RHEL fleet.
Request flow: **nginx (CAC mTLS)** → **gunicorn** as the `csrapi` service
account on `127.0.0.1:5002` → **SQLite (WAL)** at `/var/lib/csr-dashboard/jobs.db`.
Hardened RHEL 9 target: FIPS, SELinux enforcing, fapolicyd enforcing.

This runbook reflects the proven installs on `csr-host` (production)
and a fresh STIG offline VM.

---

## 1. Architecture & paths

| Path | Owner / mode | Purpose |
|---|---|---|
| `/opt/csr-dashboard/` | root:csrapi 0750 | app code + `venv/` |
| `/opt/csr-dashboard/{app,notify,gitlab_integration,import_certs}.py` | root:csrapi 0640 | backend |
| `/var/www/csr/{index.html,app.js}` | root:nginx 0640 | frontend |
| `/var/lib/csr-dashboard/jobs.db` | csrapi:csrapi 0640 | SQLite (WAL) |
| `/var/lib/csr-dashboard/trust/` | csrapi:csrapi | published CA certs (trust portal) |
| `/etc/csr-dashboard/email.conf` | csrapi:csrapi 0640 | mail config (UI-managed) |
| `/etc/csr-dashboard/integrations.conf` | csrapi:csrapi 0640 | GitLab config (UI-managed) |
| `/etc/csr-dashboard/csr-dashboard.env` | csrapi:csrapi 0640 | app env (paths, flags) |
| `/root/sslcerts/scripts/csr_dashboard_helper.sh` (+`.d/`) | root:root 0750/0640 | root-mediated ops (sudo) |
| `/etc/systemd/system/csr-api.service` | root:root 0644 | gunicorn unit |
| `/etc/nginx/csr-dashboard.d/30-csr.conf` | root:root 0644 | **location fragment** |
| `/etc/nginx/conf.d/csr-dashboard.conf` | root:root 0644 | **server block** (TLS + mTLS + include) |
| `/usr/local/sbin/{csrbackup,csr-bootstrap-admin}` | root:root 0750 | tools |

**Service account.** `csrapi` is a system account, no login shell, no home.
It runs ONLY the helper as root via a single sudoers rule
(`/etc/sudoers.d/csr-dashboard`):
```
csrapi ALL=(root) NOPASSWD: /root/sslcerts/scripts/csr_dashboard_helper.sh
```

---

## 2. Install

### Connected / non-STIG (e.g. a dev box)
```bash
sudo PYBIN=python3.12 ENABLE_MTLS=no \
     SMG_HOST=smtp.example DASHBOARD_URL=https://host/csr/ FROM_ADDRESS=noreply@example \
     ./install/online-install.sh
```
Installs OS packages, the venv from PyPI, generates the nginx server block +
self-signed cert + firewalld 443 + the `httpd_can_network_connect` SELinux
boolean, then runs `deploy.sh`.

### Air-gapped / STIG (offline bundle)
On a **connected** box matching the target (RHEL major / python / arch), and
NOT fapolicyd-enforcing (or as root):
```bash
./make-offline-bundle.sh           # -> csr-dashboard-offline-<ver>.tar.gz (+ .sha256)
```
Carry the tarball across. On the target:
```bash
sha256sum -c csr-dashboard-offline-<ver>.tar.gz.sha256
tar xzf csr-dashboard-offline-<ver>.tar.gz && cd csr-dashboard-offline-<ver>/install
sudo bash ./offline-install.sh     # guided prompts; or --unattended (reads START_HERE)
```
The guided installer asks domain, hostname, optional email relay, **CAC mTLS
(yes/no)**, first-admin, and optional DB restore, then installs (account,
dirs, sudoers, venv-from-wheelhouse, configs, nginx server block, fapolicyd
trust, deploy, start). Run via `bash` so fapolicyd doesn't block exec-by-path.

### Change workflow (existing install)
```bash
git clone <repo> && cd csr-dashboard
# edit...
sudo ./deploy.sh --diff      # preview
sudo ./deploy.sh             # backup, install changed files, perms, fapolicyd,
                             # unit validation, restart, version check
git commit -am "..." && git push
```

---

## 3. PKI / CAC mTLS

- **Server cert**: `/etc/pki/csr-dashboard/server.{crt,key}` (installer drops a
  self-signed placeholder; replace with the site cert).
- **mTLS lives at the SERVER level** (`conf.d/csr-dashboard.conf`), NOT in the
  fragment. To enforce:
  ```nginx
  ssl_client_certificate /etc/pki/dod/dod-cas.pem;   # root+intermediate, no CRLF
  ssl_verify_client       on;
  ssl_verify_depth        3;                          # Root->Intermediate->CAC
  ```
  Then `nginx -t && systemctl reload nginx`. (The installer writes these
  active or commented per `ENABLE_MTLS`.)
- The fragment passes `X-Client-DN $ssl_client_s_dn` etc. to the app;
  `client_identity()` trusts the DN ONLY when `X-Client-Verify == SUCCESS`,
  else falls back to `ip:<addr>`. **If the app logs `ip=` with verify on,
  suspect the server-level mTLS config / DoD bundle, not the app.**
- DoD bundle gotchas: strip CRLF (`sed -i 's/\r$//'`), ensure cert count > 0.
- **Trust portal**: publish the CA bundle at Admin → Trust so clients can
  download it (`/csr/api/trust`) to build trust before they have a CAC.

---

## 4. First admin

A fresh DB has no admins. Either:
- **Preferred**: `sudo csr-bootstrap-admin "<YOUR CAC DN>"` (promotes a DN; no
  prior login needed). `csr-bootstrap-admin --list` shows admins.
- Or set `CSR_BOOTSTRAP_FIRST_ADMIN=1` BEFORE first login (first user becomes
  admin, self-disables). Only safe under real mTLS.

---

## 5. Email

UI-managed at Admin → Email (written to `/etc/csr-dashboard/email.conf`,
hot-reloaded). Pick one method: **SMG** (plain :25), **SMTP** (STARTTLS/SSL +
auth), or **Mailgun** (API). Blank SMG host = email disabled. "Send test
email" verifies wiring.

---

## 6. STIG specifics that bite

- **fapolicyd**: new files under `/opt/csr-dashboard` need
  `fapolicyd-cli --file add <f> && --update` once (the installer trusts the
  venv; `deploy.sh` updates trust for existing files). Untrusted bundle
  scripts can't exec-by-path → run via `bash`.
- **venv perms**: `python -m venv` is 0700 under root umask 077 → csrapi can't
  traverse → `chmod -R g+rX /opt/csr-dashboard/venv` (installer does this).
- **systemd**: single-line `ExecStart`; `ProtectSystem=full` with
  `ReadWritePaths` covering `/opt/csr-dashboard /var/lib/csr-dashboard
  /home/ansible/issued /etc/csr-dashboard`. `deploy.sh` runs
  `systemd-analyze verify` before restart.
- **SELinux**: `setsebool -P httpd_can_network_connect 1` (else nginx→backend
  502s); `restorecon` on `/var/www/csr` (deploy.sh does this).
- **firewalld**: open 443 (`firewall-cmd --permanent --add-service=https`).
- **nginx**: the fragment must stay location-only; mTLS at server level.
- **VERSION**: read once at startup → bump VERSION, restart, confirm via
  `/api/health` (`deploy.sh` does this automatically).

---

## 7. Operations

- **Backup before risk**: `csrbackup` (snapshots deploy files + DB to
  `/root/csr-backup-*`). `deploy.sh` runs it pre-deploy.
- **Health**: `curl -sk https://localhost/csr/api/health` → `{"ok":true,...}`.
- **Logs**: `journalctl -u csr-api`; audit events also land in the DB
  `audit_log` table (admin Audit panel).
- **Expiry warnings**: `csr-expiry-warn.timer` (daily 06:30 UTC) runs
  `app.run_expiry_warnings()`.
- **Automated renewal**: `csr-auto-renew.timer` (daily 07:00 UTC) runs
  `app.run_auto_renew()` — re-signs issued certs nearing expiry whose template
  opts into auto-renew, via that template's CA backend. Off by default; enable
  on Admin → Signing/CA (master switch + default window) and per template
  (auto-renew checkbox + window). Trigger on demand with
  `POST /csr/api/admin/run-auto-renew`. Both timer entrypoints are re-exported
  from the `app` module — if either timer logs
  `AttributeError: module 'app' has no attribute ...`, that re-export is missing.
- **GitLab integration**: Admin → GitLab (config in `integrations.conf`);
  inbound webhook at `/csr/api/webhooks/gitlab` (validated by `X-Gitlab-Token`).
- **ACME server** (the dashboard *as* an RFC 8555 CA, Phase 4): off by default.
  Enable on Admin → Signing/CA (toggle + directory base URL) and entitle it with
  the `ca.server.acme` capability (env `CSR_CAP_ACME_SERVER=1`). It signs through
  the **default signing backend** and validates **HTTP-01** by fetching the
  challenge from the requested host, so:
  - **Reverse proxy**: forward the public `/acme/` path to the app (e.g. nginx
    `location /csr/acme/ { proxy_pass http://127.0.0.1:5002/acme/; }`). On mTLS
    boxes add `ssl_verify_client off;` in that location — ACME clients are
    anonymous (authenticated per-request by JWS, not CAC).
  - **Validation reachability**: the app must reach `http://<requested-host>/`
    on port 80 to read `/.well-known/acme-challenge/<token>`.
  - Client points `--server` at `<base-url>/directory`. State lives in the
    `acme_*` tables. Revoke / DNS-01 validation / key-rollover are follow-ons.

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| 502 on every request | `httpd_can_network_connect` off, or gunicorn down (`journalctl -u csr-api`) |
| UI shows old version | stale process — `deploy.sh` version check warns; `systemctl restart csr-api` |
| Admin email save 500 "read-only" | `/etc/csr-dashboard` not in unit `ReadWritePaths` |
| App logs `ip=` under mTLS | server-level `ssl_verify_client`/DoD bundle, not the app |
| `/csr/` 404s to default docroot | fragment used `alias` instead of `root /var/www` |
| orphan-certs 500 | reading issued dir directly — must go through helper `list-issued` |
| nginx "server directive not allowed" | a server{} wrapper leaked into the location fragment |
