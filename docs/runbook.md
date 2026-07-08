# Certheim — Operations Runbook

Flask/SQLite certificate request + lifecycle dashboard for a RHEL fleet.
Request flow: **nginx (CAC mTLS)** → **gunicorn** as the `certinel` service
account on `127.0.0.1:5002` → **SQLite (WAL)** at `/var/lib/certinel/jobs.db`.
Hardened RHEL 9/10 target: FIPS, SELinux enforcing, fapolicyd enforcing.

This runbook reflects the proven installs on `certinel-host` (production), a
fresh STIG offline VM, and a DISA-STIG RHEL 10.2 box (SELinux + fapolicyd
enforcing) validated via the signed RPM.

---

## 1. Architecture & paths

| Path | Owner / mode | Purpose |
|---|---|---|
| `/opt/certinel/` | root:certinel 0750 | app code + `venv/` |
| `/opt/certinel/{app,notify,gitlab_integration,import_certs}.py` | root:certinel 0640 | backend |
| `/var/www/csr/{index.html,app.js}` | root:nginx 0640 | frontend |
| `/var/lib/certinel/jobs.db` | certinel:certinel 0640 | SQLite (WAL) |
| `/var/lib/certinel/trust/` | certinel:certinel | published CA certs (trust portal) |
| `/etc/certinel/email.conf` | certinel:certinel 0640 | mail config (UI-managed) |
| `/etc/certinel/integrations.conf` | certinel:certinel 0640 | GitLab config (UI-managed) |
| `/etc/certinel/certinel.env` | certinel:certinel 0640 | app env (paths, flags) |
| `/opt/certinel/helper/certinel_helper.sh` (+`.d/`) | root:root 0750/0640 | root-mediated ops (sudo) |
| `/etc/systemd/system/certinel-api.service` | root:root 0644 | gunicorn unit |
| `/etc/nginx/certinel.d/30-csr.conf` | root:root 0644 | **location fragment** |
| `/etc/nginx/conf.d/certinel.conf` | root:root 0644 | **server block** (TLS + mTLS + include) |
| `/usr/local/sbin/{certinel-backup,certinel-bootstrap-admin}` | root:root 0750 | tools |

**Service account.** `certinel` is a system account, no login shell, no home.
It runs ONLY the helper as root via a single sudoers rule
(`/etc/sudoers.d/certinel`):
```
certinel ALL=(root) NOPASSWD: /opt/certinel/helper/certinel_helper.sh
```

---

## 2. Install

### RPM (dnf-native) — RHEL 9/10, incl. DISA STIG  ← recommended

The signed RPM installs Certheim as a native systemd service and pulls its OS
deps (`nginx`, `python3`, `openssl`, `sqlite`, `policycoreutils`, `sudo`) via
dnf. It bundles the app, an offline wheelhouse, and the `certheim-setup`
configurator (which runs the same `online-install.sh` under the hood, so all the
fapolicyd/SELinux/nginx handling in §6 applies).

**STIG hosts enforce `gpgcheck`** — import the Certheim public key first or dnf
rejects the package (`GPG check FAILED`). Do **not** use `--nogpgcheck`.

```bash
# 1. Import + verify the signature (key id A16072AF9F5E7593)
sudo rpm --import RPM-GPG-KEY-certheim
rpm -Kv ./certheim-<ver>-1.x86_64.rpm          # expect: Header/Payload … Signature … OK

# 2. Install (resolves nginx/python3/… from the RHEL repos)
sudo dnf install ./certheim-<ver>-1.x86_64.rpm

# 3. Configure + start (interactive) …
sudo certheim-setup
#    … or unattended (every prompt has an env override):
sudo FQDN=host.example.mil TLS_MODE=selfsigned ASSUME_DEFAULTS=yes certheim-setup
#    Government/Commercial license: add LICENSE_FILE=/path/to/license
#    CAC/mTLS (if the license entitles it): add ENABLE_MTLS=yes CLIENT_CA_BUNDLE=/etc/pki/dod/dod-cas.pem
```

The public key ships with the release and, post-install, at
`/usr/share/doc/certheim/RPM-GPG-KEY-certheim`
(fpr `D245 9994 B9DD 0392 9E89 1E2B A160 72AF 9F5E 7593`). Verify the running
service: `curl -sk https://localhost/csr/api/health` → `{"ok":true,…}`.
Upgrade: `sudo dnf upgrade ./certheim-<newer>.rpm && sudo certheim-setup`.
Remove: `sudo dnf remove certheim` (keeps data/config) then optional
`sudo certinel-uninstall`.

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
./make-offline-bundle.sh           # -> certheim-offline-<ver>.tar.gz (+ .sha256)
```
Carry the tarball across. On the target:
```bash
sha256sum -c certheim-offline-<ver>.tar.gz.sha256
tar xzf certheim-offline-<ver>.tar.gz && cd certheim-offline-<ver>/install
sudo bash ./offline-install.sh     # guided prompts; or --unattended (reads START_HERE)
```
The guided installer asks domain, hostname, optional email relay, **CAC mTLS
(yes/no)**, first-admin, and optional DB restore, then installs (account,
dirs, sudoers, venv-from-wheelhouse, configs, nginx server block, fapolicyd
trust, deploy, start). Run via `bash` so fapolicyd doesn't block exec-by-path.

### Change workflow (existing install)
```bash
git clone <repo> && cd certinel
# edit...
sudo ./deploy.sh --diff      # preview
sudo ./deploy.sh             # backup, install changed files, perms, fapolicyd,
                             # unit validation, restart, version check
git commit -am "..." && git push
```

---

## 3. PKI / CAC mTLS

- **Server cert**: `/etc/pki/certinel/server.{crt,key}` (installer drops a
  self-signed placeholder; replace with the site cert).
- **mTLS lives at the SERVER level** (`conf.d/certinel.conf`), NOT in the
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
- **Preferred**: `sudo certinel-bootstrap-admin "<YOUR CAC DN>"` (promotes a DN; no
  prior login needed). `certinel-bootstrap-admin --list` shows admins.
- Or set `CSR_BOOTSTRAP_FIRST_ADMIN=1` BEFORE first login (first user becomes
  admin, self-disables). Only safe under real mTLS.

---

## 5. Email

UI-managed at Admin → Email (written to `/etc/certinel/email.conf`,
hot-reloaded). Pick one method: **SMG** (plain :25), **SMTP** (STARTTLS/SSL +
auth), or **Mailgun** (API). Blank SMG host = email disabled. "Send test
email" verifies wiring.

---

## 6. STIG specifics that bite

- **Package signing / `gpgcheck`**: STIG enforces `gpgcheck` (and
  `localpkg_gpgcheck`), so the RPM **must** be signed and its key imported
  (`sudo rpm --import RPM-GPG-KEY-certheim`) before `dnf install`, or it fails
  `GPG check FAILED`. The RPM is signed with the Certheim release key
  (id `A16072AF9F5E7593`); `rpm -Kv <rpm>` must report `Signature … OK`. Never
  fall back to `--nogpgcheck` on a STIG host.
- **RHEL 10 / python 3.12 wheelhouse**: the RPM's (and offline bundle's)
  wheelhouse is built for the release CI's python (3.9 on RHEL 9), and carries
  one compiled wheel (`markupsafe`) that is CPython-version specific. On a
  **connected** RHEL 10 box the installer detects the mismatch and falls back to
  PyPI automatically (no action needed). For an **air-gapped RHEL 10** target,
  build the offline bundle/RPM **on a RHEL 10 box** so the wheelhouse matches
  python 3.12 — the same "match the target's python" rule as any offline bundle.
- **fapolicyd**: new files under `/opt/certinel` need
  `fapolicyd-cli --file add <f> && --update` once (the installer trusts the
  venv; `deploy.sh` updates trust for existing files). Untrusted bundle
  scripts can't exec-by-path → run via `bash`.
- **venv perms**: `python -m venv` is 0700 under root umask 077 → certinel can't
  traverse → `chmod -R g+rX /opt/certinel/venv` (installer does this).
- **systemd**: single-line `ExecStart`; `ProtectSystem=full` with
  `ReadWritePaths` covering `/opt/certinel /var/lib/certinel
  /var/opt/certinel /etc/certinel`. `ProtectHome=true` (helper under
  `/opt/certinel`, keys in the vault — nothing under `/home` or `/root`). `deploy.sh` runs
  `systemd-analyze verify` before restart.
- **Data root**: signed certs + generated CSRs live under `/var/opt/certinel`
  (`issued/`, `requests/`) — FHS add-on-app data, not a service-account home.
  `deploy.sh` creates them and sets `var_lib_t` so the confined service can
  write (matches the DB dir). The helper's `ISSUED_DIR`/`CSRDIR`
  (`certinel_helper.d/00-common.sh`) must match `CSR_ISSUED_DIR`.
- **SELinux**: `setsebool -P httpd_can_network_connect 1` (else nginx→backend
  502s); `restorecon` on `/var/www/csr` + `/var/opt/certinel` (deploy.sh does this).
- **firewalld**: open 443 (`firewall-cmd --permanent --add-service=https`).
- **nginx**: the fragment must stay location-only; mTLS at server level.
- **VERSION**: read once at startup → bump VERSION, restart, confirm via
  `/api/health` (`deploy.sh` does this automatically).

---

## 7. Operations

- **Backup before risk**: `certinel-backup` (snapshots deploy files + DB to
  `/root/certinel-backup-*`). `deploy.sh` runs it pre-deploy.
- **Health**: `curl -sk https://localhost/csr/api/health` → `{"ok":true,...}`.
- **Logs**: `journalctl -u certinel-api`; audit events also land in the DB
  `audit_log` table (admin Audit panel).
- **Expiry warnings**: `certinel-expiry-warn.timer` (daily 06:30 UTC) runs
  `app.run_expiry_warnings()`.
- **Automated renewal**: `certinel-auto-renew.timer` (daily 07:00 UTC) runs
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
    `acme_*` tables. Supports **HTTP-01 and DNS-01** validation (DNS-01 via
    `dig` on `_acme-challenge.<host>`), **revoke-cert** (account-signed; revokes
    at the backing CA), and account **key rollover** (`key-change`).

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| 502 on every request | `httpd_can_network_connect` off, or gunicorn down (`journalctl -u certinel-api`) |
| UI shows old version | stale process — `deploy.sh` version check warns; `systemctl restart certinel-api` |
| Admin email save 500 "read-only" | `/etc/certinel` not in unit `ReadWritePaths` |
| App logs `ip=` under mTLS | server-level `ssl_verify_client`/DoD bundle, not the app |
| `/csr/` 404s to default docroot | fragment used `alias` instead of `root /var/www` |
| orphan-certs 500 | reading issued dir directly — must go through helper `list-issued` |
| nginx "server directive not allowed" | a server{} wrapper leaked into the location fragment |
