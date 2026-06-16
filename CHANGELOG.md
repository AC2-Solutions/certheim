# Changelog

All notable changes to the CSR Dashboard. Versions track the `VERSION` file
(the app reports it at `/api/health` and on the admin Overview tile).

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
