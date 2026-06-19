# Certinel

> **Certinel** (formerly *CSR Dashboard*) — a certificate **lifecycle** platform.
> The repo slug, systemd services, paths, and `CSR_*` environment variables keep
> their original names for deployment compatibility; only the product brand
> changed.

Flask/SQLite certificate request & lifecycle dashboard for an
Platforms RHEL fleet. Runs behind nginx
with PKI/CAC mTLS (or local accounts).

## Repo layout → live paths

| Repo | Deploys to | Owner / mode |
|---|---|---|
| `backend/` | `/opt/csr-dashboard/` | root:csrapi 0640 |
| `frontend/` | `/var/www/csr/` | root:nginx 0640 (+restorecon) |
| `helper/` | `/root/sslcerts/scripts/` | root:root 0750 / 0640 |
| `systemd/` | `/etc/systemd/system/` | root:root 0644 |
| `nginx/` | `/etc/nginx/csr-dashboard.d/` | root:root 0644 |
| `tools/csrbackup.sh` | `/usr/local/sbin/csrbackup` | root:root 0750 |
| `ansible/` | run from AAP / CLI, not installed | — |

Not tracked, on purpose: the SQLite DB (`/var/lib/csr-dashboard/`), the
venv, and the live `/etc/csr-dashboard/email.conf` (managed through the
admin UI; `config/email.conf.example` documents the shape).

## Change workflow

```
git clone git@<your-git-host>:<group>/csr-dashboard.git
cd csr-dashboard
# edit files...
sudo ./deploy.sh --diff      # review exactly what will change on the box
sudo ./deploy.sh             # csrbackup, install, fapolicyd, restart, verify
git add -A && git commit -m "what and why" && git push
```

`deploy.sh` only touches files that differ, applies correct ownership and
SELinux contexts, refreshes the fapolicyd trust DB for `/opt/csr-dashboard/`
(REQUIRED on this STIG baseline - untrusted files get EPERM), restarts
`csr-api` only when backend files changed, and fails loudly if the service
doesn't come back.

If a hotfix was made directly on the box (it happens at 2am): run
`sudo ./gather.sh` in a clean clone, `git diff` shows the drift, commit it.

## Operational notes

- fapolicyd: any NEW file under `/opt/csr-dashboard/` needs
  `fapolicyd-cli --file add <file> && fapolicyd-cli --update` once;
  deploy.sh handles updates to existing files.
- Ansible tasks against this host must NOT `become_user` to unprivileged
  accounts (fapolicyd blocks AnsiballZ temp modules). `become: true` +
  `runuser -u csrapi --` instead. See `ansible/fleet-cert-scan.yml`.
- Expiry warnings: `csr-expiry-warn.timer`, daily 06:30 UTC, runs
  `app.run_expiry_warnings()` under the venv python.
- DB: `/var/lib/csr-dashboard/jobs.db` (WAL). `csrbackup` before risk.
