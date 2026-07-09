# Certheim

> **Certheim** (formerly *Certinel*, originally *CSR Dashboard*) — a certificate **lifecycle** platform.
> As of v5.2 the internals are certheim-named too: `/opt|/etc|/var/{lib,opt}/certheim`,
> the `certheim-api` service + timers, `certheim-*` tools, and `CERTHEIM_*`
> environment variables (legacy `CSR_*`/`CERTINEL_*` spellings still read via a
> compat shim until Phase 5). Pre-5.2 installs are migrated in place by
> `tools/certheim-migrate.sh`, invoked automatically by `deploy.sh`.
> Kept on purpose: the `/csr/` URL path + `/var/www/csr` web root ("certificate
> signing request" — semantic, not brand) and external names (OpenBao
> `certinel-keys` path, vault role names).

Flask/SQLite certificate request & lifecycle dashboard for an
Platforms RHEL fleet. Runs behind nginx
with PKI/CAC mTLS (or local accounts).

> **New operator?** Open **`frontend/setup-guide.html`** in any browser for a
> plain-English, start-to-finish setup runbook that tailors every step and
> command to your details (edition, hostname, OpenBao, etc.). It's also linked
> in-app as **Setup Guide** (top bar) and served at `/csr/setup-guide.html`.

## Repo layout → live paths

| Repo | Deploys to | Owner / mode |
|---|---|---|
| `backend/` | `/opt/certheim/` | root:certheim 0640 |
| `frontend/` | `/var/www/csr/` | root:nginx 0640 (+restorecon) |
| `helper/` | `/root/sslcerts/scripts/` | root:root 0750 / 0640 |
| `systemd/` | `/etc/systemd/system/` | root:root 0644 |
| `nginx/` | `/etc/nginx/certheim.d/` | root:root 0644 |
| `tools/certheim-backup.sh` | `/usr/local/sbin/certheim-backup` | root:root 0750 |
| `ansible/` | run from AAP / CLI, not installed | — |

Not tracked, on purpose: the SQLite DB (`/var/lib/certheim/`), the
venv, and the live `/etc/certheim/email.conf` (managed through the
admin UI; `config/email.conf.example` documents the shape).

## Change workflow

```
git clone git@<your-git-host>:<group>/certheim.git
cd certheim
# edit files...
sudo ./deploy.sh --diff      # review exactly what will change on the box
sudo ./deploy.sh             # certheim-backup, install, fapolicyd, restart, verify
git add -A && git commit -m "what and why" && git push
```

`deploy.sh` only touches files that differ, applies correct ownership and
SELinux contexts, refreshes the fapolicyd trust DB for `/opt/certheim/`
(REQUIRED on this STIG baseline - untrusted files get EPERM), restarts
`certheim-api` only when backend files changed, and fails loudly if the service
doesn't come back.

If a hotfix was made directly on the box (it happens at 2am): run
`sudo ./gather.sh` in a clean clone, `git diff` shows the drift, commit it.

## Operational notes

- fapolicyd: any NEW file under `/opt/certheim/` needs
  `fapolicyd-cli --file add <file> && fapolicyd-cli --update` once;
  deploy.sh handles updates to existing files.
- Ansible tasks against this host must NOT `become_user` to unprivileged
  accounts (fapolicyd blocks AnsiballZ temp modules). `become: true` +
  `runuser -u certheim --` instead. See `ansible/fleet-cert-scan.yml`.
- Expiry warnings: `certheim-expiry-warn.timer`, daily 06:30 UTC, runs
  `app.run_expiry_warnings()` under the venv python.
- DB: `/var/lib/certheim/jobs.db` (WAL). `certheim-backup` before risk.
