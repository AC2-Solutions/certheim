# Design: full `certinel` → `certheim` internal rename

**Status:** proposed (Phase 0). **Scope decision (locked):** *everything* — the
service, all filesystem paths, systemd units, the service account, env-var
prefixes, the public URL path, the helm chart, the k8s namespace, the portal DB
table + HTTP headers, and cross-repo references. Migration strategy: **move +
upgrade hook** (existing installs are migrated in place, no data left under the
old names).

The product name is already 100% `Certheim` (zero `Certinel` product-name refs).
This effort renames the remaining **internal system identifiers**, which are
load-bearing: ~750 refs across ~60 files in the app repo alone, plus the licenses
portal, registry token minter, ansible, and gitops. Existing installs
(**Government `disa`**, the `clm` K8s Commercial app, the demo box, `csr-dev`)
hold live data under `/var/lib/certinel` + `/var/opt/certinel` — so a rename
without migration would orphan real (incl. Government) data. This document is the
contract every phase implements.

---

## 1. Naming map

| Kind | Old | New |
|---|---|---|
| App dir | `/opt/certinel` | `/opt/certheim` |
| Config dir | `/etc/certinel` | `/etc/certheim` |
| State/DB dir | `/var/lib/certinel` | `/var/lib/certheim` |
| Data root | `/var/opt/certinel` | `/var/opt/certheim` |
| Web root | `/var/www/csr` | `/var/www/certheim` |
| Env file | `/etc/certinel/certinel.env` | `/etc/certheim/certheim.env` |
| Service account | `certinel` | `certheim` |
| systemd units | `certinel-api.service`, `certinel-{expiry-warn,auto-renew,deliver,doctor}.{service,timer}` | `certheim-*` |
| nginx cert dir | `/etc/pki/certinel` | `/etc/pki/certheim` |
| nginx include dir | `/etc/nginx/certinel.d` | `/etc/nginx/certheim.d` |
| nginx server block | `/etc/nginx/conf.d/certinel.conf` | `/etc/nginx/conf.d/certheim.conf` |
| sudoers | `/etc/sudoers.d/certinel` | `/etc/sudoers.d/certheim` |
| Helper | `/opt/certheim/helper/certinel_helper.sh` (+`.d/`) | `certheim_helper.sh` |
| Tools (`/usr/local/sbin`) | `certinel-{backup,restore,db-migrate,bootstrap-admin,uninstall,set-auth,doctor,doctor-alert}` | `certheim-*` |
| Setup command | `certheim-setup` (already) | (unchanged) |
| Helm chart | `deploy/helm/certinel` | `deploy/helm/certheim` |
| k8s namespace / release | `certinel` | `certheim` |
| k8s secrets | `certinel-tls`, `certinel-client-ca` | `certheim-*` |
| **Env var prefix** | `CSR_*`, `CERTINEL_*` | `CERTHEIM_*` |
| **URL base path** | `/csr/` | **KEPT `/csr/`** — decision 2026-07-09 (see §2) |
| **Portal DB table** | `certinel_licenses` | `certheim_licenses` |
| **HTTP headers** | `X-Certinel-*` (Version/SHA256), `X-Client-*` unchanged | `X-Certheim-*` |
| Portal endpoints | `/api/v1/certinel/releases[/rpm]`, `/api/v1/public/certinel-inquiry` | `/api/v1/certheim/*` |
| Portal config keys | `CertinelDownloadDir`, `CERTINEL_RELEASE_UPLOAD_SECRET`, … | `Certheim*` / `CERTHEIM_*` |
| SELinux fcontext | `/opt/certinel(/.*)?`, `/var/opt/certinel(/.*)?`, `/opt/certinel/helper(/.*)?` | `…/certheim…` |
| Backup dir | `/root/certinel-backup-*` | `/root/certheim-backup-*` |
| OpenBao key path | `secret/.../certinel-keys/*` | keep or dual-map (see §4) |

Kept as-is (not `certinel`-branded, or external contract owned elsewhere):
`CSR` in **file/URL semantics only where it means "certificate signing
request"** is *renamed* per the decision; the Go/React symbol names
(`CertinelHandler`, `CertinelLicenses.tsx`) are internal code identifiers — rename
for consistency but they carry no runtime contract.

---

## 2. Backwards compatibility (the crux)

Nothing may break during the window where repo code is renamed but a given
install / API client hasn't migrated yet. Every contract gets a dual-read shim,
removed only in Phase 5.

- **Env vars** — `getenv_compat("CERTHEIM_X")` reads `CERTHEIM_X`, else `CSR_X` /
  `CERTINEL_X`, logging a deprecation once. Applies to all ~40 backend vars and
  the portal config loader.
- **Filesystem** — the migration (§3) physically moves data; `deploy.sh` and
  `certheim-setup` detect the old layout and migrate before first run. No
  symlinks in the end state.
- **URL base path — `/csr/` is KEPT** (decided 2026-07-09). `/csr` reads as
  "certificate signing request", which is what the app does — it is semantic,
  not a brand name — and keeping it avoids the whole 301-redirect layer,
  breaking bookmarks, re-pointing ACME directory URLs, and touching every
  reverse-proxy fragment. No URL work in any phase.
- **HTTP headers** — responses emit `X-Certheim-*`; any request-side reads accept
  both `X-Certheim-*` and `X-Certinel-*`.
- **Portal DB** — migration `ALTER TABLE certinel_licenses RENAME TO
  certheim_licenses` **plus a `certinel_licenses` VIEW** onto the new table for
  one release, so an un-migrated portal binary still reads. Column-level grants
  for the scoped `portal_customer` role are re-applied to the new name (and view).
- **Portal endpoints** — new `/api/v1/certheim/*` routes; old
  `/api/v1/certinel/*` kept as aliases until Phase 5 (CI upload + marketing
  inquiry form both call these).

---

## 3. Migration routine (`move + upgrade hook`)

A single idempotent function (`migrate_certinel_layout` in `deploy.sh`, also
invoked by `certheim-setup`) that runs before any deploy/start when it detects a
legacy layout (`/opt/certinel` or `/etc/certinel` present and no
`/opt/certheim`):

1. **Guard + backup.** `certinel-backup` (DB + config + deploy files) to
   `/root/certheim-backup-premigrate-<stamp>`. Refuse if backup fails.
2. **Stop** `certinel-api` + timers.
3. **Move** each dir old→new (`/opt`, `/etc`, `/var/lib`, `/var/opt`,
   `/var/www/csr`→`/var/www/certheim`, `/etc/pki/certinel`, `/etc/nginx/certinel.d`,
   `conf.d/certinel.conf`, sudoers). `mv` preserves SELinux context temporarily.
4. **Service account** — create `certheim` group/user; `usermod`/chown the moved
   trees to it (keep `certinel` until Phase 5 so nothing half-owned breaks, then
   remove).
5. **Rewrite** the env file, systemd unit `User=`/`Group=`/`ExecStart` paths,
   nginx server block + fragment paths, sudoers path, helper `.d` path constants,
   `CSR_*`→`CERTHEIM_*` keys (keep old keys commented for rollback).
6. **Relabel SELinux** — `semanage fcontext` for the new paths (purge the old
   rules), `restorecon -RF` the moved trees.
7. **Re-trust fapolicyd** — `fapolicyd-cli --file add /opt/certheim/` +
   `/opt/certheim/helper/`, `--update` (else `203/EXEC`).
8. **daemon-reload**, enable/start `certheim-api` + timers, `systemd-analyze
   verify` gate, health check.
9. **Rollback** — on any failure before step 8 completes, the premigrate backup
   + the still-present `certinel` unit names allow a documented revert.

The routine is **rehearsed on `disa` (Government) with a fresh backup first**, in
a maintenance window, before touching the others.

---

## 4. Per-repo / per-phase breakdown

- **certheim app** (project 33, Community → propagate): §1 paths/units/tools/
  helper/`deploy.sh`+MANIFEST/`online-install.sh`/config/nginx/frontend guide/
  `deploy/helm`/`Containerfile`/backend env+URL. `.gitlab-ci.yml` (`initdb -U
  certinel`, `/tmp/certinel-pg-*`, smoke DSN) too. OpenBao `certinel-keys` path:
  keep the existing OpenBao path (external secret store) and only rename the
  *config key* that points at it, to avoid a Vault-side policy change in this
  phase; revisit in Phase 4.
- **licenses portal** (project 21): DB migration (table + view + grants),
  `X-Certinel-*`→`X-Certheim-*`, `/api/v1/certinel/*` alias, `CertinelDownloadDir`
  + `CERTINEL_*` config keys, `certinel_autoissue.go`/`registry_token.go`
  strings. Registry image repos are already `certheim/*` — no change.
- **ansible** (ac2-solutions/ansible): roles `certinel_*` → `certheim_*`, managed
  paths/units, the `certinel-portal-*` VM roles. Ship the migration as a play so
  the fleet converges.
- **gitops** (project 5): k8s app manifests — container paths, namespace/secret
  names. Probes keep hitting `/csr/` (URL path is kept).
- **websites/app guide**: mostly product-name-clean already; update the residual
  path/command/URL references once the app side lands.

## 5. Rollout order

1. Phase 1 compat shims merged + deployed **first** (portal + app can read both).
2. Phase 2 app rename + migration hook merged; **do not** mass-migrate yet.
3. Phase 3 live migrations, **`disa` first (rehearsed, backed up)**, validate,
   then `clm` (K8s: new image + PVC path handling), demo, `csr-dev`.
4. Phase 4 cross-repo (portal DB rename in a window; ansible/gitops).
5. Phase 5 remove shims (env fallback, dual headers, DB view, endpoint
   aliases) once every install + client is confirmed on the new names.

## 6. Risks

- **Government data** on `disa` — mitigated by backup + rehearsal + rollback path.
- ~~URL change~~ — **eliminated**: `/csr/` is kept (decision 2026-07-09), so no
  ACME/API client, bookmark, or reverse-proxy fragment is affected.
- **Portal DB rename** under a scoped role — grants must be re-applied to the new
  table **and** the compat view or the customer portal 500s (see the column-grant
  gotcha in prior portal work).
- **K8s (`clm`)** — the image's internal paths change; the PVC that held
  `/var/opt/certinel` data must be remounted/migrated at the new path or the app
  starts empty. Handle in Phase 3 with a one-shot init or a fresh-PVC + restore.
- **fapolicyd/SELinux** on STIG boxes — the migration must re-trust/relabel or the
  service dies `203/EXEC`; covered in §3 steps 6–7 and validated on `disa`.
