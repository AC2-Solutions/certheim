# Backup, restore, upgrade & disaster recovery

Certheim holds two kinds of state that must survive an incident:

1. **The database** — jobs, users, groups, templates, all `app_settings` (auth
   mode, signing config, license, the *encrypted* sealed-keystore blobs), and the
   audit log. SQLite (`CSR_DB_PATH`, default `/var/lib/certinel/jobs.db`) or
   PostgreSQL (`CSR_DB_URL`).
2. **The sealed-keystore unseal material** — the passphrase / recovery code /
   Shamir shares that unlock the encrypted keystore. **This is NOT in the
   database** (that's the whole point). Without it, a restored database's sealed
   secrets — the Local CA key, SCEP RA key, code-signing/TSA keys — cannot be
   decrypted. Store it separately, offline.

Everything else (issued cert files under `CSR_ISSUED_DIR`, the license) is either
reproducible or captured in the database.

> **The one rule:** a database backup + the unseal material = full recovery.
> Keep them in *different* places. If you use the built-in **sealed-keystore
> escrow** (below), you don't even need the original unseal material — the escrow
> bundle carries its own.

---

## Backup

### What to capture

| Item | Where | How |
|---|---|---|
| Database | `CSR_DB_PATH` (SQLite) or Postgres | `certinel-backup` (SQLite) / `pg_dump` (Postgres) |
| Sealed-keystore escrow (**CA key survival**) | in-app | Admin → **Encrypted keystore → Export backup** (choose a passphrase) — a self-contained bundle restorable on *any* Certheim |
| Unseal material | admin-held | recorded at keystore init; keep offline |
| License | `app_settings` (in the DB) or `CSR_LICENSE_FILE` | captured by the DB backup; re-mintable from the licenses portal |
| Issued cert files | `CSR_ISSUED_DIR` | optional — certs are also stored per-job in the DB |

### VM / systemd (SQLite)

```bash
sudo certinel-backup            # snapshot -> /root/certinel-backup-<ts>/
sudo certinel-backup --list
```

`certinel-backup` uses SQLite's online `.backup` (WAL-consistent, no downtime),
captures the deployment config files + license, and prints the exact restore
commands. **Also export the sealed-keystore escrow** from the admin UI and store
it with (but not next to) the backup.

### PostgreSQL

```bash
pg_dump "$CSR_DB_URL" -Fc -f certinel-$(date +%F).dump      # custom format
# restore: pg_restore --clean --if-exists -d "$CSR_DB_URL" certinel-<date>.dump
```

### Container / Kubernetes

State lives on the PVC (`certinel-<edition>-db`). Back it up with your cluster's
volume-snapshot tooling, **or** exec the same logic:

```bash
kubectl -n certinel-app exec deploy/certinel-app -c app -- \
  sqlite3 /var/lib/certinel/jobs.db ".backup '/tmp/jobs.db.bak'"
kubectl -n certinel-app cp certinel-app/<pod>:/tmp/jobs.db.bak ./jobs.db.bak -c app
```

The license + registry pull cred are ExternalSecrets synced from OpenBao — they
recover from OpenBao, not from the PVC (see the gitops repo).

### Cadence

- Nightly database backup, retained per your policy.
- Sealed-keystore escrow **after any change to sealed material** — a new/rotated
  Local CA, a new signing key. The escrow is a snapshot, not a live mirror.

---

## Restore (same version)

### VM / systemd

```bash
sudo certinel-restore /root/certinel-backup-<ts>.tar.gz
```

`certinel-restore` stops the service, puts back config + systemd units + sudoers
+ on-disk keys, restores the database (SQLite copy or `pg_restore` — it reads the
backup to decide which), fixes ownership/SELinux, and starts the service. It does
**not** reinstall application code — install the matching release first (the
backup's `BACKUP-MANIFEST.txt` records the version). To restore the DB by hand
instead: stop `certinel-api`, copy `db/jobs.db` from the backup tree over
`$CSR_DB_PATH`, remove the stale `-wal`/`-shm` sidecars, `chown certinel:` +
`chmod 0640`, restart.

Then in the admin UI: **Encrypted keystore → Unseal** with your material (or
**Restore backup** with the escrow bundle + its passphrase). Confirm the Local
CA shows *key present* under Signing / CA.

### Verify a restore

- `GET /api/health` returns the expected version.
- Admin → Overview → **Download support bundle**: check `schema.json` row counts
  match, capability/FIPS posture is expected.
- Sign a throwaway CSR with the Local CA (proves the sealed key decrypted).

---

## Upgrade (version N → N+1)

Certheim **self-migrates**: on startup it runs an idempotent schema pass
(`CREATE TABLE IF NOT EXISTS` for new tables, guarded `ALTER TABLE ADD COLUMN`
for new columns). Upgrading is deploy-new-code + restart; existing data is
preserved and never rewritten destructively.

1. **Back up first** (above). Non-negotiable.
2. Deploy the new version:
   - **VM:** sync the new files / package, `sudo systemctl restart certinel-api`.
   - **Container/k8s:** roll to the new image tag (pin the immutable
     `<edition>-vX.Y.Z` for a verified deploy — see `docs/verifying-releases.md`)
     and `kubectl rollout restart deploy/<name>`.
3. Migrations apply automatically on first start. Verify with the support bundle
   (`schema.json` shows the new tables/columns; row counts unchanged).
4. **Rollback:** stop the service, restore the pre-upgrade database backup, deploy
   the previous version. (Schema changes are additive, so a new-schema DB usually
   still runs on the old code — but restoring the backup is the guaranteed path.)

> Migrations are forward-only and additive. There is no down-migration; roll back
> by restoring the backup taken in step 1.

---

## Disaster recovery (rebuild from scratch)

Host lost, no running instance — you have a database backup + the sealed-keystore
escrow (or unseal material).

1. **Fresh install** of the *same or newer* Certheim version (newer is fine —
   it migrates the restored DB forward).
2. **Restore the database** into the new instance's `CSR_DB_PATH` / Postgres
   (above). This brings back every setting, template, user, group, job, and the
   *encrypted* sealed blobs.
3. **Recover the keystore:**
   - Have the original unseal material? Start the app and **Unseal**.
   - Only have the escrow bundle? **Encrypted keystore → Restore backup** with the
     bundle + its passphrase — it repopulates the sealed secrets independently of
     the original material.
4. **License:** captured in the restored DB; if absent, re-mint from the licenses
   portal and upload under Admin → License.
5. **Verify** (support bundle + a test signature) before taking traffic.

If the sealed-keystore escrow AND the unseal material are both lost, the sealed
secrets (Local CA key, etc.) are unrecoverable **by design** — there is no back
door. Re-generate the Local CA and re-issue. This is why the escrow belongs in a
separate location from the database backup.

---

## Tested

The round-trips this runbook depends on are exercised by `tests/test_dr_drill.py`:
database backup→restore preserves rows; the schema self-migration adds new
columns to an *old* database without touching existing data; and the
sealed-keystore **escrow export → import on a fresh store → the Local CA still
signs**. Run it before trusting a procedure change.
