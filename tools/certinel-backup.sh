#!/bin/bash
# certinel-backup - snapshot the recoverable state of a Certinel deployment.
#
# Backs up the things that CANNOT be regenerated from a release artifact:
#   - the database (all jobs, settings, sealed-keystore ciphertext, ACME state)
#   - /etc/certinel   (env, license, email/chat/doctor config, install.conf)
#   - /var/opt/certinel/private  (on-disk private keys, when key_storage=file)
#   - the systemd units + sudoers drop-in that wire it together
# Application code (/opt/certinel, /var/www/csr) is intentionally NOT included:
# reinstall it from the pinned release. install.conf records that version.
#
# Output goes to /root/certinel-backup-YYYYMMDD-HHMMSS/ (a tarball alongside).
#
# IMPORTANT — sealed keystore: the encrypted secrets live in the DB and ARE
# captured here, but the unseal material (passphrase / recovery code / Shamir
# shares) is admin-held and is NOT in any backup. Store it separately, or a
# restore cannot decrypt CA/RA/TSA/code-signing keys. For a portable escrow
# bundle that re-encrypts under a new passphrase, use the admin UI:
# Settings -> Sealed keystore -> Export backup.
#
# Usage:
#   certinel-backup            # take a backup now
#   certinel-backup --list     # show existing backups
#   certinel-backup --help     # this message

set -euo pipefail

case "${1:-}" in
    -l|--list)
        echo "Existing Certinel backups in /root/:"
        ls -lhd /root/certinel-backup-* 2>/dev/null || echo "  (none)"
        exit 0
        ;;
    -h|--help)
        sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "certinel-backup: must be run as root" >&2
    exit 1
fi

SERVICE_USER="${CERTINEL_USER:-certinel}"
ENV_FILE="/etc/certinel/certinel.env"
# Pull DB coordinates from the service env if present (CSR_DB_URL for Postgres,
# CSR_DB_PATH for sqlite). Defaults mirror backend/db.py.
CSR_DB_URL=""; CSR_DB_PATH=""
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    CSR_DB_URL="$(grep -E '^CSR_DB_URL=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"')"
    CSR_DB_PATH="$(grep -E '^CSR_DB_PATH=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"')"
fi
DB="${CSR_DB_PATH:-/var/lib/certinel/jobs.db}"

# Directory trees / files to snapshot, each included only if present so the
# script stays forward-compatible as the deployment grows.
PATHS=(
    /etc/certinel
    /etc/sudoers.d/certinel
    /var/opt/certinel/private
    /var/opt/certinel/issued
)
for u in /etc/systemd/system/certinel-*.service /etc/systemd/system/certinel-*.timer; do
    [[ -e "$u" ]] && PATHS+=("$u")
done

TS="$(date +%Y%m%d-%H%M%S)"
DEST="/root/certinel-backup-$TS"
echo "certinel-backup: snapshot to $DEST"
mkdir -p "$DEST"

copied=0; skipped=()
for f in "${PATHS[@]}"; do
    if [[ -e "$f" ]]; then
        cp -a --parents "$f" "$DEST"
        copied=$((copied + 1))
    else
        skipped+=("$f")
    fi
done

# ----- Database -----
db_status="not present"
if [[ -n "$CSR_DB_URL" && "$CSR_DB_URL" == postgres* ]]; then
    mkdir -p "$DEST/db"
    if PGCONNECT_TIMEOUT=10 pg_dump "$CSR_DB_URL" -Fc -f "$DEST/db/certinel.dump" 2>"$DEST/db/pg_dump.err"; then
        db_status="Postgres pg_dump: $(stat -c%s "$DEST/db/certinel.dump") bytes (restore with pg_restore)"
        rm -f "$DEST/db/pg_dump.err"
    else
        db_status="Postgres pg_dump FAILED — see $DEST/db/pg_dump.err"
    fi
elif [[ -e "$DB" ]]; then
    mkdir -p "$DEST/db"
    # Online .backup handles WAL consistently. Snapshot to a path the service
    # user owns, then move it into the backup tree as root.
    SNAP="$(dirname "$DB")/.certinel-backup.$$.db"
    if sudo -u "$SERVICE_USER" sqlite3 "$DB" ".backup '$SNAP'"; then
        mv "$SNAP" "$DEST/db/jobs.db"
        db_jobs=$(sqlite3 "$DEST/db/jobs.db" "SELECT COUNT(*) FROM jobs;" 2>/dev/null || echo "?")
        db_status="sqlite $(stat -c%s "$DEST/db/jobs.db") bytes, ${db_jobs} job rows"
    else
        db_status="sqlite .backup FAILED — see error above"
    fi
fi

# Provenance stamp so a restore knows exactly what it is looking at.
{
    echo "created=$TS"
    echo "host=$(hostname -f 2>/dev/null || hostname)"
    echo "service_user=$SERVICE_USER"
    echo "db=$db_status"
    [[ -f /opt/certinel/VERSION ]] && echo "version=$(cat /opt/certinel/VERSION)"
} > "$DEST/BACKUP-MANIFEST.txt"

# ----- Report -----
echo ""
echo "certinel-backup: paths copied: $copied"
if [[ ${#skipped[@]} -gt 0 ]]; then
    echo "certinel-backup: not present (skipped):"
    for f in "${skipped[@]}"; do echo "  $f"; done
fi
echo "certinel-backup: database: $db_status"

# Tar it up for easy off-box transfer; keep the tree too for spot restores.
TARBALL="$DEST.tar.gz"
tar -C /root -czf "$TARBALL" "certinel-backup-$TS"
echo "certinel-backup: total size: $(du -sh "$DEST" | cut -f1)  (tarball: $(du -sh "$TARBALL" | cut -f1))"
echo ""
echo "certinel-backup: DONE."
echo "  tree:    $DEST"
echo "  tarball: $TARBALL"
echo ""
echo "Restore with:   certinel-restore $TARBALL"
echo ""
echo "REMINDER: the sealed-keystore unseal material (passphrase / recovery code"
echo "/ Shamir shares) is NOT in this backup. Confirm it is stored separately."
