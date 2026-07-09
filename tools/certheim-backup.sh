#!/bin/bash
# certheim-backup - snapshot the recoverable state of a Certheim deployment.
#
# Backs up the things that CANNOT be regenerated from a release artifact:
#   - the database (all jobs, settings, sealed-keystore ciphertext, ACME state)
#   - /etc/certheim   (env, license, email/chat/doctor config, install.conf)
#   - /var/opt/certheim/private  (on-disk private keys, when key_storage=file)
#   - the systemd units + sudoers drop-in that wire it together
# Application code (/opt/certheim, /var/www/csr) is intentionally NOT included:
# reinstall it from the pinned release. install.conf records that version.
#
# Output goes to /root/certheim-backup-YYYYMMDD-HHMMSS/ (a tarball alongside).
#
# IMPORTANT — sealed keystore: the encrypted secrets live in the DB and ARE
# captured here, but the unseal material (passphrase / recovery code / Shamir
# shares) is admin-held and is NOT in any backup. Store it separately, or a
# restore cannot decrypt CA/RA/TSA/code-signing keys. For a portable escrow
# bundle that re-encrypts under a new passphrase, use the admin UI:
# Settings -> Sealed keystore -> Export backup.
#
# Usage:
#   certheim-backup            # take a backup now
#   certheim-backup --list     # show existing backups
#   certheim-backup --help     # this message

set -euo pipefail

case "${1:-}" in
    -l|--list)
        echo "Existing Certheim backups in /root/:"
        ls -lhd /root/certheim-backup-* 2>/dev/null || echo "  (none)"
        exit 0
        ;;
    -h|--help)
        sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "certheim-backup: must be run as root" >&2
    exit 1
fi

SERVICE_USER="${CERTHEIM_USER:-certheim}"
ENV_FILE="/etc/certheim/certheim.env"
# Pull DB coordinates from the service env if present (CERTHEIM_DB_URL for Postgres,
# CERTHEIM_DB_PATH for sqlite). Defaults mirror backend/db.py.
CERTHEIM_DB_URL=""; CERTHEIM_DB_PATH=""
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    CERTHEIM_DB_URL="$(grep -E '^CERTHEIM_DB_URL=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"')"
    CERTHEIM_DB_PATH="$(grep -E '^CERTHEIM_DB_PATH=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"')"
fi
DB="${CERTHEIM_DB_PATH:-/var/lib/certheim/jobs.db}"

# Directory trees / files to snapshot, each included only if present so the
# script stays forward-compatible as the deployment grows.
PATHS=(
    /etc/certheim
    /etc/sudoers.d/certheim
    /var/opt/certheim/private
    /var/opt/certheim/issued
)
for u in /etc/systemd/system/certheim-*.service /etc/systemd/system/certheim-*.timer; do
    [[ -e "$u" ]] && PATHS+=("$u")
done

TS="$(date +%Y%m%d-%H%M%S)"
DEST="/root/certheim-backup-$TS"
echo "certheim-backup: snapshot to $DEST"
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
if [[ -n "$CERTHEIM_DB_URL" && "$CERTHEIM_DB_URL" == postgres* ]]; then
    mkdir -p "$DEST/db"
    if PGCONNECT_TIMEOUT=10 pg_dump "$CERTHEIM_DB_URL" -Fc -f "$DEST/db/certheim.dump" 2>"$DEST/db/pg_dump.err"; then
        db_status="Postgres pg_dump: $(stat -c%s "$DEST/db/certheim.dump") bytes (restore with pg_restore)"
        rm -f "$DEST/db/pg_dump.err"
    else
        db_status="Postgres pg_dump FAILED — see $DEST/db/pg_dump.err"
    fi
elif [[ -e "$DB" ]]; then
    mkdir -p "$DEST/db"
    # Online .backup handles WAL consistently. Snapshot to a path the service
    # user owns, then move it into the backup tree as root.
    SNAP="$(dirname "$DB")/.certheim-backup.$$.db"
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
    [[ -f /opt/certheim/VERSION ]] && echo "version=$(cat /opt/certheim/VERSION)"
} > "$DEST/BACKUP-MANIFEST.txt"

# ----- Report -----
echo ""
echo "certheim-backup: paths copied: $copied"
if [[ ${#skipped[@]} -gt 0 ]]; then
    echo "certheim-backup: not present (skipped):"
    for f in "${skipped[@]}"; do echo "  $f"; done
fi
echo "certheim-backup: database: $db_status"

# Tar it up for easy off-box transfer; keep the tree too for spot restores.
TARBALL="$DEST.tar.gz"
tar -C /root -czf "$TARBALL" "certheim-backup-$TS"
echo "certheim-backup: total size: $(du -sh "$DEST" | cut -f1)  (tarball: $(du -sh "$TARBALL" | cut -f1))"
echo ""
echo "certheim-backup: DONE."
echo "  tree:    $DEST"
echo "  tarball: $TARBALL"
echo ""
echo "Restore with:   certheim-restore $TARBALL"
echo ""
echo "REMINDER: the sealed-keystore unseal material (passphrase / recovery code"
echo "/ Shamir shares) is NOT in this backup. Confirm it is stored separately."
