#!/bin/bash
# certinel-backup - snapshot the Certinel deployment files and database.
#
# Output goes to /root/csr-backup-YYYYMMDD-HHMMSS/
#
# Usage:
#   certinel-backup            # take a backup now
#   certinel-backup --list     # show existing backups
#   certinel-backup --help     # this message

set -euo pipefail

# ----- Argument handling -----
case "${1:-}" in
    -l|--list)
        echo "Existing Certinel backups in /root/:"
        ls -lhd /root/csr-backup-* 2>/dev/null || echo "  (none)"
        exit 0
        ;;
    -h|--help)
        cat <<'EOF'
certinel-backup - snapshot the Certinel deployment files and database.

Output goes to /root/csr-backup-YYYYMMDD-HHMMSS/

Usage:
  certinel-backup            # take a backup now
  certinel-backup --list     # show existing backups
  certinel-backup --help     # this message
EOF
        exit 0
        ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "certinel-backup: must be run as root" >&2
    exit 1
fi

# ----- Configuration -----
# Files to back up. Each is conditionally included only if it exists, so this
# script stays forward-compatible as new files are added to the deployment.
FILES=(
    /opt/certinel/app.py
    /opt/certinel/notify.py
    /var/www/certinel/index.html
    /var/www/certinel/app.js
    /opt/certinel/helper/certinel_helper.sh
    /etc/systemd/system/certinel-api.service
    /etc/sudoers.d/certinel
    /etc/certinel/email.conf
    /usr/local/sbin/certinel-bootstrap-admin
    /usr/local/sbin/certinel-backup
)
DB="/var/lib/certinel/jobs.db"

TS="$(date +%Y%m%d-%H%M%S)"
DEST="/root/csr-backup-$TS"

# ----- Run -----
echo "certinel-backup: snapshot to $DEST"
mkdir -p "$DEST"

copied=0
skipped=()
for f in "${FILES[@]}"; do
    if [[ -e "$f" ]]; then
        cp -p --parents "$f" "$DEST"
        copied=$((copied + 1))
    else
        skipped+=("$f")
    fi
done

# SQLite snapshot via .backup (handles WAL consistently). Write to a path
# certinel owns, then move into the backup tree as root.
db_status="not present"
if [[ -e "$DB" ]]; then
    mkdir -p "$DEST/var/lib/certinel"
    SNAP="/var/lib/certinel/jobs.db.snapshot.$$"
    if sudo -u certinel sqlite3 "$DB" ".backup '$SNAP'"; then
        mv "$SNAP" "$DEST/var/lib/certinel/jobs.db"
        db_size=$(stat -c%s "$DEST/var/lib/certinel/jobs.db")
        db_jobs=$(sqlite3 "$DEST/var/lib/certinel/jobs.db" \
            "SELECT COUNT(*) FROM jobs;" 2>/dev/null || echo "?")
        db_status="${db_size} bytes, ${db_jobs} job rows"
    else
        db_status="FAILED — see error above"
    fi
fi

# ----- Report -----
echo ""
echo "certinel-backup: files copied: $copied"
if [[ ${#skipped[@]} -gt 0 ]]; then
    echo "certinel-backup: not present (skipped):"
    for f in "${skipped[@]}"; do echo "  $f"; done
fi
echo "certinel-backup: database: $db_status"
echo ""
echo "certinel-backup: contents:"
find "$DEST" -type f -printf '  %M %u:%g %10s  %p\n'
echo ""
echo "certinel-backup: total size: $(du -sh "$DEST" | cut -f1)"
echo ""
echo "Restore an individual file:"
echo "  cp -p $DEST/<path/to/file> /<path/to/file>"
echo "Restore the database (stop service first):"
echo "  systemctl stop certinel-api"
echo "  cp -p $DEST/var/lib/certinel/jobs.db /var/lib/certinel/jobs.db"
echo "  rm -f /var/lib/certinel/jobs.db-wal /var/lib/certinel/jobs.db-shm"
echo "  chown certinel:certinel /var/lib/certinel/jobs.db"
echo "  chmod 0640          /var/lib/certinel/jobs.db"
echo "  systemctl start certinel-api"
