#!/bin/bash
# csrbackup - snapshot the CSR Dashboard deployment files and database.
#
# Output goes to /root/csr-backup-YYYYMMDD-HHMMSS/
#
# Usage:
#   csrbackup            # take a backup now
#   csrbackup --list     # show existing backups
#   csrbackup --help     # this message

set -euo pipefail

# ----- Argument handling -----
case "${1:-}" in
    -l|--list)
        echo "Existing CSR Dashboard backups in /root/:"
        ls -lhd /root/csr-backup-* 2>/dev/null || echo "  (none)"
        exit 0
        ;;
    -h|--help)
        cat <<'EOF'
csrbackup - snapshot the CSR Dashboard deployment files and database.

Output goes to /root/csr-backup-YYYYMMDD-HHMMSS/

Usage:
  csrbackup            # take a backup now
  csrbackup --list     # show existing backups
  csrbackup --help     # this message
EOF
        exit 0
        ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "csrbackup: must be run as root" >&2
    exit 1
fi

# ----- Configuration -----
# Files to back up. Each is conditionally included only if it exists, so this
# script stays forward-compatible as new files are added to the deployment.
FILES=(
    /opt/csr-dashboard/app.py
    /opt/csr-dashboard/notify.py
    /var/www/csr/index.html
    /var/www/csr/app.js
    /root/sslcerts/scripts/csr_dashboard_helper.sh
    /etc/systemd/system/certinel-api.service
    /etc/sudoers.d/csr-dashboard
    /etc/csr-dashboard/email.conf
    /usr/local/sbin/csr-bootstrap-admin
    /usr/local/sbin/csrbackup
)
DB="/var/lib/csr-dashboard/jobs.db"

TS="$(date +%Y%m%d-%H%M%S)"
DEST="/root/csr-backup-$TS"

# ----- Run -----
echo "csrbackup: snapshot to $DEST"
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
# csrapi owns, then move into the backup tree as root.
db_status="not present"
if [[ -e "$DB" ]]; then
    mkdir -p "$DEST/var/lib/csr-dashboard"
    SNAP="/var/lib/csr-dashboard/jobs.db.snapshot.$$"
    if sudo -u csrapi sqlite3 "$DB" ".backup '$SNAP'"; then
        mv "$SNAP" "$DEST/var/lib/csr-dashboard/jobs.db"
        db_size=$(stat -c%s "$DEST/var/lib/csr-dashboard/jobs.db")
        db_jobs=$(sqlite3 "$DEST/var/lib/csr-dashboard/jobs.db" \
            "SELECT COUNT(*) FROM jobs;" 2>/dev/null || echo "?")
        db_status="${db_size} bytes, ${db_jobs} job rows"
    else
        db_status="FAILED — see error above"
    fi
fi

# ----- Report -----
echo ""
echo "csrbackup: files copied: $copied"
if [[ ${#skipped[@]} -gt 0 ]]; then
    echo "csrbackup: not present (skipped):"
    for f in "${skipped[@]}"; do echo "  $f"; done
fi
echo "csrbackup: database: $db_status"
echo ""
echo "csrbackup: contents:"
find "$DEST" -type f -printf '  %M %u:%g %10s  %p\n'
echo ""
echo "csrbackup: total size: $(du -sh "$DEST" | cut -f1)"
echo ""
echo "Restore an individual file:"
echo "  cp -p $DEST/<path/to/file> /<path/to/file>"
echo "Restore the database (stop service first):"
echo "  systemctl stop certinel-api"
echo "  cp -p $DEST/var/lib/csr-dashboard/jobs.db /var/lib/csr-dashboard/jobs.db"
echo "  rm -f /var/lib/csr-dashboard/jobs.db-wal /var/lib/csr-dashboard/jobs.db-shm"
echo "  chown csrapi:csrapi /var/lib/csr-dashboard/jobs.db"
echo "  chmod 0640          /var/lib/csr-dashboard/jobs.db"
echo "  systemctl start certinel-api"
