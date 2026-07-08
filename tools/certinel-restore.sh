#!/bin/bash
# certinel-restore - restore a Certheim deployment from a certinel-backup archive.
#
# Restores config, systemd units, sudoers, on-disk private keys, and the
# database from a backup produced by certinel-backup. It does NOT install the
# application code — reinstall the matching release first (the backup's
# BACKUP-MANIFEST.txt records the version), then run this to put state back.
#
# The service is stopped for the DB swap and started again at the end.
#
# Usage:
#   certinel-restore /root/certinel-backup-YYYYMMDD-HHMMSS.tar.gz
#   certinel-restore /root/certinel-backup-YYYYMMDD-HHMMSS/     # unpacked tree
#   certinel-restore --help

set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || -z "${1:-}" ]]; then
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi
if [[ $EUID -ne 0 ]]; then
    echo "certinel-restore: must be run as root" >&2
    exit 1
fi

SRC="$1"
SERVICE_USER="${CERTINEL_USER:-certinel}"
SERVICE_GROUP="${CERTINEL_GROUP:-$SERVICE_USER}"
WORK=""; cleanup() { [[ -n "$WORK" ]] && rm -rf "$WORK"; }; trap cleanup EXIT

# Resolve the backup into a directory tree.
if [[ -d "$SRC" ]]; then
    TREE="$SRC"
elif [[ -f "$SRC" ]]; then
    WORK="$(mktemp -d)"
    tar -C "$WORK" -xzf "$SRC"
    TREE="$(find "$WORK" -maxdepth 1 -type d -name 'certinel-backup-*' | head -1)"
    [[ -z "$TREE" ]] && TREE="$WORK"
else
    echo "certinel-restore: $SRC not found" >&2
    exit 1
fi

echo "certinel-restore: restoring from $TREE"
[[ -f "$TREE/BACKUP-MANIFEST.txt" ]] && { echo "----- manifest -----"; cat "$TREE/BACKUP-MANIFEST.txt"; echo "--------------------"; }

read -r -p "Proceed? This overwrites current config, keys and database. [y/N] " ans
[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted."; exit 1; }

echo "certinel-restore: stopping certinel-api"
systemctl stop certinel-api 2>/dev/null || true

# ----- Filesystem trees (config, keys, units, sudoers) -----
# The backup stored them with cp --parents, so paths under $TREE mirror /.
for sub in etc/certinel etc/sudoers.d/certinel var/opt/certinel/private var/opt/certinel/issued; do
    if [[ -e "$TREE/$sub" ]]; then
        echo "certinel-restore: restoring /$sub"
        mkdir -p "/$(dirname "$sub")"
        cp -a "$TREE/$sub" "/$(dirname "$sub")/"
    fi
done
if compgen -G "$TREE/etc/systemd/system/certinel-*" > /dev/null; then
    echo "certinel-restore: restoring systemd units"
    cp -a "$TREE"/etc/systemd/system/certinel-* /etc/systemd/system/
    systemctl daemon-reload
fi

# ----- Database -----
ENV_FILE="/etc/certinel/certinel.env"
CSR_DB_URL=""; CSR_DB_PATH=""
if [[ -f "$ENV_FILE" ]]; then
    CSR_DB_URL="$(grep -E '^CSR_DB_URL=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"')"
    CSR_DB_PATH="$(grep -E '^CSR_DB_PATH=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"')"
fi
DB="${CSR_DB_PATH:-/var/lib/certinel/jobs.db}"

if [[ -f "$TREE/db/certinel.dump" ]]; then
    if [[ -z "$CSR_DB_URL" ]]; then
        echo "certinel-restore: found a Postgres dump but CSR_DB_URL is unset; set it in $ENV_FILE first" >&2
        exit 1
    fi
    echo "certinel-restore: restoring Postgres (pg_restore --clean --if-exists)"
    pg_restore --clean --if-exists --no-owner -d "$CSR_DB_URL" "$TREE/db/certinel.dump"
elif [[ -f "$TREE/db/jobs.db" ]]; then
    echo "certinel-restore: restoring sqlite DB to $DB"
    mkdir -p "$(dirname "$DB")"
    cp -f "$TREE/db/jobs.db" "$DB"
    rm -f "${DB}-wal" "${DB}-shm"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$DB"
    chmod 0640 "$DB"
else
    echo "certinel-restore: WARNING — no database found in backup; skipping DB restore"
fi

# SELinux contexts (no-op off RHEL-family / permissive).
command -v restorecon >/dev/null && restorecon -RF /etc/certinel /var/opt/certinel 2>/dev/null || true

echo "certinel-restore: starting certinel-api"
systemctl start certinel-api

echo ""
echo "certinel-restore: DONE. Verify health, then confirm the sealed keystore"
echo "unseals with your admin-held passphrase/recovery-code (it is NOT restored"
echo "from backup — only the encrypted secrets are)."
