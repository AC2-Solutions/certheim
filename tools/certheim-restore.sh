#!/bin/bash
# certheim-restore - restore a Certheim deployment from a certheim-backup archive.
#
# Restores config, systemd units, sudoers, on-disk private keys, and the
# database from a backup produced by certheim-backup. It does NOT install the
# application code — reinstall the matching release first (the backup's
# BACKUP-MANIFEST.txt records the version), then run this to put state back.
#
# The service is stopped for the DB swap and started again at the end.
#
# Usage:
#   certheim-restore /root/certheim-backup-YYYYMMDD-HHMMSS.tar.gz
#   certheim-restore /root/certheim-backup-YYYYMMDD-HHMMSS/     # unpacked tree
#   certheim-restore --help

set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || -z "${1:-}" ]]; then
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi
if [[ $EUID -ne 0 ]]; then
    echo "certheim-restore: must be run as root" >&2
    exit 1
fi

SRC="$1"
SERVICE_USER="${CERTHEIM_USER:-certheim}"
SERVICE_GROUP="${CERTHEIM_GROUP:-$SERVICE_USER}"
WORK=""; cleanup() { [[ -n "$WORK" ]] && rm -rf "$WORK"; }; trap cleanup EXIT

# Resolve the backup into a directory tree.
if [[ -d "$SRC" ]]; then
    TREE="$SRC"
elif [[ -f "$SRC" ]]; then
    WORK="$(mktemp -d)"
    tar -C "$WORK" -xzf "$SRC"
    TREE="$(find "$WORK" -maxdepth 1 -type d -name 'certheim-backup-*' | head -1)"
    [[ -z "$TREE" ]] && TREE="$WORK"
else
    echo "certheim-restore: $SRC not found" >&2
    exit 1
fi

echo "certheim-restore: restoring from $TREE"
[[ -f "$TREE/BACKUP-MANIFEST.txt" ]] && { echo "----- manifest -----"; cat "$TREE/BACKUP-MANIFEST.txt"; echo "--------------------"; }

read -r -p "Proceed? This overwrites current config, keys and database. [y/N] " ans
[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted."; exit 1; }

echo "certheim-restore: stopping certheim-api"
systemctl stop certheim-api 2>/dev/null || true

# ----- Filesystem trees (config, keys, units, sudoers) -----
# The backup stored them with cp --parents, so paths under $TREE mirror /.
for sub in etc/certheim etc/sudoers.d/certheim var/opt/certheim/private var/opt/certheim/issued; do
    if [[ -e "$TREE/$sub" ]]; then
        echo "certheim-restore: restoring /$sub"
        mkdir -p "/$(dirname "$sub")"
        cp -a "$TREE/$sub" "/$(dirname "$sub")/"
    fi
done
if compgen -G "$TREE/etc/systemd/system/certheim-*" > /dev/null; then
    echo "certheim-restore: restoring systemd units"
    cp -a "$TREE"/etc/systemd/system/certheim-* /etc/systemd/system/
    systemctl daemon-reload
fi

# ----- Database -----
ENV_FILE="/etc/certheim/certheim.env"
CERTHEIM_DB_URL=""; CERTHEIM_DB_PATH=""
if [[ -f "$ENV_FILE" ]]; then
    CERTHEIM_DB_URL="$(grep -E '^CERTHEIM_DB_URL=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"')"
    CERTHEIM_DB_PATH="$(grep -E '^CERTHEIM_DB_PATH=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"')"
fi
DB="${CERTHEIM_DB_PATH:-/var/lib/certheim/jobs.db}"

if [[ -f "$TREE/db/certheim.dump" ]]; then
    if [[ -z "$CERTHEIM_DB_URL" ]]; then
        echo "certheim-restore: found a Postgres dump but CERTHEIM_DB_URL is unset; set it in $ENV_FILE first" >&2
        exit 1
    fi
    echo "certheim-restore: restoring Postgres (pg_restore --clean --if-exists)"
    pg_restore --clean --if-exists --no-owner -d "$CERTHEIM_DB_URL" "$TREE/db/certheim.dump"
elif [[ -f "$TREE/db/jobs.db" ]]; then
    echo "certheim-restore: restoring sqlite DB to $DB"
    mkdir -p "$(dirname "$DB")"
    cp -f "$TREE/db/jobs.db" "$DB"
    rm -f "${DB}-wal" "${DB}-shm"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$DB"
    chmod 0640 "$DB"
else
    echo "certheim-restore: WARNING — no database found in backup; skipping DB restore"
fi

# SELinux contexts (no-op off RHEL-family / permissive).
command -v restorecon >/dev/null && restorecon -RF /etc/certheim /var/opt/certheim 2>/dev/null || true

echo "certheim-restore: starting certheim-api"
systemctl start certheim-api

echo ""
echo "certheim-restore: DONE. Verify health, then confirm the sealed keystore"
echo "unseals with your admin-held passphrase/recovery-code (it is NOT restored"
echo "from backup — only the encrypted secrets are)."
