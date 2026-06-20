#!/bin/bash
# certinel-uninstall.sh - cleanly remove the Certinel from this host.
#
#   sudo ./certinel-uninstall.sh            Guided uninstall (prompts before each
#                                      destructive choice; safe defaults).
#   sudo ./certinel-uninstall.sh --help     Show this help.
#   sudo ./certinel-uninstall.sh --dry-run  Show what WOULD be removed; change
#                                      nothing.
#
# What it does:
#   - stops + disables the systemd units (certinel-api, certinel-expiry-warn .service
#     and .timer) and removes the unit files
#   - removes the application code (/opt/certinel), frontend
#     (/var/www/certinel), helper scripts, and the installed tools
#   - removes ONLY the app's nginx fragment (/etc/nginx/certinel.d/30-csr.conf);
#     leaves PKI (client CA bundle, server certs) and the rest of nginx alone
#   - PROMPTS about the database (default: preserve via timestamped backup)
#   - PROMPTS about removing the certinel service account
#
# What it deliberately does NOT touch:
#   - PKI material (/etc/pki/certinel, client CA bundle) - site-managed
#   - nginx itself or any other service's config
#   - firewalld rules (port 443 may be shared)
#   - /home/ansible/issued (managed outside this app)
#
# Idempotent: safe to re-run; missing items are skipped.

set -uo pipefail   # NOT -e: uninstall should continue past a missing item

# ---- paths (match deploy.sh / the installer) ------------------------------
APP_DIR="/opt/certinel"
WWW_DIR="/var/www/certinel"
DB_DIR="/var/lib/certinel"
DB_FILE="${DB_DIR}/jobs.db"
CFG_DIR="/etc/certinel"
HELPER_DIR="/opt/certinel/helper"
NGINX_FRAG="/etc/nginx/certinel.d/30-csr.conf"
SUDOERS="/etc/sudoers.d/certinel"
SVC_USER="certinel"
UNITS=(certinel-api.service certinel-expiry-warn.service certinel-expiry-warn.timer)
TOOLS=(/usr/local/sbin/certinel-backup /usr/local/sbin/certinel-bootstrap-admin)

DRY=false
usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }
case "${1:-}" in
    --help|-h) usage; exit 0 ;;
    --dry-run) DRY=true ;;
    "") : ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
esac

[[ $EUID -eq 0 ]] || { echo "run as root (or --help)" >&2; exit 1; }

say()  { echo -e "$*"; }
do_or_show() {
    # do_or_show "description" cmd args...
    local desc="$1"; shift
    if $DRY; then
        echo "  [dry-run] would: $desc"
    else
        echo "  $desc"
        "$@" 2>/dev/null || echo "    (skip/failed: $desc)"
    fi
}

echo "=============================================================="
echo "  Certinel uninstall"
$DRY && echo "  *** DRY RUN - nothing will be changed ***"
echo "=============================================================="
echo
echo "This will stop the service and remove the application from this host."
echo "PKI certificates and the client CA bundle will be LEFT in place."
echo

# --- top-level confirmation (skipped in dry-run) ---------------------------
if ! $DRY; then
    read -r -p "Type 'remove' to proceed: " ans
    [[ "$ans" == "remove" ]] || { echo "Aborted - nothing changed."; exit 0; }
    echo
fi

# --- 1. stop + disable + remove units --------------------------------------
say "1) systemd units"
for u in "${UNITS[@]}"; do
    if systemctl list-unit-files "$u" >/dev/null 2>&1 \
       && systemctl cat "$u" >/dev/null 2>&1; then
        do_or_show "stop $u"    systemctl stop "$u"
        do_or_show "disable $u" systemctl disable "$u"
        do_or_show "rm /etc/systemd/system/$u" rm -f "/etc/systemd/system/$u"
    else
        echo "  ($u not present)"
    fi
done
do_or_show "daemon-reload" systemctl daemon-reload
echo

# --- 2. application code, frontend, helper, tools --------------------------
say "2) application files"
do_or_show "rm -rf $APP_DIR"    rm -rf "$APP_DIR"
do_or_show "rm -rf $WWW_DIR"    rm -rf "$WWW_DIR"
do_or_show "rm -rf $HELPER_DIR" rm -rf "$HELPER_DIR"
for t in "${TOOLS[@]}"; do
    do_or_show "rm $t" rm -f "$t"
done
echo

# --- 3. nginx fragment ONLY ------------------------------------------------
say "3) nginx fragment (app only - PKI and other config untouched)"
if [[ -f "$NGINX_FRAG" ]]; then
    do_or_show "rm $NGINX_FRAG" rm -f "$NGINX_FRAG"
    if ! $DRY; then
        if nginx -t 2>/dev/null; then
            systemctl reload-or-restart nginx 2>/dev/null \
                && echo "  nginx reloaded" \
                || echo "  (nginx reload skipped)"
        else
            echo "  WARN: nginx -t failed after removing the fragment - check config" >&2
        fi
    fi
else
    echo "  (fragment not present)"
fi
echo

# --- 4. database: PROMPT (default = preserve via backup) -------------------
say "4) database"
if [[ -f "$DB_FILE" ]]; then
    if $DRY; then
        echo "  [dry-run] would prompt: keep (backup) or delete the database"
    else
        echo "  The database holds all certificate request history."
        echo "    K) keep  - move it to a timestamped backup (default)"
        echo "    D) delete - permanently remove it"
        read -r -p "  Keep or delete? [K/d]: " dbans
        case "${dbans:-k}" in
            [Dd]*)
                read -r -p "  Type 'delete-data' to confirm permanent deletion: " c
                if [[ "$c" == "delete-data" ]]; then
                    rm -f "$DB_FILE" "${DB_FILE}-wal" "${DB_FILE}-shm"
                    echo "  database deleted"
                else
                    echo "  not confirmed - keeping database"
                    dbans="k"
                fi
                ;;
        esac
        if [[ "${dbans:-k}" != [Dd]* ]]; then
            ts="$(date +%Y%m%d-%H%M%S)"
            bk="/root/certinel-db-backup-${ts}"
            mkdir -p "$bk"
            cp -p "$DB_FILE" "$bk/" 2>/dev/null
            [[ -f "${DB_FILE}-wal" ]] && cp -p "${DB_FILE}-wal" "$bk/" 2>/dev/null
            [[ -f "${DB_FILE}-shm" ]] && cp -p "${DB_FILE}-shm" "$bk/" 2>/dev/null
            echo "  database preserved -> $bk"
            echo "  (the live $DB_DIR is left in place; remove it manually if desired)"
        fi
    fi
else
    echo "  (no database found)"
fi
echo

# --- 5. config dir ---------------------------------------------------------
say "5) config"
if [[ -d "$CFG_DIR" ]]; then
    # email.conf / certinel.env are operator state; back them up rather
    # than silently deleting credentials/relay settings.
    if $DRY; then
        echo "  [dry-run] would back up + remove $CFG_DIR"
    else
        ts="$(date +%Y%m%d-%H%M%S)"
        bk="/root/certinel-config-backup-${ts}"
        mkdir -p "$bk"; cp -rp "$CFG_DIR/." "$bk/" 2>/dev/null
        rm -rf "$CFG_DIR"
        echo "  config backed up -> $bk, then removed"
    fi
else
    echo "  (no config dir)"
fi
do_or_show "rm $SUDOERS" rm -f "$SUDOERS"
echo

# --- 6. service account: PROMPT --------------------------------------------
say "6) service account ($SVC_USER)"
if id "$SVC_USER" >/dev/null 2>&1; then
    if $DRY; then
        echo "  [dry-run] would prompt whether to remove user $SVC_USER"
    else
        echo "  The $SVC_USER account may own other files on this host."
        read -r -p "  Remove the $SVC_USER service account? [y/N]: " uans
        case "${uans:-n}" in
            [Yy]*)
                userdel "$SVC_USER" 2>/dev/null \
                    && echo "  removed user $SVC_USER" \
                    || echo "  (could not remove $SVC_USER - may own running procs)"
                ;;
            *) echo "  keeping $SVC_USER" ;;
        esac
    fi
else
    echo "  ($SVC_USER not present)"
fi
echo

# --- 7. fapolicyd trust cleanup (best-effort) ------------------------------
say "7) fapolicyd"
if command -v fapolicyd-cli >/dev/null 2>&1; then
    do_or_show "refresh fapolicyd trust db" fapolicyd-cli --update
    echo "  (note: any app paths added to trust are gone with the files;"
    echo "   the update above refreshes the database)"
else
    echo "  (fapolicyd-cli not present)"
fi
echo

echo "=============================================================="
$DRY && echo "  DRY RUN complete - nothing was changed." \
     || echo "  Uninstall complete."
echo "  Left in place: PKI certs, client CA bundle, nginx itself,"
echo "  firewalld rules, and any database/config backups noted above."
echo "=============================================================="
