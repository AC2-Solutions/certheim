#!/bin/bash
# certheim-migrate.sh - migrate a pre-5.2 (certinel-named) install in place to
# the certheim layout. Rename Phase 2/3 (docs/certheim-rename-design.md §3).
#
# Invoked automatically by deploy.sh when it detects the legacy layout; safe to
# run by hand. Idempotent: exits 0 immediately when there is nothing to migrate.
# Refuses (exit 2) when BOTH layouts exist — that needs a human.
#
# What it does, in order (each step logged):
#   backup -> stop old units -> move dirs -> service account -> rewrite configs
#   -> SELinux relabel -> fapolicyd re-trust -> daemon-reload
# It does NOT install the new files or start services — deploy.sh does that
# right after (this runs as its pre-flight). Rollback: the premigrate backup +
# reverse `mv`s; nothing is deleted except the old unit files and sudoers entry.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "certheim-migrate: run as root" >&2; exit 1; }

log() { echo "certheim-migrate: $*"; }

OLD_PRESENT=false
[[ -e /opt/certinel || -e /etc/certinel ]] && OLD_PRESENT=true
if ! $OLD_PRESENT; then
    log "no legacy certinel layout - nothing to migrate"
    exit 0
fi
if [[ -e /opt/certheim && -e /opt/certinel ]]; then
    echo "certheim-migrate: BOTH /opt/certinel and /opt/certheim exist - refusing." >&2
    echo "  Resolve by hand (which one is live?), then re-run." >&2
    exit 2
fi

STAMP="$(date +%Y%m%d-%H%M%S)"

# ---- 1. backup (refuse to continue without one) -----------------------------
BK="/root/certheim-backup-premigrate-${STAMP}"
if command -v certinel-backup >/dev/null 2>&1; then
    log "backup via certinel-backup"
    certinel-backup || { echo "certheim-migrate: certinel-backup FAILED - aborting" >&2; exit 1; }
else
    log "backup via tar -> ${BK}.tar.gz"
    tar czf "${BK}.tar.gz" \
        --ignore-failed-read \
        /etc/certinel /var/lib/certinel /var/opt/certinel \
        /etc/systemd/system/certinel-*.service /etc/systemd/system/certinel-*.timer \
        /etc/sudoers.d/certinel 2>/dev/null \
        || { echo "certheim-migrate: tar backup FAILED - aborting" >&2; exit 1; }
fi

# ---- 2. stop + disable the old units ----------------------------------------
log "stopping legacy certinel units"
for u in certinel-api certinel-expiry-warn certinel-auto-renew certinel-deliver \
         certinel-doctor certinel-tls-renew certinel-slack-listener; do
    systemctl disable --now "$u.timer"   2>/dev/null || true
    systemctl disable --now "$u.service" 2>/dev/null || true
done

# ---- 3. move directories old -> new -----------------------------------------
move() {
    local src="$1" dst="$2"
    [[ -e "$src" ]] || return 0
    [[ -e "$dst" ]] && { log "SKIP $src -> $dst (target exists)"; return 0; }
    mv "$src" "$dst"
    log "moved $src -> $dst"
}
move /opt/certinel           /opt/certheim
move /etc/certinel           /etc/certheim
move /var/lib/certinel       /var/lib/certheim
move /var/opt/certinel       /var/opt/certheim
move /etc/pki/certinel       /etc/pki/certheim
move /etc/nginx/certinel.d   /etc/nginx/certheim.d
move /etc/nginx/conf.d/certinel.conf /etc/nginx/conf.d/certheim.conf
# helper keeps its old file names inside the moved tree until deploy.sh installs
# the renamed ones; rename now so the new sudoers rule is valid immediately.
if [[ -e /opt/certheim/helper/certinel_helper.sh ]]; then
    mv /opt/certheim/helper/certinel_helper.sh /opt/certheim/helper/certheim_helper.sh
    [[ -d /opt/certheim/helper/certinel_helper.d ]] \
        && mv /opt/certheim/helper/certinel_helper.d /opt/certheim/helper/certheim_helper.d
    log "renamed helper inside /opt/certheim"
fi
[[ -e /etc/certheim/certinel.env ]] && mv /etc/certheim/certinel.env /etc/certheim/certheim.env

# ---- 4. service account (certinel kept until Phase 5) ------------------------
if ! getent group certheim >/dev/null; then groupadd --system certheim; log "group certheim created"; fi
if ! getent passwd certheim >/dev/null; then
    useradd --system --no-create-home --shell /sbin/nologin -g certheim \
            --comment "Certheim service account" certheim
    log "user certheim created"
fi
for tree in /opt/certheim /etc/certheim /var/lib/certheim /var/opt/certheim /etc/pki/certheim; do
    [[ -d "$tree" ]] || continue
    chown -R --from=certinel certheim "$tree" 2>/dev/null || true   # user remap
    chown -R --from=:certinel :certheim "$tree" 2>/dev/null || true # group remap
done
log "ownership remapped certinel -> certheim (certinel account kept until Phase 5)"

# ---- 5. rewrite configs -------------------------------------------------------
ENVF=/etc/certheim/certheim.env
if [[ -f "$ENVF" ]]; then
    cp -p "$ENVF" "${ENVF}.premigrate"
    sed -i -e 's/^CSR_/CERTHEIM_/' -e 's/^CERTINEL_/CERTHEIM_/' \
           -e 's#/opt/certinel#/opt/certheim#g' -e 's#/etc/certinel#/etc/certheim#g' \
           -e 's#/var/lib/certinel#/var/lib/certheim#g' -e 's#/var/opt/certinel#/var/opt/certheim#g' \
           -e 's#certinel_helper#certheim_helper#g' "$ENVF"
    log "env file rewritten (original kept at ${ENVF}.premigrate)"
fi
if [[ -f /etc/certheim/install.conf ]]; then
    sed -i 's/^SERVICE_USER=certinel$/SERVICE_USER=certheim/; s/^SERVICE_GROUP=certinel$/SERVICE_GROUP=certheim/' \
        /etc/certheim/install.conf
fi
# nginx: path references inside the moved configs
for f in /etc/nginx/conf.d/certheim.conf /etc/nginx/certheim.d/*.conf; do
    [[ -f "$f" ]] || continue
    sed -i -e 's#/etc/pki/certinel#/etc/pki/certheim#g' \
           -e 's#/etc/nginx/certinel\.d#/etc/nginx/certheim.d#g' "$f"
done
if command -v nginx >/dev/null 2>&1 && ! nginx -t 2>/dev/null; then
    echo "certheim-migrate: WARNING - nginx -t failed after path rewrite; fix before reload" >&2
fi
# sudoers: new rule, validated, then the old one goes
if [[ -f /etc/sudoers.d/certinel ]]; then
    printf 'certheim ALL=(root) NOPASSWD: /opt/certheim/helper/certheim_helper.sh\n' \
        > /etc/sudoers.d/certheim
    chmod 0440 /etc/sudoers.d/certheim
    if visudo -cf /etc/sudoers.d/certheim >/dev/null; then
        rm -f /etc/sudoers.d/certinel
        log "sudoers migrated"
    else
        rm -f /etc/sudoers.d/certheim
        echo "certheim-migrate: new sudoers failed visudo - kept the old rule" >&2
    fi
fi
# old unit files (deploy.sh installs the certheim-* ones right after)
rm -f /etc/systemd/system/certinel-*.service /etc/systemd/system/certinel-*.timer
log "legacy unit files removed"

# ---- 6. SELinux ---------------------------------------------------------------
if command -v semanage >/dev/null 2>&1; then
    semanage fcontext -d '/opt/certinel(/.*)?'              2>/dev/null || true
    semanage fcontext -d '/opt/certinel/helper(/.*)?'       2>/dev/null || true
    semanage fcontext -d '/var/opt/certinel(/.*)?'          2>/dev/null || true
    semanage fcontext -a -t var_lib_t '/var/opt/certheim(/.*)?'    2>/dev/null || true
    semanage fcontext -a -t bin_t     '/opt/certheim/helper(/.*)?' 2>/dev/null || true
    command -v restorecon >/dev/null 2>&1 && \
        restorecon -RF /opt/certheim /etc/certheim /var/lib/certheim /var/opt/certheim 2>/dev/null || true
    log "SELinux contexts migrated"
fi

# ---- 7. fapolicyd -------------------------------------------------------------
if command -v fapolicyd-cli >/dev/null 2>&1; then
    fapolicyd-cli --file add /opt/certheim/ 2>/dev/null \
        || fapolicyd-cli --file update /opt/certheim/ 2>/dev/null || true
    fapolicyd-cli --file add /opt/certheim/helper/ 2>/dev/null \
        || fapolicyd-cli --file update /opt/certheim/helper/ 2>/dev/null || true
    fapolicyd-cli --update 2>/dev/null || true
    log "fapolicyd trust updated"
fi

systemctl daemon-reload
log "DONE - layout migrated. deploy.sh will now install the certheim-named files and start certheim-api."
