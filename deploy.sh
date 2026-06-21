#!/bin/bash
# deploy.sh - install the certinel repo contents to their live paths.
#
# Usage:
#   ./deploy.sh --diff     show what would change, touch nothing
#   ./deploy.sh            backup, install changed files, fapolicyd, restart
#   ./deploy.sh --no-restart   install but skip the certinel-api restart
#
# Run as root from the repo root on the dashboard host.

set -euo pipefail
cd "$(dirname "$0")"

DIFF_ONLY=false
RESTART=true
for arg in "$@"; do
    case "$arg" in
        --diff) DIFF_ONLY=true ;;
        --no-restart) RESTART=false ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

# Service account the app runs as. online-install.sh records the operator's
# choice in /etc/certinel/install.conf; absent that we default to certinel, so
# existing deployments are unaffected. deploy substitutes it into file ownership
# (the manifest's `:certinel` group) and into the systemd units' User=/Group=.
INSTALL_CONF=/etc/certinel/install.conf
# shellcheck source=/dev/null
[[ -r "$INSTALL_CONF" ]] && . "$INSTALL_CONF"
SERVICE_USER="${SERVICE_USER:-certinel}"
SERVICE_GROUP="${SERVICE_GROUP:-$SERVICE_USER}"

# src | dest | owner:group | mode | tag
MANIFEST=(
  "VERSION                   /opt/certinel/VERSION                        root:certinel 0640 backend"
  "backend/app.py            /opt/certinel/app.py                         root:certinel 0640 backend"
  "backend/notify.py         /opt/certinel/notify.py                      root:certinel 0640 backend"
  "backend/build_mode.py     /opt/certinel/build_mode.py                  root:certinel 0640 backend"
  "backend/capabilities.py   /opt/certinel/capabilities.py                root:certinel 0640 backend"
  "backend/licensing.py      /opt/certinel/licensing.py                   root:certinel 0640 backend"
  "backend/domains.py        /opt/certinel/domains.py                     root:certinel 0640 backend"
  "backend/sign.py           /opt/certinel/sign.py                        root:certinel 0640 backend"
  "backend/deliver.py        /opt/certinel/deliver.py                     root:certinel 0640 backend"
  "backend/keystore.py       /opt/certinel/keystore.py                    root:certinel 0640 backend"
  "backend/renew.py          /opt/certinel/renew.py                       root:certinel 0640 backend"
  "backend/acme_client.py    /opt/certinel/acme_client.py                 root:certinel 0640 backend"
  "backend/acme_dns.py       /opt/certinel/acme_dns.py                    root:certinel 0640 backend"
  "backend/ca_providers.py   /opt/certinel/ca_providers.py                root:certinel 0640 backend"
  "backend/acme_server.py    /opt/certinel/acme_server.py                 root:certinel 0640 backend"
  "backend/routes_acme.py    /opt/certinel/routes_acme.py                 root:certinel 0640 backend"
  "backend/routes_deliver.py /opt/certinel/routes_deliver.py              root:certinel 0640 backend"
  "backend/truststore.py     /opt/certinel/truststore.py                  root:certinel 0640 backend"
  "backend/routes_truststore.py /opt/certinel/routes_truststore.py        root:certinel 0640 backend"
  "backend/csr_subject.py    /opt/certinel/csr_subject.py                 root:certinel 0640 backend"
  "backend/routes_integrations.py /opt/certinel/routes_integrations.py    root:certinel 0640 backend"
  "backend/routes_feedback.py /opt/certinel/routes_feedback.py            root:certinel 0640 backend"
  "backend/routes_auth.py    /opt/certinel/routes_auth.py                 root:certinel 0640 backend"
  "backend/routes_jobs.py    /opt/certinel/routes_jobs.py                 root:certinel 0640 backend"
  "backend/routes_requests.py /opt/certinel/routes_requests.py            root:certinel 0640 backend"
  "backend/routes_groups.py  /opt/certinel/routes_groups.py               root:certinel 0640 backend"
  "backend/routes_me.py      /opt/certinel/routes_me.py                   root:certinel 0640 backend"
  "backend/routes_admin.py   /opt/certinel/routes_admin.py                root:certinel 0640 backend"
  "backend/routes_signing.py /opt/certinel/routes_signing.py              root:certinel 0640 backend"
  "backend/import_certs.py   /opt/certinel/import_certs.py                root:certinel 0640 backend"
  "frontend/index.html       /var/www/csr/index.html                           root:nginx  0640 frontend"
  "frontend/app.css          /var/www/csr/app.css                              root:nginx  0640 frontend"
  "frontend/app.1-core.js    /var/www/csr/app.1-core.js                        root:nginx  0640 frontend"
  "frontend/app.2-jobs.js    /var/www/csr/app.2-jobs.js                        root:nginx  0640 frontend"
  "frontend/app.3-admin.js   /var/www/csr/app.3-admin.js                       root:nginx  0640 frontend"
  "frontend/app.4-misc-boot.js /var/www/csr/app.4-misc-boot.js                 root:nginx  0640 frontend"
  "frontend/app.5-guide.js   /var/www/csr/app.5-guide.js                       root:nginx  0640 frontend"
  "helper/certinel_helper.sh /opt/certinel/helper/certinel_helper.sh root:root 0750 helper"
  "helper/certinel_helper.d/00-common.sh    /opt/certinel/helper/certinel_helper.d/00-common.sh    root:root 0640 helper"
  "helper/certinel_helper.d/10-certtypes.sh /opt/certinel/helper/certinel_helper.d/10-certtypes.sh root:root 0640 helper"
  "helper/certinel_helper.d/20-generate.sh  /opt/certinel/helper/certinel_helper.d/20-generate.sh  root:root 0640 helper"
  "helper/certinel_helper.d/30-truststore.sh /opt/certinel/helper/certinel_helper.d/30-truststore.sh root:root 0640 helper"
  "helper/certinel_helper.d/40-mtls.sh       /opt/certinel/helper/certinel_helper.d/40-mtls.sh       root:root 0640 helper"
  "systemd/certinel-expiry-warn.service /etc/systemd/system/certinel-expiry-warn.service root:root 0644 systemd"
  "systemd/certinel-expiry-warn.timer   /etc/systemd/system/certinel-expiry-warn.timer   root:root 0644 systemd"
  "systemd/certinel-auto-renew.service  /etc/systemd/system/certinel-auto-renew.service  root:root 0644 systemd"
  "systemd/certinel-auto-renew.timer    /etc/systemd/system/certinel-auto-renew.timer    root:root 0644 systemd"
  "systemd/certinel-deliver.service     /etc/systemd/system/certinel-deliver.service     root:root 0644 systemd"
  "systemd/certinel-deliver.timer       /etc/systemd/system/certinel-deliver.timer       root:root 0644 systemd"
  "systemd/certinel-api.service          /etc/systemd/system/certinel-api.service          root:root 0644 systemd"
  "systemd/certinel-doctor.service       /etc/systemd/system/certinel-doctor.service       root:root 0644 systemd"
  "systemd/certinel-doctor.timer         /etc/systemd/system/certinel-doctor.timer         root:root 0644 systemd"
  "tools/certinel-backup.sh        /usr/local/sbin/certinel-backup                         root:root 0750 tools"
  "tools/certinel-bootstrap-admin /usr/local/sbin/certinel-bootstrap-admin               root:root 0750 tools"
  "tools/certinel-uninstall.sh    /usr/local/sbin/certinel-uninstall                      root:root 0750 tools"
  "tools/certinel-set-auth        /usr/local/sbin/certinel-set-auth                       root:root 0750 tools"
  "tools/certinel-doctor.sh       /usr/local/sbin/certinel-doctor                         root:root 0750 tools"
  "tools/certinel-doctor-alert.sh /usr/local/sbin/certinel-doctor-alert                   root:root 0750 tools"
  "tools/openbao-fetch.sh         /usr/local/sbin/openbao-fetch                           root:root 0755 tools"
)
# nginx include: uncomment and fix the filename once it's in the repo
MANIFEST+=("nginx/30-csr.conf /etc/nginx/certinel.d/30-csr.conf root:root 0644 nginx")

changed_tags=""

for entry in "${MANIFEST[@]}"; do
    read -r src dest og mode tag <<< "$entry"
    if [[ ! -f "$src" ]]; then
        echo "MISSING in repo: $src" >&2
        exit 1
    fi
    # Parameterize the service account: the manifest carries the default group
    # `certinel`; swap it for the configured group, and render the chosen
    # User=/Group= into the systemd units. With the certinel default all of this is
    # a no-op (rendered output is byte-identical to the repo file).
    og="${og//certinel/$SERVICE_GROUP}"
    render="$src"; tmp=""
    if [[ "$tag" == systemd && "$dest" == *.service ]]; then
        tmp="$(mktemp)"
        sed "s/^User=certinel\$/User=$SERVICE_USER/; s/^Group=certinel\$/Group=$SERVICE_GROUP/" \
            "$src" > "$tmp"
        render="$tmp"
    fi
    if [[ -f "$dest" ]] && cmp -s "$render" "$dest"; then
        [[ -n "$tmp" ]] && rm -f "$tmp"
        continue
    fi
    if $DIFF_ONLY; then
        echo "=== would update: $dest ==="
        diff -u "$dest" "$render" 2>/dev/null | head -40 || echo "  (new file)"
        [[ -n "$tmp" ]] && rm -f "$tmp"
        continue
    fi
    install -o "${og%%:*}" -g "${og##*:}" -m "$mode" -D "$render" "$dest"
    echo "installed: $dest (${og} ${mode})"
    changed_tags+=" $tag"
    [[ -n "$tmp" ]] && rm -f "$tmp"
done

# Stamp the DEPLOYED build_mode.py as a hardened release build so the insecure
# dev-only env overrides (CSR_ENTITLEMENTS=*, CSR_LICENSE_PUBKEY) are inert on
# an installed instance - regardless of what environment is later set. The repo
# copy stays RELEASE_BUILD=False so source checkouts and tests run in dev mode.
# Set CERTINEL_DEV_DEPLOY=1 to deploy an evaluation box that keeps the overrides
# (e.g. to demo premium features without installing a license).
if ! $DIFF_ONLY && [[ -f /opt/certinel/build_mode.py && "${CERTINEL_DEV_DEPLOY:-0}" != "1" ]]; then
    sed -i 's/^RELEASE_BUILD = False/RELEASE_BUILD = True/' /opt/certinel/build_mode.py
    echo "stamped: /opt/certinel/build_mode.py -> release build (dev overrides disabled)"
fi

$DIFF_ONLY && exit 0

if [[ -z "$changed_tags" ]]; then
    echo "nothing to deploy - live files match the repo"
    exit 0
fi

# Seed the per-deployment env file from the example if it does not exist yet.
# The live env file is operator-managed (like email.conf) and is never
# overwritten by deploy - edit /etc/certinel/certinel.env directly.
if [[ ! -f /etc/certinel/certinel.env && -f config/certinel.env.example ]]; then
    install -d -o root -g "$SERVICE_GROUP" -m 0750 /etc/certinel
    install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0640 \
        config/certinel.env.example /etc/certinel/certinel.env
    echo "seeded /etc/certinel/certinel.env from example - review it"
fi
if [[ ! -f /etc/certinel/doctor-alert.conf && -f config/doctor-alert.conf.example ]]; then
    install -o root -g root -m 0600 \
        config/doctor-alert.conf.example /etc/certinel/doctor-alert.conf
    echo "seeded /etc/certinel/doctor-alert.conf (blank - add Mailgun creds to enable email alerts)"
fi
if [[ ! -f /etc/certinel/email.conf && -f config/email.conf.example ]]; then
    install -d -o root -g "$SERVICE_GROUP" -m 0750 /etc/certinel
    install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0640 \
        config/email.conf.example /etc/certinel/email.conf
    echo "seeded /etc/certinel/email.conf from example - set the SMG host"
fi

# Certinel data root (FHS /var/opt for add-on app data). issued/ holds signed
# certs (written by the app as certinel + chowned by the helper); requests/ holds
# generated CSRs (written by the helper as root). var_lib_t lets the confined
# certinel-api service write here, matching the DB dir's context.
install -d -o root              -g root            -m 0755 /var/opt/certinel
install -d -o "$SERVICE_USER"   -g "$SERVICE_GROUP" -m 0750 /var/opt/certinel/issued
install -d -o root              -g "$SERVICE_GROUP" -m 0750 /var/opt/certinel/requests
# Helper lives under /opt (Phase 4b, off /root) so the sandbox can mask /root;
# KEYDIR is a brief 0700 scratch for key generation (keys then go to the vault).
# WorkingDirectory of the service: the account must traverse it (CHDIR), so it
# is group-owned by the service group (0750), not root:root (which left the
# account unable to enter -> systemd status=200/CHDIR "Permission denied").
install -d -o root -g "$SERVICE_GROUP" -m 0750 /opt/certinel
install -d -o root -g root -m 0750 /opt/certinel/helper
install -d -o root -g root -m 0700 /var/opt/certinel/private
if command -v semanage >/dev/null 2>&1; then
    # /opt/certinel holds the APP (code + venv) and MUST stay executable by
    # systemd, so leave it at the /opt default (usr_t/bin_t). A prior release
    # wrongly labelled it var_lib_t (that type is for the writable data root);
    # once the app moved into /opt/certinel the venv became unexecutable and the
    # service died with 203/EXEC ("Permission denied" on gunicorn). Purge that
    # stale rule on upgrade so the app dir relabels back to an exec-able type.
    semanage fcontext -d '/opt/certinel(/.*)?'                  2>/dev/null || true
    # Only the writable data root is service state -> var_lib_t.
    semanage fcontext -a -t var_lib_t '/var/opt/certinel(/.*)?' 2>/dev/null || true
    # The helper is exec'd as root via sudo: a more-specific bin_t rule.
    semanage fcontext -a -t bin_t     '/opt/certinel/helper(/.*)?' 2>/dev/null || true
    command -v restorecon >/dev/null 2>&1 && {
        restorecon -RF /var/opt/certinel /opt/certinel 2>/dev/null || true; }
fi
# fapolicyd must trust the relocated helper (exec + sourced parts).
if [[ "$changed_tags" == *helper* ]] && command -v fapolicyd-cli >/dev/null 2>&1; then
    # 'add' on a fresh box, 'update' when the entry already exists (re-deploy).
    # '--file update' alone errors with "not in the trust database" on install.
    fapolicyd-cli --file add /opt/certinel/helper/ 2>/dev/null \
        || fapolicyd-cli --file update /opt/certinel/helper/ 2>/dev/null || true
    fapolicyd-cli --update || true
fi

# Pre-deploy DB/file backup (after diffing, before service restart)
command -v certinel-backup >/dev/null && certinel-backup || echo "WARN: certinel-backup not found"

if [[ "$changed_tags" == *frontend* ]]; then
    restorecon -Rv /var/www/csr/ || true
fi
if [[ "$changed_tags" == *backend* ]]; then
    fapolicyd-cli --file add /opt/certinel/ 2>/dev/null \
        || fapolicyd-cli --file update /opt/certinel/ 2>/dev/null || true
    fapolicyd-cli --update || true
fi
if [[ "$changed_tags" == *systemd* ]]; then
    # One-time migration: retire the legacy csr-* unit names (renamed to
    # certinel-*). Stop + disable + remove them so the old csr-api releases
    # 127.0.0.1:5002 before certinel-api binds, and the old timers stop firing.
    # Idempotent: no-ops once the legacy files are gone. NOTE: csr-slack-listener
    # is intentionally excluded - it's an opt-in Socket-Mode service installed
    # manually (not in MANIFEST), so deploy must not retire it without a
    # replacement; swap it by hand when reconfiguring Slack Socket Mode.
    for legacy in csr-api csr-expiry-warn csr-auto-renew csr-deliver; do
        if [[ -f "/etc/systemd/system/$legacy.service" || -f "/etc/systemd/system/$legacy.timer" ]]; then
            systemctl disable --now "$legacy.timer" "$legacy.service" 2>/dev/null || true
            rm -f "/etc/systemd/system/$legacy.service" "/etc/systemd/system/$legacy.timer"
            echo "retired legacy unit: $legacy"
        fi
    done
    # Validate every installed unit BEFORE reloading - a malformed unit must
    # not reach a restart (a bad ExecStart line once left the service unable
    # to restart). Same fail-loud gate as nginx -t below.
    for unit in /etc/systemd/system/certinel-api.service \
                /etc/systemd/system/certinel-expiry-warn.service \
                /etc/systemd/system/certinel-expiry-warn.timer \
                /etc/systemd/system/certinel-auto-renew.service \
                /etc/systemd/system/certinel-auto-renew.timer \
                /etc/systemd/system/certinel-deliver.service \
                /etc/systemd/system/certinel-deliver.timer; do
        [[ -f "$unit" ]] || continue
        if ! systemd-analyze verify "$unit" 2>&1; then
            echo "systemd unit FAILED validation: $unit" >&2
            echo "the file is installed but daemon-reload/restart was skipped." >&2
            echo "fix it and re-run deploy, or correct $unit directly." >&2
            exit 1
        fi
    done
    systemctl daemon-reload
    # Enable the periodic timers (idempotent). The .service units are oneshot,
    # triggered by their timers; we enable the timers, not the services.
    systemctl enable --now certinel-expiry-warn.timer certinel-auto-renew.timer certinel-deliver.timer certinel-doctor.timer 2>/dev/null || true
fi
if [[ "$changed_tags" == *nginx* ]]; then
    # Validate before (re)loading - a bad config must not take nginx down.
    if nginx -t; then
        # reload-or-restart: on a fresh box nginx may be installed-but-stopped,
        # in which case `reload` fails. reload-or-restart starts it if down and
        # reloads if up - so first install and steady-state both work (F9).
        systemctl reload-or-restart nginx
        echo "nginx: reload-or-restart ok"
    else
        echo "nginx -t FAILED - config NOT (re)loaded; the new file is on disk" >&2
        echo "fix it and run: nginx -t && systemctl reload-or-restart nginx" >&2
        echo "(on first install also ensure nginx.conf includes certinel.d/*.conf" >&2
        echo " and that nginx is enabled - see OFFLINE-INSTALL.md)" >&2
        exit 1
    fi
fi
if $RESTART && [[ "$changed_tags" == *backend* || "$changed_tags" == *systemd* ]]; then
    systemctl restart certinel-api
    sleep 1
    if ! systemctl is-active certinel-api >/dev/null; then
        echo "certinel-api FAILED to start - check journalctl -u certinel-api" >&2
        exit 1
    fi
    echo "certinel-api: active (restarted)"

    # Verify the running app reports the deployed VERSION. app.py reads VERSION
    # once at startup, so a stale process is the classic "UI shows old version"
    # bug. This makes the mismatch loud instead of silent.
    if [[ -f /opt/certinel/VERSION ]]; then
        want="$(cat /opt/certinel/VERSION 2>/dev/null)"
        # give gunicorn a moment, then ask the unauth health endpoint
        got=""
        for _ in 1 2 3; do
            got="$(curl -sk https://127.0.0.1/csr/api/health 2>/dev/null \
                   | sed -n 's/.*"version"[: ]*"\([^"]*\)".*/\1/p')"
            [[ -n "$got" ]] && break
            sleep 1
        done
        if [[ -n "$got" && "$got" != "$want" ]]; then
            echo "WARN: running version ($got) != deployed VERSION ($want)." >&2
            echo "      The service may not have fully reloaded; try:" >&2
            echo "      systemctl restart certinel-api" >&2
        elif [[ "$got" == "$want" ]]; then
            echo "certinel-api: serving v$got"
        fi
        # (empty $got just means health wasn't reachable over loopback TLS here;
        #  not fatal - mTLS/cert setup can make local curl fail. Skip silently.)
    fi
fi

echo "deploy complete:$changed_tags"
