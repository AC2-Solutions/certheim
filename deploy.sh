#!/bin/bash
# deploy.sh - install the certheim repo contents to their live paths.
#
# Usage:
#   ./deploy.sh --diff     show what would change, touch nothing
#   ./deploy.sh            backup, install changed files, fapolicyd, restart
#   ./deploy.sh --no-restart   install but skip the certheim-api restart
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

# certinel->certheim rename (Phase 2): a pre-5.2 install still has the legacy
# layout. Migrate it in place (backup, stop, move, remap, relabel, re-trust)
# before deploying — tools/certheim-migrate.sh is idempotent and refuses
# ambiguous states. Never run during --diff (read-only preview).
if ! $DIFF_ONLY && [[ -e /opt/certinel || -e /etc/certinel ]] && [[ ! -e /opt/certheim ]]; then
    echo "legacy certinel layout detected - migrating (tools/certheim-migrate.sh)"
    bash tools/certheim-migrate.sh || { echo "layout migration FAILED - deploy aborted (see backup in /root)" >&2; exit 1; }
fi

# Service account the app runs as. online-install.sh records the operator's
# choice in /etc/certheim/install.conf; absent that we default to certheim, so
# existing deployments are unaffected. deploy substitutes it into file ownership
# (the manifest's `:certheim` group) and into the systemd units' User=/Group=.
INSTALL_CONF=/etc/certheim/install.conf
# shellcheck source=/dev/null
[[ -r "$INSTALL_CONF" ]] && . "$INSTALL_CONF"
SERVICE_USER="${SERVICE_USER:-certheim}"
SERVICE_GROUP="${SERVICE_GROUP:-$SERVICE_USER}"

# Materialize the running edition's version into root VERSION (the file the app
# reads and this manifest deploys). Each edition keeps its own number in
# editions/<edition>.version so the three branches never collide on a shared
# VERSION during propagation; here we resolve it to this build's actual edition.
DEPLOY_EDITION="$(python3 -c 'import sys; sys.path.insert(0,"backend"); import build_mode; print(build_mode.EDITION)' 2>/dev/null || echo community)"
if [[ -f "editions/${DEPLOY_EDITION}.version" ]]; then
    cp -f "editions/${DEPLOY_EDITION}.version" VERSION
fi

# src | dest | owner:group | mode | tag
MANIFEST=(
  "VERSION                   /opt/certheim/VERSION                        root:certheim 0640 backend"
  "backend/app.py            /opt/certheim/app.py                         root:certheim 0640 backend"
  "backend/notify.py         /opt/certheim/notify.py                      root:certheim 0640 backend"
  "backend/build_mode.py     /opt/certheim/build_mode.py                  root:certheim 0640 backend"
  "backend/envcompat.py      /opt/certheim/envcompat.py                   root:certheim 0640 backend"
  "backend/capabilities.py   /opt/certheim/capabilities.py                root:certheim 0640 backend"
  "backend/db.py             /opt/certheim/db.py                          root:certheim 0640 backend"
  "backend/db_migrate.py     /opt/certheim/db_migrate.py                  root:certheim 0640 backend"
  "backend/licensing.py      /opt/certheim/licensing.py                   root:certheim 0640 backend"
  "backend/domains.py        /opt/certheim/domains.py                     root:certheim 0640 backend"
  "backend/sign.py           /opt/certheim/sign.py                        root:certheim 0640 backend"
  "backend/keystore.py       /opt/certheim/keystore.py                    root:certheim 0640 backend"
  "backend/truststore.py     /opt/certheim/truststore.py                  root:certheim 0640 backend"
  "backend/routes_truststore.py /opt/certheim/routes_truststore.py        root:certheim 0640 backend"
  "backend/csr_subject.py    /opt/certheim/csr_subject.py                 root:certheim 0640 backend"
  "backend/routes_integrations.py /opt/certheim/routes_integrations.py    root:certheim 0640 backend"
  "backend/routes_feedback.py /opt/certheim/routes_feedback.py            root:certheim 0640 backend"
  "backend/routes_auth.py    /opt/certheim/routes_auth.py                 root:certheim 0640 backend"
  "backend/routes_jobs.py    /opt/certheim/routes_jobs.py                 root:certheim 0640 backend"
  "backend/routes_requests.py /opt/certheim/routes_requests.py            root:certheim 0640 backend"
  "backend/routes_groups.py  /opt/certheim/routes_groups.py               root:certheim 0640 backend"
  "backend/routes_me.py      /opt/certheim/routes_me.py                   root:certheim 0640 backend"
  "backend/routes_admin.py   /opt/certheim/routes_admin.py                root:certheim 0640 backend"
  "backend/routes_signing.py /opt/certheim/routes_signing.py              root:certheim 0640 backend"
  "backend/import_certs.py   /opt/certheim/import_certs.py                root:certheim 0640 backend"
  "frontend/index.html       /var/www/csr/index.html                           root:nginx  0640 frontend"
  "frontend/app.css          /var/www/csr/app.css                              root:nginx  0640 frontend"
  "frontend/app.1-core.js    /var/www/csr/app.1-core.js                        root:nginx  0640 frontend"
  "frontend/app.2-jobs.js    /var/www/csr/app.2-jobs.js                        root:nginx  0640 frontend"
  "frontend/app.3-admin.js   /var/www/csr/app.3-admin.js                       root:nginx  0640 frontend"
  "frontend/app.4-misc-boot.js /var/www/csr/app.4-misc-boot.js                 root:nginx  0640 frontend"
  "frontend/app.5-guide.js   /var/www/csr/app.5-guide.js                       root:nginx  0640 frontend"
  "frontend/setup-guide.html /var/www/csr/setup-guide.html                     root:nginx  0640 frontend"
  "helper/certheim_helper.sh /opt/certheim/helper/certheim_helper.sh root:root 0750 helper"
  "helper/certheim_helper.d/00-common.sh    /opt/certheim/helper/certheim_helper.d/00-common.sh    root:root 0640 helper"
  "helper/certheim_helper.d/10-certtypes.sh /opt/certheim/helper/certheim_helper.d/10-certtypes.sh root:root 0640 helper"
  "helper/certheim_helper.d/20-generate.sh  /opt/certheim/helper/certheim_helper.d/20-generate.sh  root:root 0640 helper"
  "helper/certheim_helper.d/30-truststore.sh /opt/certheim/helper/certheim_helper.d/30-truststore.sh root:root 0640 helper"
  "helper/certheim_helper.d/40-mtls.sh       /opt/certheim/helper/certheim_helper.d/40-mtls.sh       root:root 0640 helper"
  "systemd/certheim-expiry-warn.service /etc/systemd/system/certheim-expiry-warn.service root:root 0644 systemd"
  "systemd/certheim-expiry-warn.timer   /etc/systemd/system/certheim-expiry-warn.timer   root:root 0644 systemd"
  "systemd/certheim-auto-renew.service  /etc/systemd/system/certheim-auto-renew.service  root:root 0644 systemd"
  "systemd/certheim-auto-renew.timer    /etc/systemd/system/certheim-auto-renew.timer    root:root 0644 systemd"
  "systemd/certheim-deliver.service     /etc/systemd/system/certheim-deliver.service     root:root 0644 systemd"
  "systemd/certheim-deliver.timer       /etc/systemd/system/certheim-deliver.timer       root:root 0644 systemd"
  "systemd/certheim-api.service          /etc/systemd/system/certheim-api.service          root:root 0644 systemd"
  "systemd/certheim-doctor.service       /etc/systemd/system/certheim-doctor.service       root:root 0644 systemd"
  "systemd/certheim-doctor.timer         /etc/systemd/system/certheim-doctor.timer         root:root 0644 systemd"
  "tools/certheim-backup.sh        /usr/local/sbin/certheim-backup                         root:root 0750 tools"
  "tools/certheim-bootstrap-admin /usr/local/sbin/certheim-bootstrap-admin               root:root 0750 tools"
  "tools/certheim-db-migrate      /usr/local/sbin/certheim-db-migrate                    root:root 0750 tools"
  "tools/certheim-uninstall.sh    /usr/local/sbin/certheim-uninstall                      root:root 0750 tools"
  "tools/certheim-migrate.sh      /usr/local/sbin/certheim-migrate                        root:root 0750 tools"
  "tools/certheim-set-auth        /usr/local/sbin/certheim-set-auth                       root:root 0750 tools"
  "tools/certheim-doctor.sh       /usr/local/sbin/certheim-doctor                         root:root 0750 tools"
  "tools/certheim-doctor-alert.sh /usr/local/sbin/certheim-doctor-alert                   root:root 0750 tools"
  "tools/openbao-fetch.sh         /usr/local/sbin/openbao-fetch                           root:root 0755 tools"
)
# nginx include: uncomment and fix the filename once it's in the repo
MANIFEST+=("nginx/30-csr.conf /etc/nginx/certheim.d/30-csr.conf root:root 0644 nginx")

changed_tags=""

for entry in "${MANIFEST[@]}"; do
    read -r src dest og mode tag <<< "$entry"
    if [[ ! -f "$src" ]]; then
        echo "MISSING in repo: $src" >&2
        exit 1
    fi
    # Parameterize the service account: the manifest carries the default group
    # `certheim`; swap it for the configured group, and render the chosen
    # User=/Group= into the systemd units. With the certheim default all of this is
    # a no-op (rendered output is byte-identical to the repo file).
    og="${og//certheim/$SERVICE_GROUP}"
    render="$src"; tmp=""
    if [[ "$tag" == systemd && "$dest" == *.service ]]; then
        tmp="$(mktemp)"
        sed "s/^User=certheim\$/User=$SERVICE_USER/; s/^Group=certheim\$/Group=$SERVICE_GROUP/" \
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
# dev-only env overrides (CERTHEIM_ENTITLEMENTS=*, CERTHEIM_LICENSE_PUBKEY) are inert on
# an installed instance - regardless of what environment is later set. The repo
# copy stays RELEASE_BUILD=False so source checkouts and tests run in dev mode.
# Set CERTHEIM_DEV_DEPLOY=1 to deploy an evaluation box that keeps the overrides
# (e.g. to demo premium features without installing a license).
if ! $DIFF_ONLY && [[ -f /opt/certheim/build_mode.py && "${CERTHEIM_DEV_DEPLOY:-0}" != "1" ]]; then
    sed -i 's/^RELEASE_BUILD = False/RELEASE_BUILD = True/' /opt/certheim/build_mode.py
    echo "stamped: /opt/certheim/build_mode.py -> release build (dev overrides disabled)"
fi

$DIFF_ONLY && exit 0

if [[ -z "$changed_tags" ]]; then
    echo "nothing to deploy - live files match the repo"
    exit 0
fi

# Seed the per-deployment env file from the example if it does not exist yet.
# The live env file is operator-managed (like email.conf) and is never
# overwritten by deploy - edit /etc/certheim/certheim.env directly.
if [[ ! -f /etc/certheim/certheim.env && -f config/certheim.env.example ]]; then
    install -d -o root -g "$SERVICE_GROUP" -m 0750 /etc/certheim
    install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0640 \
        config/certheim.env.example /etc/certheim/certheim.env
    echo "seeded /etc/certheim/certheim.env from example - review it"
fi
if [[ ! -f /etc/certheim/doctor-alert.conf && -f config/doctor-alert.conf.example ]]; then
    install -o root -g root -m 0600 \
        config/doctor-alert.conf.example /etc/certheim/doctor-alert.conf
    echo "seeded /etc/certheim/doctor-alert.conf (blank - add Mailgun creds to enable email alerts)"
fi
if [[ ! -f /etc/certheim/email.conf && -f config/email.conf.example ]]; then
    install -d -o root -g "$SERVICE_GROUP" -m 0750 /etc/certheim
    install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0640 \
        config/email.conf.example /etc/certheim/email.conf
    echo "seeded /etc/certheim/email.conf from example - set the SMG host"
fi

# Certheim data root (FHS /var/opt for add-on app data). issued/ holds signed
# certs (written by the app as certheim + chowned by the helper); requests/ holds
# generated CSRs (written by the helper as root). var_lib_t lets the confined
# certheim-api service write here, matching the DB dir's context.
install -d -o root              -g root            -m 0755 /var/opt/certheim
install -d -o "$SERVICE_USER"   -g "$SERVICE_GROUP" -m 0750 /var/opt/certheim/issued
install -d -o root              -g "$SERVICE_GROUP" -m 0750 /var/opt/certheim/requests
# Helper lives under /opt (Phase 4b, off /root) so the sandbox can mask /root;
# KEYDIR is a brief 0700 scratch for key generation (keys then go to the vault).
# WorkingDirectory of the service: the account must traverse it (CHDIR), so it
# is group-owned by the service group (0750), not root:root (which left the
# account unable to enter -> systemd status=200/CHDIR "Permission denied").
install -d -o root -g "$SERVICE_GROUP" -m 0750 /opt/certheim
install -d -o root -g root -m 0750 /opt/certheim/helper
install -d -o root -g root -m 0700 /var/opt/certheim/private
if command -v semanage >/dev/null 2>&1; then
    # /opt/certheim holds the APP (code + venv) and MUST stay executable by
    # systemd, so leave it at the /opt default (usr_t/bin_t). A prior release
    # wrongly labelled it var_lib_t (that type is for the writable data root);
    # once the app moved into /opt/certheim the venv became unexecutable and the
    # service died with 203/EXEC ("Permission denied" on gunicorn). Purge that
    # stale rule on upgrade so the app dir relabels back to an exec-able type.
    semanage fcontext -d '/opt/certheim(/.*)?'                  2>/dev/null || true
    # Only the writable data root is service state -> var_lib_t.
    semanage fcontext -a -t var_lib_t '/var/opt/certheim(/.*)?' 2>/dev/null || true
    # The helper is exec'd as root via sudo: a more-specific bin_t rule.
    semanage fcontext -a -t bin_t     '/opt/certheim/helper(/.*)?' 2>/dev/null || true
    command -v restorecon >/dev/null 2>&1 && {
        restorecon -RF /var/opt/certheim /opt/certheim 2>/dev/null || true; }
fi
# fapolicyd must trust the relocated helper (exec + sourced parts).
if [[ "$changed_tags" == *helper* ]] && command -v fapolicyd-cli >/dev/null 2>&1; then
    # 'add' on a fresh box, 'update' when the entry already exists (re-deploy).
    # '--file update' alone errors with "not in the trust database" on install.
    fapolicyd-cli --file add /opt/certheim/helper/ 2>/dev/null \
        || fapolicyd-cli --file update /opt/certheim/helper/ 2>/dev/null || true
    fapolicyd-cli --update || true
fi

# Pre-deploy DB/file backup (after diffing, before service restart)
command -v certheim-backup >/dev/null && certheim-backup || echo "WARN: certheim-backup not found"

if [[ "$changed_tags" == *frontend* ]]; then
    restorecon -Rv /var/www/csr/ || true
    # Cache-bust: stamp a content hash onto the JS/CSS refs in the SERVED
    # index.html, so browsers fetch fresh assets after every frontend change
    # (the files have no version query, so an un-stamped change is invisible
    # until a hard refresh). Source index.html keeps bare refs; only the
    # deployed copy is stamped, recomputed each deploy.
    if [[ -f /var/www/csr/index.html ]]; then
        _stamp="$(cat frontend/app.*.js frontend/app.css 2>/dev/null | sha256sum | cut -c1-10)"
        sed -i -E "s#(href=\"app\.css)(\?v=[0-9a-f]+)?\"#\1?v=${_stamp}\"#; \
                   s#(src=\"app\.[0-9][^\"?]*\.js)(\?v=[0-9a-f]+)?\"#\1?v=${_stamp}\"#g" \
            /var/www/csr/index.html
        echo "  cache-bust: stamped assets ?v=${_stamp}"
    fi
fi
if [[ "$changed_tags" == *backend* ]]; then
    fapolicyd-cli --file add /opt/certheim/ 2>/dev/null \
        || fapolicyd-cli --file update /opt/certheim/ 2>/dev/null || true
    fapolicyd-cli --update || true
fi
if [[ "$changed_tags" == *systemd* ]]; then
    # One-time migration: retire the legacy csr-* unit names (renamed to
    # certheim-*). Stop + disable + remove them so the old csr-api releases
    # 127.0.0.1:5002 before certheim-api binds, and the old timers stop firing.
    # Idempotent: no-ops once the legacy files are gone. NOTE: csr-slack-listener
    # is intentionally excluded - it's an opt-in Socket-Mode service installed
    # manually (not in MANIFEST), so deploy must not retire it without a
    # replacement; swap it by hand when reconfiguring Slack Socket Mode.
    for legacy in csr-api csr-expiry-warn csr-auto-renew csr-deliver certinel-api certinel-expiry-warn certinel-auto-renew certinel-deliver certinel-doctor certinel-tls-renew; do
        if [[ -f "/etc/systemd/system/$legacy.service" || -f "/etc/systemd/system/$legacy.timer" ]]; then
            systemctl disable --now "$legacy.timer" "$legacy.service" 2>/dev/null || true
            rm -f "/etc/systemd/system/$legacy.service" "/etc/systemd/system/$legacy.timer"
            echo "retired legacy unit: $legacy"
        fi
    done
    # Validate every installed unit BEFORE reloading - a malformed unit must
    # not reach a restart (a bad ExecStart line once left the service unable
    # to restart). Same fail-loud gate as nginx -t below.
    for unit in /etc/systemd/system/certheim-api.service \
                /etc/systemd/system/certheim-expiry-warn.service \
                /etc/systemd/system/certheim-expiry-warn.timer \
                /etc/systemd/system/certheim-auto-renew.service \
                /etc/systemd/system/certheim-auto-renew.timer \
                /etc/systemd/system/certheim-deliver.service \
                /etc/systemd/system/certheim-deliver.timer; do
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
    systemctl enable --now certheim-expiry-warn.timer certheim-auto-renew.timer certheim-deliver.timer certheim-doctor.timer 2>/dev/null || true
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
        echo "(on first install also ensure nginx.conf includes certheim.d/*.conf" >&2
        echo " and that nginx is enabled - see OFFLINE-INSTALL.md)" >&2
        exit 1
    fi
fi
if $RESTART && [[ "$changed_tags" == *backend* || "$changed_tags" == *systemd* ]]; then
    systemctl restart certheim-api
    sleep 1
    if ! systemctl is-active certheim-api >/dev/null; then
        echo "certheim-api FAILED to start - check journalctl -u certheim-api" >&2
        exit 1
    fi
    echo "certheim-api: active (restarted)"

    # Verify the running app reports the deployed VERSION. app.py reads VERSION
    # once at startup, so a stale process is the classic "UI shows old version"
    # bug. This makes the mismatch loud instead of silent.
    if [[ -f /opt/certheim/VERSION ]]; then
        want="$(cat /opt/certheim/VERSION 2>/dev/null)"
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
            echo "      systemctl restart certheim-api" >&2
        elif [[ "$got" == "$want" ]]; then
            echo "certheim-api: serving v$got"
        fi
        # (empty $got just means health wasn't reachable over loopback TLS here;
        #  not fatal - mTLS/cert setup can make local curl fail. Skip silently.)
    fi
fi

echo "deploy complete:$changed_tags"
