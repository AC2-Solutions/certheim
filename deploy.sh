#!/bin/bash
# deploy.sh - install the csr-dashboard repo contents to their live paths.
#
# Usage:
#   ./deploy.sh --diff     show what would change, touch nothing
#   ./deploy.sh            backup, install changed files, fapolicyd, restart
#   ./deploy.sh --no-restart   install but skip the csr-api restart
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

# src | dest | owner:group | mode | tag
MANIFEST=(
  "VERSION                   /opt/csr-dashboard/VERSION                        root:csrapi 0640 backend"
  "backend/app.py            /opt/csr-dashboard/app.py                         root:csrapi 0640 backend"
  "backend/notify.py         /opt/csr-dashboard/notify.py                      root:csrapi 0640 backend"
  "backend/capabilities.py   /opt/csr-dashboard/capabilities.py                root:csrapi 0640 backend"
  "backend/licensing.py      /opt/csr-dashboard/licensing.py                   root:csrapi 0640 backend"
  "backend/sign.py           /opt/csr-dashboard/sign.py                        root:csrapi 0640 backend"
  "backend/deliver.py        /opt/csr-dashboard/deliver.py                     root:csrapi 0640 backend"
  "backend/renew.py          /opt/csr-dashboard/renew.py                       root:csrapi 0640 backend"
  "backend/acme_client.py    /opt/csr-dashboard/acme_client.py                 root:csrapi 0640 backend"
  "backend/acme_dns.py       /opt/csr-dashboard/acme_dns.py                    root:csrapi 0640 backend"
  "backend/ca_providers.py   /opt/csr-dashboard/ca_providers.py                root:csrapi 0640 backend"
  "backend/acme_server.py    /opt/csr-dashboard/acme_server.py                 root:csrapi 0640 backend"
  "backend/routes_acme.py    /opt/csr-dashboard/routes_acme.py                 root:csrapi 0640 backend"
  "backend/routes_deliver.py /opt/csr-dashboard/routes_deliver.py              root:csrapi 0640 backend"
  "backend/csr_subject.py    /opt/csr-dashboard/csr_subject.py                 root:csrapi 0640 backend"
  "backend/routes_integrations.py /opt/csr-dashboard/routes_integrations.py    root:csrapi 0640 backend"
  "backend/routes_feedback.py /opt/csr-dashboard/routes_feedback.py            root:csrapi 0640 backend"
  "backend/routes_auth.py    /opt/csr-dashboard/routes_auth.py                 root:csrapi 0640 backend"
  "backend/routes_jobs.py    /opt/csr-dashboard/routes_jobs.py                 root:csrapi 0640 backend"
  "backend/routes_requests.py /opt/csr-dashboard/routes_requests.py            root:csrapi 0640 backend"
  "backend/routes_groups.py  /opt/csr-dashboard/routes_groups.py               root:csrapi 0640 backend"
  "backend/routes_me.py      /opt/csr-dashboard/routes_me.py                   root:csrapi 0640 backend"
  "backend/routes_admin.py   /opt/csr-dashboard/routes_admin.py                root:csrapi 0640 backend"
  "backend/routes_signing.py /opt/csr-dashboard/routes_signing.py              root:csrapi 0640 backend"
  "backend/import_certs.py   /opt/csr-dashboard/import_certs.py                root:csrapi 0640 backend"
  "frontend/index.html       /var/www/csr/index.html                           root:nginx  0640 frontend"
  "frontend/app.css          /var/www/csr/app.css                              root:nginx  0640 frontend"
  "frontend/app.1-core.js    /var/www/csr/app.1-core.js                        root:nginx  0640 frontend"
  "frontend/app.2-jobs.js    /var/www/csr/app.2-jobs.js                        root:nginx  0640 frontend"
  "frontend/app.3-admin.js   /var/www/csr/app.3-admin.js                       root:nginx  0640 frontend"
  "frontend/app.4-misc-boot.js /var/www/csr/app.4-misc-boot.js                 root:nginx  0640 frontend"
  "frontend/app.5-guide.js   /var/www/csr/app.5-guide.js                       root:nginx  0640 frontend"
  "helper/csr_dashboard_helper.sh /root/sslcerts/scripts/csr_dashboard_helper.sh root:root 0750 helper"
  "helper/csr_dashboard_helper.d/00-common.sh    /root/sslcerts/scripts/csr_dashboard_helper.d/00-common.sh    root:root 0640 helper"
  "helper/csr_dashboard_helper.d/10-certtypes.sh /root/sslcerts/scripts/csr_dashboard_helper.d/10-certtypes.sh root:root 0640 helper"
  "helper/csr_dashboard_helper.d/20-generate.sh  /root/sslcerts/scripts/csr_dashboard_helper.d/20-generate.sh  root:root 0640 helper"
  "systemd/csr-expiry-warn.service /etc/systemd/system/csr-expiry-warn.service root:root 0644 systemd"
  "systemd/csr-expiry-warn.timer   /etc/systemd/system/csr-expiry-warn.timer   root:root 0644 systemd"
  "systemd/csr-auto-renew.service  /etc/systemd/system/csr-auto-renew.service  root:root 0644 systemd"
  "systemd/csr-auto-renew.timer    /etc/systemd/system/csr-auto-renew.timer    root:root 0644 systemd"
  "systemd/csr-deliver.service     /etc/systemd/system/csr-deliver.service     root:root 0644 systemd"
  "systemd/csr-deliver.timer       /etc/systemd/system/csr-deliver.timer       root:root 0644 systemd"
  "systemd/csr-api.service          /etc/systemd/system/csr-api.service          root:root 0644 systemd"
  "tools/csrbackup.sh        /usr/local/sbin/csrbackup                         root:root 0750 tools"
  "tools/csr-bootstrap-admin /usr/local/sbin/csr-bootstrap-admin               root:root 0750 tools"
  "tools/csr-uninstall.sh    /usr/local/sbin/csr-uninstall                      root:root 0750 tools"
  "tools/csr-set-auth        /usr/local/sbin/csr-set-auth                       root:root 0750 tools"
)
# nginx include: uncomment and fix the filename once it's in the repo
MANIFEST+=("nginx/30-csr.conf /etc/nginx/csr-dashboard.d/30-csr.conf root:root 0644 nginx")

changed_tags=""

for entry in "${MANIFEST[@]}"; do
    read -r src dest og mode tag <<< "$entry"
    if [[ ! -f "$src" ]]; then
        echo "MISSING in repo: $src" >&2
        exit 1
    fi
    if [[ -f "$dest" ]] && cmp -s "$src" "$dest"; then
        continue
    fi
    if $DIFF_ONLY; then
        echo "=== would update: $dest ==="
        diff -u "$dest" "$src" 2>/dev/null | head -40 || echo "  (new file)"
        continue
    fi
    install -o "${og%%:*}" -g "${og##*:}" -m "$mode" -D "$src" "$dest"
    echo "installed: $dest (${og} ${mode})"
    changed_tags+=" $tag"
done

$DIFF_ONLY && exit 0

if [[ -z "$changed_tags" ]]; then
    echo "nothing to deploy - live files match the repo"
    exit 0
fi

# Seed the per-deployment env file from the example if it does not exist yet.
# The live env file is operator-managed (like email.conf) and is never
# overwritten by deploy - edit /etc/csr-dashboard/csr-dashboard.env directly.
if [[ ! -f /etc/csr-dashboard/csr-dashboard.env && -f config/csr-dashboard.env.example ]]; then
    install -d -o root -g csrapi -m 0750 /etc/csr-dashboard
    install -o csrapi -g csrapi -m 0640 \
        config/csr-dashboard.env.example /etc/csr-dashboard/csr-dashboard.env
    echo "seeded /etc/csr-dashboard/csr-dashboard.env from example - review it"
fi
if [[ ! -f /etc/csr-dashboard/email.conf && -f config/email.conf.example ]]; then
    install -d -o root -g csrapi -m 0750 /etc/csr-dashboard
    install -o csrapi -g csrapi -m 0640 \
        config/email.conf.example /etc/csr-dashboard/email.conf
    echo "seeded /etc/csr-dashboard/email.conf from example - set the SMG host"
fi

# Certinel data root (FHS /var/opt for add-on app data). issued/ holds signed
# certs (written by the app as csrapi + chowned by the helper); requests/ holds
# generated CSRs (written by the helper as root). var_lib_t lets the confined
# csr-api service write here, matching the DB dir's context.
install -d -o root   -g root   -m 0755 /var/opt/certinel
install -d -o csrapi -g csrapi -m 0750 /var/opt/certinel/issued
install -d -o root   -g csrapi -m 0750 /var/opt/certinel/requests
if command -v semanage >/dev/null 2>&1; then
    # Some RHEL variants ship an SELinux equivalency '/var/opt = /opt' (the
    # /var/opt/certinel rule is then rejected and the /opt/certinel rule applies
    # via the equivalency); others don't (the /var/opt/certinel rule applies
    # directly). Register both — whichever is valid on this host wins, the other
    # is a harmless no-op — so the data root always relabels to var_lib_t.
    semanage fcontext -a -t var_lib_t '/opt/certinel(/.*)?'     2>/dev/null || true
    semanage fcontext -a -t var_lib_t '/var/opt/certinel(/.*)?' 2>/dev/null || true
    command -v restorecon >/dev/null 2>&1 && restorecon -R /var/opt/certinel || true
fi

# Pre-deploy DB/file backup (after diffing, before service restart)
command -v csrbackup >/dev/null && csrbackup || echo "WARN: csrbackup not found"

if [[ "$changed_tags" == *frontend* ]]; then
    restorecon -Rv /var/www/csr/ || true
fi
if [[ "$changed_tags" == *backend* ]]; then
    fapolicyd-cli --file update /opt/csr-dashboard/ || true
    fapolicyd-cli --update || true
fi
if [[ "$changed_tags" == *systemd* ]]; then
    # Validate every installed unit BEFORE reloading - a malformed unit must
    # not reach a restart (a bad ExecStart line once left the service unable
    # to restart). Same fail-loud gate as nginx -t below.
    for unit in /etc/systemd/system/csr-api.service \
                /etc/systemd/system/csr-expiry-warn.service \
                /etc/systemd/system/csr-expiry-warn.timer \
                /etc/systemd/system/csr-auto-renew.service \
                /etc/systemd/system/csr-auto-renew.timer \
                /etc/systemd/system/csr-deliver.service \
                /etc/systemd/system/csr-deliver.timer; do
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
    systemctl enable --now csr-expiry-warn.timer csr-auto-renew.timer csr-deliver.timer 2>/dev/null || true
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
        echo "(on first install also ensure nginx.conf includes csr-dashboard.d/*.conf" >&2
        echo " and that nginx is enabled - see OFFLINE-INSTALL.md)" >&2
        exit 1
    fi
fi
if $RESTART && [[ "$changed_tags" == *backend* || "$changed_tags" == *systemd* ]]; then
    systemctl restart csr-api
    sleep 1
    if ! systemctl is-active csr-api >/dev/null; then
        echo "csr-api FAILED to start - check journalctl -u csr-api" >&2
        exit 1
    fi
    echo "csr-api: active (restarted)"

    # Verify the running app reports the deployed VERSION. app.py reads VERSION
    # once at startup, so a stale process is the classic "UI shows old version"
    # bug. This makes the mismatch loud instead of silent.
    if [[ -f /opt/csr-dashboard/VERSION ]]; then
        want="$(cat /opt/csr-dashboard/VERSION 2>/dev/null)"
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
            echo "      systemctl restart csr-api" >&2
        elif [[ "$got" == "$want" ]]; then
            echo "csr-api: serving v$got"
        fi
        # (empty $got just means health wasn't reachable over loopback TLS here;
        #  not fatal - mTLS/cert setup can make local curl fail. Skip silently.)
    fi
fi

echo "deploy complete:$changed_tags"
