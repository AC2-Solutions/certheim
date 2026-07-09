#!/bin/bash
# repo-verify.sh - confirm the clone has every file the repo should contain,
# and that each tracked file matches what's live on the box. Run from the
# clone root on the production box. Read-only: changes nothing.
set -uo pipefail
cd "$(dirname "$0")"

# repo_path | live_path  (live "" = repo-only file, existence check only)
PAIRS=(
  "VERSION|/opt/certheim/VERSION"
  "backend/app.py|/opt/certheim/app.py"
  "backend/notify.py|/opt/certheim/notify.py"
  "backend/build_mode.py|/opt/certheim/build_mode.py"
  "backend/envcompat.py|/opt/certheim/envcompat.py"
  "backend/capabilities.py|/opt/certheim/capabilities.py"
  "backend/db.py|/opt/certheim/db.py"
  "backend/db_migrate.py|/opt/certheim/db_migrate.py"
  "backend/licensing.py|/opt/certheim/licensing.py"
  "backend/domains.py|/opt/certheim/domains.py"
  "backend/sign.py|/opt/certheim/sign.py"
  "backend/keystore.py|/opt/certheim/keystore.py"
  "backend/truststore.py|/opt/certheim/truststore.py"
  "backend/routes_truststore.py|/opt/certheim/routes_truststore.py"
  "backend/csr_subject.py|/opt/certheim/csr_subject.py"
  "backend/routes_integrations.py|/opt/certheim/routes_integrations.py"
  "backend/routes_feedback.py|/opt/certheim/routes_feedback.py"
  "backend/routes_auth.py|/opt/certheim/routes_auth.py"
  "backend/routes_jobs.py|/opt/certheim/routes_jobs.py"
  "backend/routes_requests.py|/opt/certheim/routes_requests.py"
  "backend/routes_groups.py|/opt/certheim/routes_groups.py"
  "backend/routes_me.py|/opt/certheim/routes_me.py"
  "backend/routes_admin.py|/opt/certheim/routes_admin.py"
  "backend/routes_signing.py|/opt/certheim/routes_signing.py"
  "backend/import_certs.py|/opt/certheim/import_certs.py"
  "frontend/index.html|/var/www/csr/index.html"
  "frontend/app.css|/var/www/csr/app.css"
  "frontend/app.1-core.js|/var/www/csr/app.1-core.js"
  "frontend/app.2-jobs.js|/var/www/csr/app.2-jobs.js"
  "frontend/app.3-admin.js|/var/www/csr/app.3-admin.js"
  "frontend/app.4-misc-boot.js|/var/www/csr/app.4-misc-boot.js"
  "frontend/app.5-guide.js|/var/www/csr/app.5-guide.js"
  "frontend/setup-guide.html|/var/www/csr/setup-guide.html"
  "helper/certheim_helper.sh|/opt/certheim/helper/certheim_helper.sh"
  "helper/certheim_helper.d/00-common.sh|/opt/certheim/helper/certheim_helper.d/00-common.sh"
  "helper/certheim_helper.d/10-certtypes.sh|/opt/certheim/helper/certheim_helper.d/10-certtypes.sh"
  "helper/certheim_helper.d/20-generate.sh|/opt/certheim/helper/certheim_helper.d/20-generate.sh"
  "helper/certheim_helper.d/30-truststore.sh|/opt/certheim/helper/certheim_helper.d/30-truststore.sh"
  "helper/certheim_helper.d/40-mtls.sh|/opt/certheim/helper/certheim_helper.d/40-mtls.sh"
  "systemd/certheim-expiry-warn.service|/etc/systemd/system/certheim-expiry-warn.service"
  "systemd/certheim-expiry-warn.timer|/etc/systemd/system/certheim-expiry-warn.timer"
  "systemd/certheim-auto-renew.service|/etc/systemd/system/certheim-auto-renew.service"
  "systemd/certheim-auto-renew.timer|/etc/systemd/system/certheim-auto-renew.timer"
  "systemd/certheim-deliver.service|/etc/systemd/system/certheim-deliver.service"
  "systemd/certheim-deliver.timer|/etc/systemd/system/certheim-deliver.timer"
  "systemd/certheim-api.service|/etc/systemd/system/certheim-api.service"
  "systemd/certheim-doctor.service|/etc/systemd/system/certheim-doctor.service"
  "systemd/certheim-doctor.timer|/etc/systemd/system/certheim-doctor.timer"
  "nginx/30-csr.conf|/etc/nginx/certheim.d/30-csr.conf"
  "tools/certheim-backup.sh|/usr/local/sbin/certheim-backup"
  "tools/certheim-bootstrap-admin|/usr/local/sbin/certheim-bootstrap-admin"
  "tools/certheim-uninstall.sh|/usr/local/sbin/certheim-uninstall"
  "tools/certheim-set-auth|/usr/local/sbin/certheim-set-auth"
  "tools/certheim-doctor.sh|/usr/local/sbin/certheim-doctor"
  "tools/certheim-doctor-alert.sh|/usr/local/sbin/certheim-doctor-alert"
  "tools/openbao-fetch.sh|/usr/local/sbin/openbao-fetch"
  "README.md|"
  ".gitignore|"
  ".gitlab-ci.yml|"
  "deploy.sh|"
  "gather.sh|"
  "config/email.conf.example|"
  "config/certheim.env.example|"
)

miss=0; drift=0; ok=0
for pair in "${PAIRS[@]}"; do
    repo="${pair%%|*}"; live="${pair##*|}"
    if [[ ! -f "$repo" ]]; then
        printf 'MISSING from repo : %s\n' "$repo"; ((miss++)); continue
    fi
    if [[ -n "$live" ]]; then
        if [[ ! -f "$live" ]]; then
            printf 'live file absent  : %s (cannot compare)\n' "$live"; continue
        fi
        if cmp -s "$repo" "$live"; then
            ((ok++))
        else
            printf 'DRIFT repo<>live  : %s  vs  %s\n' "$repo" "$live"; ((drift++))
        fi
    else
        ((ok++))
    fi
done

echo "----"
echo "ok=$ok  missing=$miss  drift=$drift"
if (( miss || drift )); then
    echo "Resolve before pushing:"
    echo "  - MISSING: add the file to the repo (./gather.sh pulls live ones)"
    echo "  - DRIFT: the box differs from the repo. If the box is correct,"
    echo "    run ./gather.sh to capture it; then git diff to review."
    exit 1
fi
echo "Clone matches the live box. Safe to commit/push."
