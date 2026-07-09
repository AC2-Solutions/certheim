#!/bin/bash
# repo-verify.sh - confirm the clone has every file the repo should contain,
# and that each tracked file matches what's live on the box. Run from the
# clone root on the production box. Read-only: changes nothing.
set -uo pipefail
cd "$(dirname "$0")"

# repo_path | live_path  (live "" = repo-only file, existence check only)
PAIRS=(
  "VERSION|/opt/certinel/VERSION"
  "backend/app.py|/opt/certinel/app.py"
  "backend/notify.py|/opt/certinel/notify.py"
  "backend/build_mode.py|/opt/certinel/build_mode.py"
  "backend/envcompat.py|/opt/certinel/envcompat.py"
  "backend/capabilities.py|/opt/certinel/capabilities.py"
  "backend/db.py|/opt/certinel/db.py"
  "backend/db_migrate.py|/opt/certinel/db_migrate.py"
  "backend/licensing.py|/opt/certinel/licensing.py"
  "backend/domains.py|/opt/certinel/domains.py"
  "backend/sign.py|/opt/certinel/sign.py"
  "backend/keystore.py|/opt/certinel/keystore.py"
  "backend/truststore.py|/opt/certinel/truststore.py"
  "backend/routes_truststore.py|/opt/certinel/routes_truststore.py"
  "backend/csr_subject.py|/opt/certinel/csr_subject.py"
  "backend/routes_integrations.py|/opt/certinel/routes_integrations.py"
  "backend/routes_feedback.py|/opt/certinel/routes_feedback.py"
  "backend/routes_auth.py|/opt/certinel/routes_auth.py"
  "backend/routes_jobs.py|/opt/certinel/routes_jobs.py"
  "backend/routes_requests.py|/opt/certinel/routes_requests.py"
  "backend/routes_groups.py|/opt/certinel/routes_groups.py"
  "backend/routes_me.py|/opt/certinel/routes_me.py"
  "backend/routes_admin.py|/opt/certinel/routes_admin.py"
  "backend/routes_signing.py|/opt/certinel/routes_signing.py"
  "backend/import_certs.py|/opt/certinel/import_certs.py"
  "frontend/index.html|/var/www/csr/index.html"
  "frontend/app.css|/var/www/csr/app.css"
  "frontend/app.1-core.js|/var/www/csr/app.1-core.js"
  "frontend/app.2-jobs.js|/var/www/csr/app.2-jobs.js"
  "frontend/app.3-admin.js|/var/www/csr/app.3-admin.js"
  "frontend/app.4-misc-boot.js|/var/www/csr/app.4-misc-boot.js"
  "frontend/app.5-guide.js|/var/www/csr/app.5-guide.js"
  "frontend/setup-guide.html|/var/www/csr/setup-guide.html"
  "helper/certinel_helper.sh|/opt/certinel/helper/certinel_helper.sh"
  "helper/certinel_helper.d/00-common.sh|/opt/certinel/helper/certinel_helper.d/00-common.sh"
  "helper/certinel_helper.d/10-certtypes.sh|/opt/certinel/helper/certinel_helper.d/10-certtypes.sh"
  "helper/certinel_helper.d/20-generate.sh|/opt/certinel/helper/certinel_helper.d/20-generate.sh"
  "helper/certinel_helper.d/30-truststore.sh|/opt/certinel/helper/certinel_helper.d/30-truststore.sh"
  "helper/certinel_helper.d/40-mtls.sh|/opt/certinel/helper/certinel_helper.d/40-mtls.sh"
  "systemd/certinel-expiry-warn.service|/etc/systemd/system/certinel-expiry-warn.service"
  "systemd/certinel-expiry-warn.timer|/etc/systemd/system/certinel-expiry-warn.timer"
  "systemd/certinel-auto-renew.service|/etc/systemd/system/certinel-auto-renew.service"
  "systemd/certinel-auto-renew.timer|/etc/systemd/system/certinel-auto-renew.timer"
  "systemd/certinel-deliver.service|/etc/systemd/system/certinel-deliver.service"
  "systemd/certinel-deliver.timer|/etc/systemd/system/certinel-deliver.timer"
  "systemd/certinel-api.service|/etc/systemd/system/certinel-api.service"
  "systemd/certinel-doctor.service|/etc/systemd/system/certinel-doctor.service"
  "systemd/certinel-doctor.timer|/etc/systemd/system/certinel-doctor.timer"
  "nginx/30-csr.conf|/etc/nginx/certinel.d/30-csr.conf"
  "tools/certinel-backup.sh|/usr/local/sbin/certinel-backup"
  "tools/certinel-bootstrap-admin|/usr/local/sbin/certinel-bootstrap-admin"
  "tools/certinel-uninstall.sh|/usr/local/sbin/certinel-uninstall"
  "tools/certinel-set-auth|/usr/local/sbin/certinel-set-auth"
  "tools/certinel-doctor.sh|/usr/local/sbin/certinel-doctor"
  "tools/certinel-doctor-alert.sh|/usr/local/sbin/certinel-doctor-alert"
  "tools/openbao-fetch.sh|/usr/local/sbin/openbao-fetch"
  "README.md|"
  ".gitignore|"
  ".gitlab-ci.yml|"
  "deploy.sh|"
  "gather.sh|"
  "config/email.conf.example|"
  "config/certinel.env.example|"
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
