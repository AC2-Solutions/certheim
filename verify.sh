#!/bin/bash
# repo-verify.sh - confirm the clone has every file the repo should contain,
# and that each tracked file matches what's live on the box. Run from the
# clone root on the production box. Read-only: changes nothing.
set -uo pipefail
cd "$(dirname "$0")"

# repo_path | live_path  (live "" = repo-only file, existence check only)
PAIRS=(
  "VERSION|/opt/csr-dashboard/VERSION"
  "backend/app.py|/opt/csr-dashboard/app.py"
  "backend/notify.py|/opt/csr-dashboard/notify.py"
  "backend/capabilities.py|/opt/csr-dashboard/capabilities.py"
  "backend/licensing.py|/opt/csr-dashboard/licensing.py"
  "backend/sign.py|/opt/csr-dashboard/sign.py"
  "backend/deliver.py|/opt/csr-dashboard/deliver.py"
  "backend/keystore.py|/opt/csr-dashboard/keystore.py"
  "backend/renew.py|/opt/csr-dashboard/renew.py"
  "backend/acme_client.py|/opt/csr-dashboard/acme_client.py"
  "backend/acme_dns.py|/opt/csr-dashboard/acme_dns.py"
  "backend/ca_providers.py|/opt/csr-dashboard/ca_providers.py"
  "backend/acme_server.py|/opt/csr-dashboard/acme_server.py"
  "backend/routes_acme.py|/opt/csr-dashboard/routes_acme.py"
  "backend/routes_deliver.py|/opt/csr-dashboard/routes_deliver.py"
  "backend/truststore.py|/opt/csr-dashboard/truststore.py"
  "backend/routes_truststore.py|/opt/csr-dashboard/routes_truststore.py"
  "backend/csr_subject.py|/opt/csr-dashboard/csr_subject.py"
  "backend/routes_integrations.py|/opt/csr-dashboard/routes_integrations.py"
  "backend/routes_feedback.py|/opt/csr-dashboard/routes_feedback.py"
  "backend/routes_auth.py|/opt/csr-dashboard/routes_auth.py"
  "backend/routes_jobs.py|/opt/csr-dashboard/routes_jobs.py"
  "backend/routes_requests.py|/opt/csr-dashboard/routes_requests.py"
  "backend/routes_groups.py|/opt/csr-dashboard/routes_groups.py"
  "backend/routes_me.py|/opt/csr-dashboard/routes_me.py"
  "backend/routes_admin.py|/opt/csr-dashboard/routes_admin.py"
  "backend/routes_signing.py|/opt/csr-dashboard/routes_signing.py"
  "backend/import_certs.py|/opt/csr-dashboard/import_certs.py"
  "frontend/index.html|/var/www/csr/index.html"
  "frontend/app.css|/var/www/csr/app.css"
  "frontend/app.1-core.js|/var/www/csr/app.1-core.js"
  "frontend/app.2-jobs.js|/var/www/csr/app.2-jobs.js"
  "frontend/app.3-admin.js|/var/www/csr/app.3-admin.js"
  "frontend/app.4-misc-boot.js|/var/www/csr/app.4-misc-boot.js"
  "frontend/app.5-guide.js|/var/www/csr/app.5-guide.js"
  "helper/csr_dashboard_helper.sh|/opt/certinel/helper/csr_dashboard_helper.sh"
  "helper/csr_dashboard_helper.d/00-common.sh|/opt/certinel/helper/csr_dashboard_helper.d/00-common.sh"
  "helper/csr_dashboard_helper.d/10-certtypes.sh|/opt/certinel/helper/csr_dashboard_helper.d/10-certtypes.sh"
  "helper/csr_dashboard_helper.d/20-generate.sh|/opt/certinel/helper/csr_dashboard_helper.d/20-generate.sh"
  "helper/csr_dashboard_helper.d/30-truststore.sh|/opt/certinel/helper/csr_dashboard_helper.d/30-truststore.sh"
  "helper/csr_dashboard_helper.d/40-mtls.sh|/opt/certinel/helper/csr_dashboard_helper.d/40-mtls.sh"
  "systemd/certinel-expiry-warn.service|/etc/systemd/system/certinel-expiry-warn.service"
  "systemd/certinel-expiry-warn.timer|/etc/systemd/system/certinel-expiry-warn.timer"
  "systemd/certinel-auto-renew.service|/etc/systemd/system/certinel-auto-renew.service"
  "systemd/certinel-auto-renew.timer|/etc/systemd/system/certinel-auto-renew.timer"
  "systemd/certinel-deliver.service|/etc/systemd/system/certinel-deliver.service"
  "systemd/certinel-deliver.timer|/etc/systemd/system/certinel-deliver.timer"
  "systemd/certinel-api.service|/etc/systemd/system/certinel-api.service"
  "nginx/30-csr.conf|/etc/nginx/csr-dashboard.d/30-csr.conf"
  "tools/csrbackup.sh|/usr/local/sbin/csrbackup"
  "tools/csr-bootstrap-admin|/usr/local/sbin/csr-bootstrap-admin"
  "tools/csr-uninstall.sh|/usr/local/sbin/csr-uninstall"
  "tools/csr-set-auth|/usr/local/sbin/csr-set-auth"
  "README.md|"
  ".gitignore|"
  ".gitlab-ci.yml|"
  "deploy.sh|"
  "gather.sh|"
  "config/email.conf.example|"
  "config/csr-dashboard.env.example|"
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
