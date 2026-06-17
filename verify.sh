#!/bin/bash
# repo-verify.sh - confirm the clone has every file the repo should contain,
# and that each tracked file matches what's live on the box. Run from the
# clone root on rcdn01. Read-only: changes nothing.
set -uo pipefail
cd "$(dirname "$0")"

# repo_path | live_path  (live "" = repo-only file, existence check only)
PAIRS=(
  "VERSION|/opt/csr-dashboard/VERSION"
  "backend/app.py|/opt/csr-dashboard/app.py"
  "backend/notify.py|/opt/csr-dashboard/notify.py"
  "backend/import_certs.py|/opt/csr-dashboard/import_certs.py"
  "frontend/index.html|/var/www/csr/index.html"
  "frontend/app.js|/var/www/csr/app.js"
  "helper/csr_dashboard_helper.sh|/root/sslcerts/scripts/csr_dashboard_helper.sh"
  "helper/csr_dashboard_helper.d/00-common.sh|/root/sslcerts/scripts/csr_dashboard_helper.d/00-common.sh"
  "helper/csr_dashboard_helper.d/10-certtypes.sh|/root/sslcerts/scripts/csr_dashboard_helper.d/10-certtypes.sh"
  "helper/csr_dashboard_helper.d/20-generate.sh|/root/sslcerts/scripts/csr_dashboard_helper.d/20-generate.sh"
  "systemd/csr-expiry-warn.service|/etc/systemd/system/csr-expiry-warn.service"
  "systemd/csr-expiry-warn.timer|/etc/systemd/system/csr-expiry-warn.timer"
  "systemd/csr-api.service|/etc/systemd/system/csr-api.service"
  "nginx/30-csr.conf|/etc/nginx/rcdn01.d/30-csr.conf"
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
