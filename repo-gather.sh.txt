#!/bin/bash
# gather.sh - copy the LIVE files into the repo layout. Used once to build
# the initial baseline, and afterwards to capture any hotfix made directly
# on the box (git diff will then show exactly what drifted).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p backend frontend helper/csr_dashboard_helper.d systemd nginx config ansible tools docs

cp -v /opt/csr-dashboard/VERSION           ./        2>/dev/null || true
cp -v /opt/csr-dashboard/app.py            backend/
cp -v /opt/csr-dashboard/notify.py         backend/
cp -v /opt/csr-dashboard/import_certs.py   backend/
cp -v /var/www/csr/index.html              frontend/
cp -v /var/www/csr/app.js                  frontend/
cp -v /root/sslcerts/scripts/csr_dashboard_helper.sh helper/
cp -v /root/sslcerts/scripts/csr_dashboard_helper.d/*.sh helper/csr_dashboard_helper.d/
cp -v /etc/systemd/system/csr-expiry-warn.service systemd/
cp -v /etc/systemd/system/csr-expiry-warn.timer   systemd/
cp -v /etc/systemd/system/csr-api.service         systemd/
cp -v /usr/local/sbin/csrbackup            tools/csrbackup.sh
# nginx include - adjust to your actual filename:
cp -v /etc/nginx/rcdn01.d/30-csr.conf    nginx/
# sanitized config example (live email.conf is intentionally NOT tracked)
if [[ ! -f config/email.conf.example && -f /etc/csr-dashboard/email.conf ]]; then
    cp -v /etc/csr-dashboard/email.conf config/email.conf.example
fi
if [[ ! -f config/csr-dashboard.env.example && -f /etc/csr-dashboard/csr-dashboard.env ]]; then
    cp -v /etc/csr-dashboard/csr-dashboard.env config/csr-dashboard.env.example
fi
echo "gather complete - review with: git status && git diff"
