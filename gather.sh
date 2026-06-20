#!/bin/bash
# gather.sh - copy the LIVE files into the repo layout. Used once to build
# the initial baseline, and afterwards to capture any hotfix made directly
# on the box (git diff will then show exactly what drifted).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p backend frontend helper/certinel_helper.d systemd nginx config ansible tools docs

cp -v /opt/certinel/VERSION           ./        2>/dev/null || true
cp -v /opt/certinel/app.py            backend/
cp -v /opt/certinel/notify.py         backend/
cp -v /opt/certinel/import_certs.py   backend/
cp -v /var/www/csr/index.html              frontend/
cp -v /var/www/csr/app.js                  frontend/
cp -v /root/sslcerts/scripts/certinel_helper.sh helper/
cp -v /root/sslcerts/scripts/certinel_helper.d/*.sh helper/certinel_helper.d/
cp -v /etc/systemd/system/certinel-expiry-warn.service systemd/
cp -v /etc/systemd/system/certinel-expiry-warn.timer   systemd/
cp -v /etc/systemd/system/certinel-api.service         systemd/
cp -v /usr/local/sbin/certinel-backup            tools/certinel-backup.sh
cp -v /usr/local/sbin/certinel-bootstrap-admin  tools/certinel-bootstrap-admin 2>/dev/null || true
cp -v /usr/local/sbin/certinel-uninstall        tools/certinel-uninstall.sh 2>/dev/null || true
cp -v /usr/local/sbin/certinel-set-auth         tools/certinel-set-auth 2>/dev/null || true
# nginx include - adjust to your actual filename:
cp -v /etc/nginx/certinel.d/30-csr.conf    nginx/
# sanitized config example (live email.conf is intentionally NOT tracked)
if [[ ! -f config/email.conf.example && -f /etc/certinel/email.conf ]]; then
    cp -v /etc/certinel/email.conf config/email.conf.example
fi
if [[ ! -f config/certinel.env.example && -f /etc/certinel/certinel.env ]]; then
    cp -v /etc/certinel/certinel.env config/certinel.env.example
fi
echo "gather complete - review with: git status && git diff"
