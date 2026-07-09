#!/bin/bash
# gather.sh - copy the LIVE files into the repo layout. Used once to build
# the initial baseline, and afterwards to capture any hotfix made directly
# on the box (git diff will then show exactly what drifted).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p backend frontend helper/certheim_helper.d systemd nginx config ansible tools docs

cp -v /opt/certheim/VERSION           ./        2>/dev/null || true
cp -v /opt/certheim/app.py            backend/
cp -v /opt/certheim/notify.py         backend/
cp -v /opt/certheim/import_certs.py   backend/
cp -v /var/www/csr/index.html              frontend/
cp -v /var/www/csr/app.js                  frontend/
cp -v /root/sslcerts/scripts/certheim_helper.sh helper/
cp -v /root/sslcerts/scripts/certheim_helper.d/*.sh helper/certheim_helper.d/
cp -v /etc/systemd/system/certheim-expiry-warn.service systemd/
cp -v /etc/systemd/system/certheim-expiry-warn.timer   systemd/
cp -v /etc/systemd/system/certheim-api.service         systemd/
cp -v /usr/local/sbin/certheim-backup            tools/certheim-backup.sh
cp -v /usr/local/sbin/certheim-bootstrap-admin  tools/certheim-bootstrap-admin 2>/dev/null || true
cp -v /usr/local/sbin/certheim-uninstall        tools/certheim-uninstall.sh 2>/dev/null || true
cp -v /usr/local/sbin/certheim-set-auth         tools/certheim-set-auth 2>/dev/null || true
# nginx include - adjust to your actual filename:
cp -v /etc/nginx/certheim.d/30-csr.conf    nginx/
# sanitized config example (live email.conf is intentionally NOT tracked)
if [[ ! -f config/email.conf.example && -f /etc/certheim/email.conf ]]; then
    cp -v /etc/certheim/email.conf config/email.conf.example
fi
if [[ ! -f config/certheim.env.example && -f /etc/certheim/certheim.env ]]; then
    cp -v /etc/certheim/certheim.env config/certheim.env.example
fi
echo "gather complete - review with: git status && git diff"
