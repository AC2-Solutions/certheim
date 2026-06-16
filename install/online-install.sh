#!/bin/bash
# online-install.sh - online (non-STIG / connected) installer for CSR Dashboard.
#
# Companion to install/offline-install.sh. Use this on a CONNECTED, non-STIG
# box (no air-gap, no fapolicyd, pip+internet available) - e.g. a development
# instance. It does everything offline-install does, except it builds the venv
# from PyPI instead of a bundled wheelhouse, and it wires nginx + a self-signed
# server cert + firewalld so a bare RHEL/Alma box ends up serving the dashboard.
#
# It does NOT harden for STIG (no FIPS, no fapolicyd trust). For the air-gapped
# production target use the offline bundle workflow instead.
#
#     sudo PYBIN=python3.12 SMG_HOST=smtp.example DASHBOARD_URL=https://host/csr/ \
#          FROM_ADDRESS=noreply@example ./online-install.sh
#
# Idempotent: safe to re-run. Run as root from the repo root (NOT install/).

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PYBIN="${PYBIN:-python3.12}"
SVC_USER="csrapi"
SMG_HOST="${SMG_HOST:-smtp.ac2.lan}"
SMG_PORT="${SMG_PORT:-25}"
FROM_ADDRESS="${FROM_ADDRESS:-noreply-csr@ac2.lan}"
DASHBOARD_URL="${DASHBOARD_URL:-https://csr-dev.ac2.lan/csr/}"
GLOBAL_CC="${GLOBAL_CC:-}"
CERT_DIR=/etc/pki/csr-dashboard
NGINX_INCLUDE_DIR=/etc/nginx/rcdn01.d

log()  { echo -e "\n=== $* ==="; }
warn() { echo "  WARN: $*" >&2; }
die()  { echo "  ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
log "1/9  OS packages (dnf)"
# ---------------------------------------------------------------------------
need_pkgs=()
command -v nginx      >/dev/null || need_pkgs+=(nginx)
command -v sqlite3    >/dev/null || need_pkgs+=(sqlite)
command -v git        >/dev/null || need_pkgs+=(git)
command -v openssl    >/dev/null || need_pkgs+=(openssl)
command -v restorecon >/dev/null || need_pkgs+=(policycoreutils)
$PYBIN -m pip --version >/dev/null 2>&1 || need_pkgs+=(python3-pip)
if (( ${#need_pkgs[@]} )); then
    echo "  installing: ${need_pkgs[*]}"
    dnf install -y "${need_pkgs[@]}"
else
    echo "  all present"
fi

# ---------------------------------------------------------------------------
log "2/9  Service account: ${SVC_USER}"
# ---------------------------------------------------------------------------
id "$SVC_USER" >/dev/null 2>&1 \
    || useradd --system --no-create-home --shell /sbin/nologin \
               --comment "CSR Dashboard service account" "$SVC_USER"
getent group nginx >/dev/null || die "nginx group missing - nginx install failed?"
echo "  ok"

# ---------------------------------------------------------------------------
log "3/9  Directories"
# ---------------------------------------------------------------------------
DIRS=(
  "/opt/csr-dashboard|root:${SVC_USER}|0750"
  "/var/lib/csr-dashboard|${SVC_USER}:${SVC_USER}|0750"
  "/var/www/csr|root:nginx|0750"
  "/etc/csr-dashboard|root:${SVC_USER}|0750"
  "/root/sslcerts/scripts|root:root|0750"
  "/root/sslcerts/scripts/csr_dashboard_helper.d|root:root|0750"
  "/root/sslcerts/private|root:root|0700"
  "/home/ansible/new_request|root:root|0755"
  "/home/ansible/issued|root:${SVC_USER}|0750"
)
for entry in "${DIRS[@]}"; do
    IFS='|' read -r d og mode <<< "$entry"
    install -d -o "${og%%:*}" -g "${og##*:}" -m "$mode" "$d"
done
chmod o+x /home/ansible 2>/dev/null || true
echo "  ok"

# ---------------------------------------------------------------------------
log "4/9  Sudoers drop-in (service account runs only the helper as root)"
# ---------------------------------------------------------------------------
SUDOERS=/etc/sudoers.d/csr-dashboard
if [[ ! -f "$SUDOERS" ]]; then
    printf '# CSR Dashboard: service account runs ONLY the helper as root.\n%s ALL=(root) NOPASSWD: /root/sslcerts/scripts/csr_dashboard_helper.sh\n' \
        "$SVC_USER" > "$SUDOERS"
    chmod 0440 "$SUDOERS"
    visudo -cf "$SUDOERS" >/dev/null || die "sudoers validation failed"
fi
echo "  ok"

# ---------------------------------------------------------------------------
log "5/9  Python venv from PyPI"
# ---------------------------------------------------------------------------
VENV=/opt/csr-dashboard/venv
[[ -x "$VENV/bin/python3" ]] || "$PYBIN" -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip setuptools wheel
if ! "$VENV/bin/pip" install -r requirements.txt; then
    warn "pinned requirements.txt failed on $PYBIN - retrying with core deps unpinned"
    "$VENV/bin/pip" install flask gunicorn
fi
# Group (csrapi) must read/traverse the whole venv to exec gunicorn/python.
# This is the correct generalization of the STIG venv-perm fix (F10): g+rX
# covers non-exec files (pyvenv.cfg, site-packages *.py) that a narrow
# "only +x files" chmod misses.
chown -R root:csrapi "$VENV"
chmod 0750 /opt/csr-dashboard "$VENV" "$VENV/bin"
chmod -R g+rX "$VENV"
echo "  venv ready"

# ---------------------------------------------------------------------------
log "6/9  Config files"
# ---------------------------------------------------------------------------
cat > /etc/csr-dashboard/email.conf <<EMAILCONF
# generated by online-install
[smtp]
host = ${SMG_HOST}
port = ${SMG_PORT}
timeout = 10

[from]
address = ${FROM_ADDRESS}

[recipients]
cc = ${GLOBAL_CC}

[content]
dashboard_url = ${DASHBOARD_URL}
EMAILCONF
chown "${SVC_USER}:${SVC_USER}" /etc/csr-dashboard/email.conf
chmod 0640 /etc/csr-dashboard/email.conf
if [[ ! -f /etc/csr-dashboard/csr-dashboard.env && -f config/csr-dashboard.env.example ]]; then
    install -o "$SVC_USER" -g "$SVC_USER" -m 0640 \
        config/csr-dashboard.env.example /etc/csr-dashboard/csr-dashboard.env
fi
echo "  ok"

# ---------------------------------------------------------------------------
log "7/9  nginx wiring + self-signed server cert (PKI placeholder)"
# ---------------------------------------------------------------------------
install -d -m 0755 "$NGINX_INCLUDE_DIR"
# include rcdn01.d from the http{} block if not already wired
if ! grep -q "rcdn01.d" /etc/nginx/nginx.conf; then
    # insert the include just inside the http { block
    sed -i '0,/^\s*http\s*{/s//&\n    include '"${NGINX_INCLUDE_DIR//\//\\/}"'\/*.conf;/' /etc/nginx/nginx.conf
    echo "  wired include ${NGINX_INCLUDE_DIR}/*.conf into nginx.conf"
fi
if [[ ! -f "$CERT_DIR/server.crt" ]]; then
    install -d -m 0750 "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
        -subj "/CN=$(hostname -f)" \
        -addext "subjectAltName=DNS:$(hostname -f),DNS:$(hostname -s)" >/dev/null 2>&1
    chmod 0640 "$CERT_DIR/server.key"; chmod 0644 "$CERT_DIR/server.crt"
    echo "  generated self-signed cert for $(hostname -f) (replace with real PKI for CAC mTLS)"
fi
# SELinux: nginx is denied connecting to the gunicorn backend (127.0.0.1:5002)
# unless this boolean is on - otherwise every proxied request 502s (F12).
if command -v getsebool >/dev/null && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
    setsebool -P httpd_can_network_connect 1
    echo "  setsebool httpd_can_network_connect=on (nginx -> backend)"
fi
systemctl enable --now nginx >/dev/null 2>&1 || systemctl restart nginx
echo "  nginx up"

# ---------------------------------------------------------------------------
log "8/9  firewalld: open https"
# ---------------------------------------------------------------------------
if systemctl is-active firewalld >/dev/null 2>&1; then
    firewall-cmd --permanent --add-service=https >/dev/null
    firewall-cmd --reload >/dev/null
    echo "  443/tcp open"
else
    echo "  firewalld inactive - skipped"
fi

# ---------------------------------------------------------------------------
log "9/9  Deploy code + start services"
# ---------------------------------------------------------------------------
bash ./deploy.sh
systemctl enable csr-api.service csr-expiry-warn.timer >/dev/null 2>&1 || true
systemctl start csr-expiry-warn.timer 2>/dev/null || true

echo ""
echo "==================================================================="
echo " online install COMPLETE for v$(cat VERSION 2>/dev/null || echo '?')"
echo "==================================================================="
echo " Verify:  curl -sk https://localhost/csr/api/health"
echo " Admin:   fresh DB has no admins. After one browser/API hit, run"
echo "          (dev box, behind proxy all non-CAC users are ip:127.0.0.1):"
echo "            sqlite3 /var/lib/csr-dashboard/jobs.db \\"
echo "              \"UPDATE users SET is_admin=1,is_active=1 WHERE dn='ip:127.0.0.1'\""
echo "          systemctl restart csr-api"
echo "==================================================================="
