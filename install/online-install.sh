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
# CAC mTLS option. ENABLE_MTLS=yes generates an ENFORCING server block
# (ssl_verify_client on against the DoD CA bundle); =no leaves those lines
# commented and uses optional_no_ca (the app falls back to ip:<addr> identity).
# WARNING: with mTLS off do NOT enable first-admin bootstrap - the "first user"
# could be an unauthenticated ip= identity.
ENABLE_MTLS="${ENABLE_MTLS:-no}"
DOD_CA_BUNDLE="${DOD_CA_BUNDLE:-/etc/pki/dod/dod-cas.pem}"

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
  "/home/ansible/issued|${SVC_USER}:${SVC_USER}|0750"
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
log "7/9  nginx: server block + fragment dir + self-signed cert (PKI placeholder)"
# ---------------------------------------------------------------------------
# nginx/30-csr.conf is a LOCATION FRAGMENT and must be included INSIDE a
# server{} block. deploy.sh installs it to $NGINX_INCLUDE_DIR (rcdn01.d). For a
# fresh/standalone box (no pre-existing server doing that include, e.g. rcdn01's
# conf.d/<host>.conf) we generate a standalone server block here that holds the
# TLS + CAC mTLS config and includes the fragment dir.
FQDN="$(hostname -f 2>/dev/null || hostname)"
install -d -m 0755 "$NGINX_INCLUDE_DIR"
if [[ ! -f "$CERT_DIR/server.crt" ]]; then
    install -d -m 0750 "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
        -subj "/CN=${FQDN}" \
        -addext "subjectAltName=DNS:${FQDN},DNS:$(hostname -s)" >/dev/null 2>&1
    chmod 0640 "$CERT_DIR/server.key"; chmod 0644 "$CERT_DIR/server.crt"
    echo "  generated self-signed cert for ${FQDN} (replace with real PKI for CAC mTLS)"
fi
# Build the CAC mTLS stanza per the ENABLE_MTLS choice. Enabled => enforcing;
# disabled => the enforcing lines are present but COMMENTED, with optional_no_ca
# active so the box still serves.
if [[ "${ENABLE_MTLS,,}" =~ ^(y|yes|true|1|on)$ ]]; then
    [[ -s "$DOD_CA_BUNDLE" ]] || warn "ENABLE_MTLS=yes but $DOD_CA_BUNDLE is missing/empty - nginx -t will fail until the DoD CA bundle is placed there"
    MTLS_STANZA="    # CAC mTLS ENFORCED (ENABLE_MTLS=yes). DoD chain depth: Root->Intermediate->CAC.
    ssl_client_certificate ${DOD_CA_BUNDLE};
    ssl_verify_client       on;
    ssl_verify_depth        3;"
    echo "  CAC mTLS: ENFORCED (ssl_verify_client on, CA bundle ${DOD_CA_BUNDLE})"
else
    MTLS_STANZA="    # CAC mTLS NOT enabled at install (ENABLE_MTLS=no). To enforce later: place
    # the DoD CA bundle at ${DOD_CA_BUNDLE}, uncomment the next two lines, and
    # remove the optional_no_ca line below, then: nginx -t && systemctl reload nginx
    #   ssl_client_certificate ${DOD_CA_BUNDLE};
    #   ssl_verify_client       on;
    ssl_verify_client optional_no_ca;
    ssl_verify_depth  3;"
    echo "  CAC mTLS: not enforced (optional_no_ca) - app uses ip:<addr> identity"
fi
SERVER_CONF=/etc/nginx/conf.d/csr-dashboard.conf
if [[ -f "$SERVER_CONF" ]] || grep -rqs "$NGINX_INCLUDE_DIR" /etc/nginx/conf.d; then
    echo "  a server block already includes ${NGINX_INCLUDE_DIR} - leaving nginx server config alone"
else
    cat > "$SERVER_CONF" <<NGINXCONF
# Standalone CSR Dashboard server block - generated by the installer for a
# fresh/air-gapped box. (On rcdn01 an equivalent block already exists in
# conf.d/<host>.conf and this file is NOT created.) TLS + CAC mTLS live HERE;
# the request routing is the location fragment in ${NGINX_INCLUDE_DIR}/30-csr.conf.
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${FQDN};

    ssl_certificate     ${CERT_DIR}/server.crt;
    ssl_certificate_key ${CERT_DIR}/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

${MTLS_STANZA}

    include ${NGINX_INCLUDE_DIR}/*.conf;
}
NGINXCONF
    echo "  generated standalone server block ${SERVER_CONF} (server_name ${FQDN})"
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
