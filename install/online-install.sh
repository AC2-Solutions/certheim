#!/bin/bash
# online-install.sh - interactive online installer for Certinel (CSR Dashboard).
#
# Use this on a CONNECTED, non-STIG box (no air-gap, pip+internet available) -
# a dev box or a fresh on-prem VM. It installs OS deps, the service account, the
# venv (from PyPI), nginx + a TLS cert, firewalld, then deploys the app.
#
# It is INTERACTIVE: on a TTY it walks you through the environment-specific
# variables (service account, FQDN/URL, TLS source, auth mode, email, OpenBao,
# license) and confirms before doing anything. Every prompt has a default and is
# overridable by an env var of the same name, so it also runs unattended:
#
#     sudo SERVICE_USER=certinel FQDN=cert.example.com \
#          DASHBOARD_URL=https://cert.example.com/csr/ ASSUME_DEFAULTS=yes \
#          ./install/online-install.sh
#
# It does NOT harden for STIG (no FIPS, no fapolicyd trust). For the air-gapped
# production target use the offline bundle workflow instead.
#
# Idempotent: safe to re-run. Run as root from the repo root.

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

log()  { echo -e "\n=== $* ==="; }
warn() { echo "  WARN: $*" >&2; }
die()  { echo "  ERROR: $*" >&2; exit 1; }

# Interactive unless stdin isn't a TTY or ASSUME_DEFAULTS=yes (CI / unattended).
interactive=true
[[ -t 0 && "${ASSUME_DEFAULTS:-no}" != "yes" ]] || interactive=false

# ask VAR "prompt" "default" : an env value (if already set) wins with no prompt;
# otherwise prompt on a TTY, else take the default.
ask() {
    local var="$1" prompt="$2" def="$3" ans
    [[ -n "${!var+x}" ]] && return 0
    if ! $interactive; then printf -v "$var" '%s' "$def"; return 0; fi
    read -r -e -p "  $prompt [$def]: " ans || true
    printf -v "$var" '%s' "${ans:-$def}"
}
# ask_secret VAR "prompt" : no-echo; env value wins; blank allowed.
ask_secret() {
    local var="$1" prompt="$2" ans
    [[ -n "${!var+x}" ]] && return 0
    if ! $interactive; then printf -v "$var" '%s' ""; return 0; fi
    read -r -s -p "  $prompt (hidden, blank to skip): " ans || true; echo
    printf -v "$var" '%s' "$ans"
}
is_yes() { [[ "${1,,}" =~ ^(y|yes|true|1|on)$ ]]; }

# ---------------------------------------------------------------------------
log "Certinel installer - environment configuration"
# ---------------------------------------------------------------------------
$interactive && echo "  (press Enter to accept each [default]; or pre-set any as an env var)"

# A. Identity & paths
ask SERVICE_USER  "Service account (the app runs as this user)" "csrapi"
ask SERVICE_GROUP "Service account group" "$SERVICE_USER"
ask PYBIN         "Python interpreter" "python3.12"

# B. Web & TLS
_def_fqdn="$(hostname -f 2>/dev/null || hostname)"
ask FQDN          "Server FQDN (TLS CN + nginx server_name)" "$_def_fqdn"
ask DASHBOARD_URL "Public base URL" "https://${FQDN}/csr/"
# TLS source: selfsigned (placeholder) | byo (bring cert+key) | stepca (ACME auto-renew)
ask TLS_MODE      "TLS cert source: selfsigned / byo / stepca" "selfsigned"
case "${TLS_MODE,,}" in
  byo)
    ask TLS_CERT_SRC "  path to your TLS certificate (PEM, leaf+chain)" "/etc/pki/tls/certs/${FQDN}.crt"
    ask TLS_KEY_SRC  "  path to your TLS private key (PEM)" "/etc/pki/tls/private/${FQDN}.key"
    ;;
  stepca)
    ask STEP_CA_URL         "  step-ca base URL" "https://ca.example.com"
    ask STEP_CA_FINGERPRINT "  step-ca root fingerprint" ""
    # Guard against a truncated/ellipsis paste: a step-ca root fingerprint is
    # exactly 64 hex chars (SHA-256). Reject anything else up front.
    STEP_CA_FINGERPRINT="${STEP_CA_FINGERPRINT//[[:space:]]/}"
    [[ "$STEP_CA_FINGERPRINT" =~ ^[0-9a-fA-F]{64}$ ]] \
        || die "step-ca fingerprint must be 64 hex chars (got: '${STEP_CA_FINGERPRINT}'). Get it with: step certificate fingerprint root_ca.crt"
    ask STEP_PROVISIONER    "  step-ca provisioner" "acme"
    ask_secret STEP_PROV_PASSWORD "  provisioner password (JWK provisioners only)"
    ;;
esac

# C. Authentication
# DOD_CA_BUNDLE is referenced by the nginx stanza in BOTH mTLS modes, so default
# it unconditionally (set -u would otherwise abort when mTLS is off).
DOD_CA_BUNDLE="${DOD_CA_BUNDLE:-/etc/pki/dod/dod-cas.pem}"
ask ENABLE_MTLS "Enable CAC/mTLS auth? (else local username/password)" "no"
if is_yes "$ENABLE_MTLS"; then
    ask DOD_CA_BUNDLE "  client-CA bundle path (mTLS verify)" "$DOD_CA_BUNDLE"
    AUTH_MODE=cac
else
    AUTH_MODE=local
fi

# D. Integrations (each skippable)
ask CONFIGURE_EMAIL "Configure outbound email now?" "no"
if is_yes "$CONFIGURE_EMAIL"; then
    ask SMG_HOST     "  SMTP host" "smtp.example.com"
    ask SMG_PORT     "  SMTP port" "25"
    ask FROM_ADDRESS "  From address" "noreply-certinel@example.com"
    ask GLOBAL_CC    "  global CC (optional)" ""
fi
ask CONFIGURE_OPENBAO "Wire OpenBao/Vault now? (signing/delivery/key storage)" "no"
if is_yes "$CONFIGURE_OPENBAO"; then
    ask CSR_OPENBAO_ADDR    "  OpenBao address" "https://openbao.example.com"
    ask CSR_OPENBAO_ROLE_ID "  AppRole role_id" ""
    ask_secret CSR_OPENBAO_SECRET_ID "  AppRole secret_id"
fi
ask LICENSE_FILE "License file to install (blank = Community edition)" ""

# Derived / fixed paths (internal identifiers kept per the rebrand).
CERT_DIR=/etc/pki/csr-dashboard
NGINX_INCLUDE_DIR=/etc/nginx/csr-dashboard.d
SMG_HOST="${SMG_HOST:-smtp.example.com}"; SMG_PORT="${SMG_PORT:-25}"
FROM_ADDRESS="${FROM_ADDRESS:-noreply-certinel@example.com}"; GLOBAL_CC="${GLOBAL_CC:-}"

echo
echo "  ---------------------------------------------------------------"
echo "  service account : ${SERVICE_USER}:${SERVICE_GROUP}"
echo "  python          : ${PYBIN}"
echo "  FQDN / URL      : ${FQDN}  ->  ${DASHBOARD_URL}"
echo "  TLS source      : ${TLS_MODE}"
echo "  auth mode       : ${AUTH_MODE}$(is_yes "$ENABLE_MTLS" && echo " (mTLS: ${DOD_CA_BUNDLE})")"
echo "  email           : $(is_yes "$CONFIGURE_EMAIL" && echo "${SMG_HOST}:${SMG_PORT}" || echo "(skip)")"
echo "  openbao         : $(is_yes "$CONFIGURE_OPENBAO" && echo "${CSR_OPENBAO_ADDR}" || echo "(skip)")"
echo "  license         : ${LICENSE_FILE:-Community}"
echo "  ---------------------------------------------------------------"
if $interactive; then
    read -r -e -p "  Proceed with these settings? (y/n) [y]: " _go || true
    is_yes "${_go:-y}" || die "aborted by operator"
fi

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
log "2/9  Service account: ${SERVICE_USER}:${SERVICE_GROUP}"
# ---------------------------------------------------------------------------
getent group "$SERVICE_GROUP" >/dev/null || groupadd --system "$SERVICE_GROUP"
id "$SERVICE_USER" >/dev/null 2>&1 \
    || useradd --system --no-create-home --shell /sbin/nologin \
               -g "$SERVICE_GROUP" --comment "Certinel service account" "$SERVICE_USER"
getent group nginx >/dev/null || die "nginx group missing - nginx install failed?"
echo "  ok"

# ---------------------------------------------------------------------------
log "3/9  Directories"
# ---------------------------------------------------------------------------
DIRS=(
  "/opt/csr-dashboard|root:${SERVICE_GROUP}|0750"
  "/var/lib/csr-dashboard|${SERVICE_USER}:${SERVICE_GROUP}|0750"
  "/var/www/csr|root:nginx|0750"
  "/etc/csr-dashboard|root:${SERVICE_GROUP}|0750"
  "/opt/certinel|root:root|0755"
  "/opt/certinel/helper|root:root|0750"
  "/opt/certinel/helper/csr_dashboard_helper.d|root:root|0750"
  "/var/opt/certinel|root:root|0755"
  "/var/opt/certinel/private|root:root|0700"
  "/var/opt/certinel/requests|root:${SERVICE_GROUP}|0750"
  "/var/opt/certinel/issued|${SERVICE_USER}:${SERVICE_GROUP}|0750"
)
for entry in "${DIRS[@]}"; do
    IFS='|' read -r d og mode <<< "$entry"
    install -d -o "${og%%:*}" -g "${og##*:}" -m "$mode" "$d"
done
# Record the operator's choices where deploy.sh can read them (service account).
cat > /etc/csr-dashboard/install.conf <<CONF
# Certinel install-time choices (read by deploy.sh). Managed by online-install.sh.
SERVICE_USER=${SERVICE_USER}
SERVICE_GROUP=${SERVICE_GROUP}
CONF
chmod 0644 /etc/csr-dashboard/install.conf
echo "  ok"

# ---------------------------------------------------------------------------
log "4/9  Sudoers drop-in (service account runs only the helper as root)"
# ---------------------------------------------------------------------------
SUDOERS=/etc/sudoers.d/csr-dashboard
printf '# Certinel: service account runs ONLY the helper as root.\n%s ALL=(root) NOPASSWD: /opt/certinel/helper/csr_dashboard_helper.sh\n' \
    "$SERVICE_USER" > "$SUDOERS"
chmod 0440 "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null || die "sudoers validation failed"
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
# The service group must read/traverse the whole venv to exec gunicorn/python
# (g+rX covers non-exec files a narrow "+x only" chmod misses - the STIG F10 fix).
chown -R "root:${SERVICE_GROUP}" "$VENV"
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
chown "${SERVICE_USER}:${SERVICE_GROUP}" /etc/csr-dashboard/email.conf
chmod 0640 /etc/csr-dashboard/email.conf

ENVF=/etc/csr-dashboard/csr-dashboard.env
if [[ ! -f "$ENVF" && -f config/csr-dashboard.env.example ]]; then
    install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0640 \
        config/csr-dashboard.env.example "$ENVF"
fi
# Helper to set a KEY=value in the env file (idempotent).
set_env() {
    local k="$1" v="$2"
    [[ -f "$ENVF" ]] || return 0
    if grep -q "^${k}=" "$ENVF"; then sed -i "s|^${k}=.*|${k}=${v}|" "$ENVF";
    else echo "${k}=${v}" >> "$ENVF"; fi
}
set_env CSR_AUTH_MODE "$AUTH_MODE"
if is_yes "${CONFIGURE_OPENBAO:-no}"; then
    set_env CSR_OPENBAO_ADDR "${CSR_OPENBAO_ADDR:-}"
    set_env CSR_OPENBAO_ROLE_ID "${CSR_OPENBAO_ROLE_ID:-}"
    set_env CSR_OPENBAO_SECRET_ID "${CSR_OPENBAO_SECRET_ID:-}"
    set_env CSR_CAP_OPENBAO 1
fi
[[ -n "${LICENSE_FILE:-}" && -r "$LICENSE_FILE" ]] && set_env CSR_LICENSE_FILE "$LICENSE_FILE"
# Local mode needs a persistent session signing key.
if [[ "$AUTH_MODE" == "local" && ! -s /etc/csr-dashboard/secret.key ]]; then
    openssl rand -hex 32 > /etc/csr-dashboard/secret.key
    chown "${SERVICE_USER}:${SERVICE_GROUP}" /etc/csr-dashboard/secret.key
    chmod 0640 /etc/csr-dashboard/secret.key
fi
echo "  ok (auth mode: ${AUTH_MODE})"

# ---------------------------------------------------------------------------
log "7/9  TLS certificate (${TLS_MODE}) + nginx server block"
# ---------------------------------------------------------------------------
install -d -m 0755 "$NGINX_INCLUDE_DIR"
install -d -m 0750 "$CERT_DIR"
setup_tls() {
    case "${TLS_MODE,,}" in
      byo)
        [[ -r "$TLS_CERT_SRC" && -r "$TLS_KEY_SRC" ]] || die "byo TLS: cert/key not readable ($TLS_CERT_SRC / $TLS_KEY_SRC)"
        install -m 0644 "$TLS_CERT_SRC" "$CERT_DIR/server.crt"
        install -m 0640 "$TLS_KEY_SRC"  "$CERT_DIR/server.key"
        echo "  installed bring-your-own cert for ${FQDN}"
        ;;
      stepca)
        if ! command -v step >/dev/null 2>&1; then
            dnf install -y step-cli 2>/dev/null || warn "could not install step-cli"
        fi
        command -v step >/dev/null 2>&1 || { warn "step CLI unavailable - falling back to self-signed"; TLS_MODE=selfsigned; setup_tls; return; }
        [[ -n "${STEP_CA_FINGERPRINT:-}" ]] || die "stepca TLS: STEP_CA_FINGERPRINT required"
        STEPPATH=/etc/step step ca bootstrap --ca-url "$STEP_CA_URL" \
            --fingerprint "$STEP_CA_FINGERPRINT" --install --force \
            || die "step ca bootstrap failed"
        local pwf="" pwflag=()
        if [[ -n "${STEP_PROV_PASSWORD:-}" ]]; then
            pwf="$(mktemp)"; printf '%s' "$STEP_PROV_PASSWORD" > "$pwf"
            pwflag=(--provisioner-password-file "$pwf")
        fi
        STEPPATH=/etc/step step ca certificate "$FQDN" \
            "$CERT_DIR/server.crt" "$CERT_DIR/server.key" \
            --provisioner "$STEP_PROVISIONER" "${pwflag[@]}" \
            --san "$FQDN" --force || { [[ -n "$pwf" ]] && rm -f "$pwf"; die "step ca certificate failed"; }
        [[ -n "$pwf" ]] && rm -f "$pwf"
        chmod 0640 "$CERT_DIR/server.key"; chmod 0644 "$CERT_DIR/server.crt"
        # Auto-renew: env file + timer (renews daily, reloads nginx).
        cat > /etc/default/certinel-tls-renew <<RENEW
CERT_LOCATION=$CERT_DIR/server.crt
KEY_LOCATION=$CERT_DIR/server.key
RENEW
        install -m 0644 systemd/certinel-tls-renew.service /etc/systemd/system/certinel-tls-renew.service
        install -m 0644 systemd/certinel-tls-renew.timer   /etc/systemd/system/certinel-tls-renew.timer
        systemctl daemon-reload
        systemctl enable --now certinel-tls-renew.timer
        echo "  issued step-ca cert for ${FQDN} + enabled daily auto-renew"
        ;;
      *)
        if [[ ! -f "$CERT_DIR/server.crt" ]]; then
            openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
                -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
                -subj "/CN=${FQDN}" \
                -addext "subjectAltName=DNS:${FQDN},DNS:$(hostname -s)" >/dev/null 2>&1
            chmod 0640 "$CERT_DIR/server.key"; chmod 0644 "$CERT_DIR/server.crt"
            echo "  generated self-signed cert for ${FQDN} (replace with real PKI later)"
        else
            echo "  cert already present - left as-is"
        fi
        ;;
    esac
}
setup_tls

# CAC mTLS stanza per ENABLE_MTLS (enabled => enforcing; disabled => commented + optional_no_ca).
if is_yes "$ENABLE_MTLS"; then
    [[ -s "$DOD_CA_BUNDLE" ]] || warn "ENABLE_MTLS=yes but $DOD_CA_BUNDLE is missing/empty - nginx -t will fail until placed"
    MTLS_STANZA="    ssl_client_certificate ${DOD_CA_BUNDLE};
    ssl_verify_client       on;
    ssl_verify_depth        3;"
    echo "  CAC mTLS: ENFORCED (CA bundle ${DOD_CA_BUNDLE})"
else
    MTLS_STANZA="    # CAC mTLS not enabled at install. To enforce later: place the DoD CA bundle
    # at ${DOD_CA_BUNDLE}, uncomment the next two lines, remove optional_no_ca, reload.
    #   ssl_client_certificate ${DOD_CA_BUNDLE};
    #   ssl_verify_client       on;
    ssl_verify_client optional_no_ca;
    ssl_verify_depth  3;"
    echo "  CAC mTLS: not enforced (optional_no_ca)"
fi
SERVER_CONF=/etc/nginx/conf.d/csr-dashboard.conf
if [[ -f "$SERVER_CONF" ]] || grep -rqs "$NGINX_INCLUDE_DIR" /etc/nginx/conf.d; then
    echo "  a server block already includes ${NGINX_INCLUDE_DIR} - leaving nginx server config alone"
else
    cat > "$SERVER_CONF" <<NGINXCONF
# Standalone Certinel server block - generated by the installer. TLS + CAC mTLS
# live HERE; request routing is the location fragment in ${NGINX_INCLUDE_DIR}.
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
# SELinux: nginx -> gunicorn backend (127.0.0.1) is denied unless this boolean is on.
if command -v getsebool >/dev/null && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
    setsebool -P httpd_can_network_connect 1
    echo "  setsebool httpd_can_network_connect=on"
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
systemctl enable certinel-api.service certinel-expiry-warn.timer certinel-auto-renew.timer >/dev/null 2>&1 || true
systemctl start certinel-expiry-warn.timer certinel-auto-renew.timer 2>/dev/null || true

echo ""
echo "==================================================================="
echo " Certinel online install COMPLETE for v$(cat VERSION 2>/dev/null || echo '?')"
echo "==================================================================="
echo " URL:     ${DASHBOARD_URL}"
echo " Verify:  curl -sk https://localhost/csr/api/health"
echo " Admin:   fresh DB has no admins. After one browser/API hit (local mode,"
echo "          all non-CAC users are ip:127.0.0.1):"
echo "            sqlite3 /var/lib/csr-dashboard/jobs.db \\"
echo "              \"UPDATE users SET is_admin=1,is_active=1 WHERE dn='ip:127.0.0.1'\""
echo "          systemctl restart certinel-api"
echo "==================================================================="
