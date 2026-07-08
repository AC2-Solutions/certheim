#!/bin/bash
# online-install.sh - interactive online installer for Certheim.
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

# cac_licensed: true iff the chosen LICENSE_FILE entitles CAC/mTLS (capability
# auth.cac - Government edition, or a Commercial add-on). Evaluated with the
# repo's stdlib-only licensing/capabilities modules so the installer only offers
# mTLS when the license allows it. Degrades to "not licensed" if no python yet.
cac_licensed() {
    local lf="${LICENSE_FILE:-}" py
    [[ -n "$lf" && -r "$lf" ]] || return 1
    py="$(command -v python3 || command -v "${PYBIN:-python3.12}" || true)"
    [[ -n "$py" ]] || return 1
    CSR_LICENSE_FILE="$lf" "$py" -c "import sys; sys.path.insert(0,'backend'); import capabilities; sys.exit(0 if capabilities.is_entitled('auth.cac') else 1)" 2>/dev/null
}

# ---------------------------------------------------------------------------
log "Certheim installer - environment configuration"
# ---------------------------------------------------------------------------
$interactive && echo "  (press Enter to accept each [default]; or pre-set any as an env var)"

# A. Identity & paths
ask SERVICE_USER  "Service account (the app runs as this user)" "certinel"
ask SERVICE_GROUP "Service account group" "$SERVICE_USER"
# Pick the best Python present (newest preferred; RHEL/Alma 9 only ships 3.9).
# Hardcoding python3.12 broke installs on el9 - detect instead of assume.
# A bare `command -v` match isn't enough: a name on PATH may be a dangling
# symlink or below our floor, so actually RUN each candidate and require >=3.9.
_default_py=python3
for _p in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    command -v "$_p" >/dev/null 2>&1 || continue
    "$_p" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,9) else 1)' \
        >/dev/null 2>&1 && { _default_py="$_p"; break; }
done
ask PYBIN         "Python interpreter" "$_default_py"

# A2. Database backend. SQLite (default, zero-config) or PostgreSQL (shared/HA).
ask DB_BACKEND    "Database backend: sqlite / postgres" "sqlite"
case "${DB_BACKEND,,}" in
  postgres|postgresql)
    DB_BACKEND=postgres
    ask CSR_DB_HOST     "  Postgres host" "localhost"
    ask CSR_DB_PORT     "  Postgres port" "5432"
    ask CSR_DB_NAME     "  Postgres database" "certinel"
    ask CSR_DB_USER     "  Postgres user" "certinel"
    ask CSR_DB_PASSWORD "  Postgres password" ""
    ask CSR_DB_SSLMODE  "  Postgres sslmode (disable/require/verify-full)" "require"
    ;;
  *) DB_BACKEND=sqlite ;;
esac

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
    # A step-ca root fingerprint is exactly 64 hex chars (SHA-256). Tolerate a
    # pasted annotation / 'sha256:' prefix / surrounding text by extracting the
    # first 64-hex token from whatever was entered, then validate it.
    _fp="$(printf '%s' "$STEP_CA_FINGERPRINT" | grep -oiE '[0-9a-f]{64}' | head -1 || true)"
    [[ -n "$_fp" ]] && STEP_CA_FINGERPRINT="$_fp"
    [[ "$STEP_CA_FINGERPRINT" =~ ^[0-9a-fA-F]{64}$ ]] \
        || die "step-ca fingerprint must contain 64 hex chars (got: '${STEP_CA_FINGERPRINT}'). Get it with: step certificate fingerprint root_ca.crt"
    ask STEP_PROVISIONER    "  step-ca provisioner" "acme"
    ask_secret STEP_PROV_PASSWORD "  provisioner password (JWK provisioners only)"
    ;;
esac

# C. Licensing + Authentication
# License first, so CAC/mTLS is only offered when the license entitles it.
ask LICENSE_FILE "License file to install (blank = Community edition)" ""
# CLIENT_CA_BUNDLE is referenced by the nginx stanza in BOTH mTLS modes, so default
# it unconditionally (set -u would otherwise abort when mTLS is off).
CLIENT_CA_BUNDLE="${CLIENT_CA_BUNDLE:-/etc/pki/dod/dod-cas.pem}"
if cac_licensed; then
    ask ENABLE_MTLS "Enable CAC/mTLS auth? (else local username/password)" "no"
else
    is_yes "${ENABLE_MTLS:-no}" && warn "CAC/mTLS is not licensed - using local auth (enable later in the UI after a license upgrade)"
    ENABLE_MTLS=no
    $interactive && echo "  Auth: local user/pass. CAC/mTLS is a licensed feature (Government edition, or a Commercial CAC add-on) - apply a license later and enable it in Admin -> Authentication."
fi
if is_yes "$ENABLE_MTLS"; then
    ask CLIENT_CA_BUNDLE "  client-CA bundle path (mTLS verify)" "$CLIENT_CA_BUNDLE"
    AUTH_MODE=mtls        # the app stores the setting as 'mtls' or 'local'
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

# Derived / fixed paths (internal identifiers kept per the rebrand).
CERT_DIR=/etc/pki/certinel
NGINX_INCLUDE_DIR=/etc/nginx/certinel.d
SMG_HOST="${SMG_HOST:-smtp.example.com}"; SMG_PORT="${SMG_PORT:-25}"
FROM_ADDRESS="${FROM_ADDRESS:-noreply-certinel@example.com}"; GLOBAL_CC="${GLOBAL_CC:-}"

echo
echo "  ---------------------------------------------------------------"
echo "  service account : ${SERVICE_USER}:${SERVICE_GROUP}"
echo "  python          : ${PYBIN}"
echo "  FQDN / URL      : ${FQDN}  ->  ${DASHBOARD_URL}"
echo "  TLS source      : ${TLS_MODE}"
echo "  auth mode       : ${AUTH_MODE}$(is_yes "$ENABLE_MTLS" && echo " (mTLS: ${CLIENT_CA_BUNDLE})")"
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
               -g "$SERVICE_GROUP" --comment "Certheim service account" "$SERVICE_USER"
getent group nginx >/dev/null || die "nginx group missing - nginx install failed?"
echo "  ok"

# ---------------------------------------------------------------------------
log "3/9  Directories"
# ---------------------------------------------------------------------------
DIRS=(
  "/opt/certinel|root:${SERVICE_GROUP}|0750"
  "/var/lib/certinel|${SERVICE_USER}:${SERVICE_GROUP}|0750"
  "/var/www/csr|root:nginx|0750"
  "/etc/certinel|root:${SERVICE_GROUP}|0750"
  "/opt/certinel/helper|root:root|0750"
  "/opt/certinel/helper/certinel_helper.d|root:root|0750"
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
cat > /etc/certinel/install.conf <<CONF
# Certheim install-time choices (read by deploy.sh). Managed by online-install.sh.
SERVICE_USER=${SERVICE_USER}
SERVICE_GROUP=${SERVICE_GROUP}
CONF
chmod 0644 /etc/certinel/install.conf
echo "  ok"

# ---------------------------------------------------------------------------
log "4/9  Sudoers drop-in (service account runs only the helper as root)"
# ---------------------------------------------------------------------------
SUDOERS=/etc/sudoers.d/certinel
printf '# Certheim: service account runs ONLY the helper as root.\n%s ALL=(root) NOPASSWD: /opt/certinel/helper/certinel_helper.sh\n' \
    "$SERVICE_USER" > "$SUDOERS"
chmod 0440 "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null || die "sudoers validation failed"
echo "  ok"

# ---------------------------------------------------------------------------
log "5/9  Python venv"
# ---------------------------------------------------------------------------
VENV=/opt/certinel/venv
[[ -x "$VENV/bin/python3" ]] || "$PYBIN" -m venv "$VENV"
# Prefer an offline wheelhouse when one ships alongside the repo (the RPM/offline
# bundle drop a wheelhouse/ dir here); this lets the install run air-gapped with
# no PyPI reach. CERTINEL_WHEELHOUSE overrides the location. When absent we fall
# back to installing from PyPI as before. PIP_OFFLINE holds the shared flags so
# the base and postgres installs stay consistent.
WHEELHOUSE="${CERTINEL_WHEELHOUSE:-$(pwd)/wheelhouse}"
PIP_OFFLINE=()
if [[ -d "$WHEELHOUSE" ]] && compgen -G "$WHEELHOUSE/*.whl" >/dev/null 2>&1; then
    PIP_OFFLINE=(--no-index --find-links "$WHEELHOUSE")
    echo "  using offline wheelhouse: $WHEELHOUSE"
    "$VENV/bin/pip" install "${PIP_OFFLINE[@]}" --upgrade pip setuptools wheel 2>/dev/null || true
else
    "$VENV/bin/pip" install --upgrade pip setuptools wheel
fi
# pip_reqs: install a requirements file, preferring the offline wheelhouse but
# falling back to PyPI if the offline pass fails. A wheelhouse carries some
# compiled, CPython-version-specific wheels (e.g. markupsafe), so a wheelhouse
# built for a different python than this host's needs the online fallback (or,
# for a true air-gap, a wheelhouse built to match the target python — as the
# offline bundle documents). Returns pip's exit status of the last attempt.
pip_reqs() {
    if [[ ${#PIP_OFFLINE[@]} -gt 0 ]]; then
        "$VENV/bin/pip" install "${PIP_OFFLINE[@]}" -r "$1" && return 0
        warn "offline wheelhouse install of $1 failed (python/arch mismatch?) - retrying from PyPI"
    fi
    "$VENV/bin/pip" install -r "$1"
}
if ! pip_reqs requirements.txt; then
    warn "pinned requirements.txt failed on $PYBIN - retrying with core deps unpinned"
    "$VENV/bin/pip" install flask gunicorn
fi
# The Postgres backend needs psycopg (kept out of the base wheelhouse so SQLite
# installs stay slim). requirements-postgres.txt pins it; pip_reqs pulls it from
# PyPI (the wheelhouse omits it).
if [[ "$DB_BACKEND" == "postgres" ]]; then
    pip_reqs requirements-postgres.txt \
        || die "psycopg install failed - cannot use the postgres backend"
fi
# The service group must read/traverse the whole venv to exec gunicorn/python
# (g+rX covers non-exec files a narrow "+x only" chmod misses - the STIG F10 fix).
chown -R "root:${SERVICE_GROUP}" "$VENV"
chmod 0750 /opt/certinel "$VENV" "$VENV/bin"
chmod -R g+rX "$VENV"
# Trust the freshly-created venv with fapolicyd, or the service cannot exec
# gunicorn/python on STIG hosts. deploy.sh later UPDATES trust for known files;
# the brand-new venv binaries must be ADDED here first. (The offline installer
# already does this - keep the two install paths in lockstep.)
if command -v fapolicyd-cli >/dev/null 2>&1; then
    fapolicyd-cli --file add "$VENV/" 2>/dev/null \
        || fapolicyd-cli --file update "$VENV/" 2>/dev/null || true
    fapolicyd-cli --update 2>/dev/null || true
    echo "  fapolicyd: trusted $VENV/"
fi
echo "  venv ready"

# ---------------------------------------------------------------------------
log "6/9  Config files"
# ---------------------------------------------------------------------------
cat > /etc/certinel/email.conf <<EMAILCONF
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
chown "${SERVICE_USER}:${SERVICE_GROUP}" /etc/certinel/email.conf
chmod 0640 /etc/certinel/email.conf

ENVF=/etc/certinel/certinel.env
if [[ ! -f "$ENVF" && -f config/certinel.env.example ]]; then
    install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0640 \
        config/certinel.env.example "$ENVF"
fi
# Helper to set a KEY=value in the env file (idempotent).
set_env() {
    local k="$1" v="$2"
    [[ -f "$ENVF" ]] || return 0
    if grep -q "^${k}=" "$ENVF"; then sed -i "s|^${k}=.*|${k}=${v}|" "$ENVF";
    else echo "${k}=${v}" >> "$ENVF"; fi
}
# NOTE: the live auth mode is the app_settings 'auth_mode' row (seeded after
# deploy, below) - NOT this env var, which the app does not read. Kept only as a
# record of the install-time choice.
set_env CSR_AUTH_MODE "$AUTH_MODE"
# Database backend. For postgres, CSR_DB_BACKEND=postgres makes the app select
# PG regardless of the (ignored) CSR_DB_PATH; the discrete CSR_DB_* parts build
# the libpq DSN. SQLite is the default and needs no extra env (CSR_DB_PATH is
# already in the example).
if [[ "$DB_BACKEND" == "postgres" ]]; then
    set_env CSR_DB_BACKEND  postgres
    set_env CSR_DB_HOST     "$CSR_DB_HOST"
    set_env CSR_DB_PORT     "$CSR_DB_PORT"
    set_env CSR_DB_NAME     "$CSR_DB_NAME"
    set_env CSR_DB_USER     "$CSR_DB_USER"
    set_env CSR_DB_PASSWORD "$CSR_DB_PASSWORD"
    set_env CSR_DB_SSLMODE  "$CSR_DB_SSLMODE"
fi
# First-admin OOBE: the first user to authenticate on an empty users table is
# made admin (self-disables once any user exists), so a fresh box has a way in -
# the first self-registered local user, or the first CAC user in mTLS mode.
set_env CSR_BOOTSTRAP_FIRST_ADMIN 1
if is_yes "${CONFIGURE_OPENBAO:-no}"; then
    set_env CSR_OPENBAO_ADDR "${CSR_OPENBAO_ADDR:-}"
    set_env CSR_OPENBAO_ROLE_ID "${CSR_OPENBAO_ROLE_ID:-}"
    set_env CSR_OPENBAO_SECRET_ID "${CSR_OPENBAO_SECRET_ID:-}"
    set_env CSR_CAP_OPENBAO 1
fi
[[ -n "${LICENSE_FILE:-}" && -r "$LICENSE_FILE" ]] && set_env CSR_LICENSE_FILE "$LICENSE_FILE"
# Local mode needs a persistent session signing key.
if [[ "$AUTH_MODE" == "local" && ! -s /etc/certinel/secret.key ]]; then
    openssl rand -hex 32 > /etc/certinel/secret.key
    chown "${SERVICE_USER}:${SERVICE_GROUP}" /etc/certinel/secret.key
    chmod 0640 /etc/certinel/secret.key
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

# Client-cert (mTLS) verification is APP-MANAGED: write it as a dedicated
# include-dir fragment (Admin -> Authentication re-renders this via the helper).
# The server block holds only TLS + the include, so there's never a duplicate
# ssl_verify_client. MTLS_MODE_SEED is seeded into app_settings after deploy.
if is_yes "$ENABLE_MTLS"; then
    [[ -s "$CLIENT_CA_BUNDLE" ]] || warn "ENABLE_MTLS=yes but $CLIENT_CA_BUNDLE is missing/empty - nginx -t will fail until the bundle is placed there"
    printf '# managed by Certheim (Admin -> Authentication)\nssl_client_certificate %s;\nssl_verify_client on;\nssl_verify_depth 3;\n' \
        "$CLIENT_CA_BUNDLE" > "$NGINX_INCLUDE_DIR/10-mtls.conf"
    MTLS_MODE_SEED=enforce
    echo "  CAC mTLS: ENFORCED (CA bundle ${CLIENT_CA_BUNDLE})"
else
    # mTLS disabled: client certs OFF (not optional). Seeding 'optional' here
    # left unlicensed boxes with mtls_mode=optional, which then tripped the
    # CAC-license gate on every unrelated Admin -> Authentication save.
    printf '# managed by Certheim (Admin -> Authentication)\nssl_verify_client off;\n' \
        > "$NGINX_INCLUDE_DIR/10-mtls.conf"
    MTLS_MODE_SEED=off
    echo "  CAC mTLS: off (local auth) - enable later in Admin -> Authentication"
fi
chmod 0644 "$NGINX_INCLUDE_DIR/10-mtls.conf"
SERVER_CONF=/etc/nginx/conf.d/certinel.conf
if [[ -f "$SERVER_CONF" ]] || grep -rqs "$NGINX_INCLUDE_DIR" /etc/nginx/conf.d; then
    echo "  a server block already includes ${NGINX_INCLUDE_DIR} - leaving nginx server config alone"
else
    cat > "$SERVER_CONF" <<NGINXCONF
# Standalone Certheim server block - generated by the installer. TLS lives HERE;
# request routing + client-cert (mTLS) verification are include-dir fragments in
# ${NGINX_INCLUDE_DIR} (10-mtls.conf is app-managed via Admin -> Authentication).
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${FQDN};

    ssl_certificate     ${CERT_DIR}/server.crt;
    ssl_certificate_key ${CERT_DIR}/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # --- security hardening (applies to every response via 'always') ---
    server_tokens off;                                            # don't leak the nginx version
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Frame-Options           "DENY"    always;
    add_header Referrer-Policy           "no-referrer" always;

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

# Seed the auth + mTLS choices into app_settings (the LIVE source of truth the
# app reads - auth_mode() = get_setting('auth_mode') or 'mtls'). Without this a
# fresh DB defaults to mtls/CAC regardless of what was chosen. Local mode also
# opens self-registration so the first-admin bootstrap has something to register.
# Backend-agnostic: route through the app's own db layer (app.set_setting +
# init_db handle sqlite AND postgres), not the sqlite3 CLI - so this works the
# same on a Postgres install. Reads the DB target from the env file we wrote.
if [[ -r "$ENVF" ]]; then set -a; . "$ENVF" 2>/dev/null || true; set +a; fi
if REPO_ROOT="$REPO_ROOT" AUTH_MODE="$AUTH_MODE" MTLS_MODE_SEED="$MTLS_MODE_SEED" \
   CLIENT_CA_BUNDLE="$CLIENT_CA_BUNDLE" \
   "$VENV/bin/python" - <<'PY'
import os, sys
sys.path.insert(0, os.path.join(os.environ["REPO_ROOT"], "backend"))
import app
app.init_db()  # idempotent: guarantees app_settings exists on either backend
rows = [("auth_mode", os.environ["AUTH_MODE"]),
        ("mtls_mode", os.environ["MTLS_MODE_SEED"]),
        ("mtls_ca_bundle_path", os.environ["CLIENT_CA_BUNDLE"])]
if os.environ["AUTH_MODE"] == "local":
    rows.append(("allow_registration", "1"))
for k, v in rows:
    app.set_setting(k, v)
import db as dbx
print("  seeded %d settings into %s" % (len(rows), dbx.backend()))
PY
then
    [[ "$DB_BACKEND" == "sqlite" ]] && \
        chown "${SERVICE_USER}:${SERVICE_GROUP}" /var/lib/certinel/jobs.db 2>/dev/null || true
    # deploy.sh started the service BEFORE this seed - restart so it reads the
    # seeded auth_mode/registration settings.
    systemctl try-restart certinel-api.service 2>/dev/null || true
else
    warn "app_settings seed failed - set auth_mode (and allow_registration) in the admin UI"
fi

# Post-install self-check: surface CHDIR/exec/SELinux/502/auth-gate/TLS issues
# now, instead of when the operator first hits the login page. Non-fatal.
echo ""
log "Post-install health check (certinel-doctor)"
bash "$REPO_ROOT/tools/certinel-doctor.sh" || warn "certinel-doctor reported problems above - review before using this host"

echo ""
echo "==================================================================="
echo " Certheim online install COMPLETE for v$(cat VERSION 2>/dev/null || echo '?')"
echo "==================================================================="
echo " URL:      ${DASHBOARD_URL}"
echo " Verify:   curl -sk https://localhost/csr/api/health"
if [[ "$AUTH_MODE" == "local" ]]; then
echo " Sign in:  open ${DASHBOARD_URL} -> Register and create your account."
echo "           The first account becomes admin automatically; then turn"
echo "           registration off in Admin -> Authentication."
else
echo " Sign in:  CAC mode - the first CAC user to authenticate becomes admin"
echo "           (bootstrap, self-disabling). Ensure CAC verification works."
fi
echo "==================================================================="
