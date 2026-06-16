#!/bin/bash
# make-offline-bundle.sh
#
# Builds a self-contained archive for deploying the CSR Dashboard to an
# AIR-GAPPED RHEL host. Run this on a CONNECTED box whose Python version
# and architecture MATCH THE OFFLINE TARGET (e.g. RHEL 9 / python3.9 /
# x86_64), because the downloaded wheels are version- and arch-specific.
#
# Produces:  csr-dashboard-offline-<version>.tar.gz
# containing: the repo code, a wheelhouse of all Python deps, this repo's
# requirements.txt, and the offline install script + docs.
#
# Usage (from the repo root on a connected box):
#   ./make-offline-bundle.sh
#
# Then: burn the tarball to disc, carry it across, and on the offline box
# follow OFFLINE-INSTALL.md.

set -euo pipefail
cd "$(dirname "$0")"

VERSION="$(cat VERSION 2>/dev/null || echo unknown)"
PYBIN="${PYBIN:-python3.9}"          # MUST match the offline target's python
STAGE="$(mktemp -d)"
BUNDLE="csr-dashboard-offline-${VERSION}"
OUT="${STAGE}/${BUNDLE}"

echo "=== Building offline bundle for v${VERSION} using ${PYBIN} ==="
command -v "$PYBIN" >/dev/null || { echo "ERROR: $PYBIN not found" >&2; exit 1; }

# F4: on a fapolicyd-enforcing STIG box, reading .py source as a non-root user
# is DENIED (the %languages open-deny rule), so the cp below fails with EPERM.
# This builder is meant to run on a CONNECTED box WITHOUT fapolicyd enforcing
# (it also needs pip + internet, which a STIG target lacks). Warn early.
if [[ $EUID -ne 0 ]] && command -v fapolicyd >/dev/null 2>&1 \
   && systemctl is-active --quiet fapolicyd 2>/dev/null; then
    echo "WARNING: fapolicyd is active and you are not root." >&2
    echo "  Reading .py source may be denied (EPERM). Build on a connected box" >&2
    echo "  without fapolicyd enforcing, or run this builder as root." >&2
fi

mkdir -p "$OUT"

# --- 1. the application code (everything deploy.sh manages, plus tooling) ---
echo "[1/4] copying application code..."
for item in VERSION deploy.sh gather.sh verify.sh README.md .gitlab-ci.yml \
            backend frontend helper systemd nginx tools config docs; do
    [[ -e "$item" ]] && cp -r "$item" "$OUT/" || echo "  (skip missing: $item)"
done

# --- 2. requirements.txt (pinned) ---
echo "[2/4] freezing requirements..."
if [[ -f requirements.txt ]]; then
    cp requirements.txt "$OUT/"
    echo "  using existing requirements.txt"
else
    # Minimal known deps; pin exact versions from the live venv if available.
    cat > "$OUT/requirements.txt" <<'REQ'
flask
gunicorn
REQ
    echo "  WARNING: no requirements.txt found - wrote minimal flask+gunicorn."
    echo "  For reproducibility, generate from the live venv instead:"
    echo "    /opt/csr-dashboard/venv/bin/pip freeze > requirements.txt"
fi

# --- 3. wheelhouse: download every wheel for offline pip install ---
echo "[3/4] downloading wheels (matching ${PYBIN})..."
mkdir -p "$OUT/wheelhouse"
# also stage pip/setuptools/wheel so the offline venv can bootstrap
"$PYBIN" -m pip download -d "$OUT/wheelhouse" pip setuptools wheel
"$PYBIN" -m pip download -d "$OUT/wheelhouse" -r "$OUT/requirements.txt"
echo "  wheels: $(ls "$OUT/wheelhouse" | wc -l) files"

# --- 4. install/ directory: one-shot installer + START_HERE variables -----
echo "[4/4] writing install/ directory (installer + START_HERE) + docs..."
mkdir -p "$OUT/install"

cat > "$OUT/install/START_HERE" <<'STARTHERE'
# ===========================================================================
#  START_HERE  -  edit these values for THIS deployment, then run:
#
#      cd install
#      sudo ./offline-install.sh
#
#  Lines are KEY="value". Email (SMG) is optional - leave SMG_HOST blank to
#  disable it. Domain/hostname have working defaults you can keep or change.
# ===========================================================================

# --- REQUIRED: this site's values ------------------------------------------

# This deployment's domain and hostname. The installer rewrites the bundled
# files to use these in place of the defaults (eucom.mil / nipat-pl-rcdn01):
#   - CSR_DOMAIN   = the domain appended to bare hostnames on cert requests
#                    (the helper's DOMAIN_SUFFIX) and shown in the UI.
#   - CSR_HOSTNAME = this server's short hostname, shown in UI titles and
#                    used to build the FQDN (CSR_HOSTNAME.CSR_DOMAIN).
CSR_DOMAIN="eucom.mil"
CSR_HOSTNAME="nipat-pl-rcdn01"

# SMG relay IP or hostname (the mail relay this server sends through).
# OPTIONAL: leave BLANK to disable email entirely (the dashboard works fine
# without notifications). If set, the relay must whitelist THIS server's IP.
SMG_HOST=""

# This server's dashboard URL (used in notification email links). If left
# blank the installer builds it from CSR_HOSTNAME.CSR_DOMAIN automatically.
DASHBOARD_URL=""

# From: address on outgoing notifications (only needed if SMG_HOST is set).
# The relay must accept this sender from this server's IP.
FROM_ADDRESS=""

# --- OPTIONAL: usually fine as-is ------------------------------------------

# Python interpreter on the target (must match the bundle's wheels).
PYBIN="python3.9"

# SMG port / timeout.
SMG_PORT="25"
SMG_TIMEOUT="10"

# Optional comma-separated Cc applied to every notification. Blank = none.
GLOBAL_CC=""

# CAC mTLS. "yes" => the generated nginx server block ENFORCES client certs
# (ssl_verify_client on) against the DoD CA bundle below. "no" => those lines
# are written COMMENTED and optional_no_ca is used so the box still serves
# (the app then sees ip:<addr> identities). WARNING: do NOT pair mTLS "no"
# with BOOTSTRAP_FIRST_ADMIN=1 (the "first user" could be an ip= identity).
ENABLE_MTLS="no"
DOD_CA_BUNDLE="/etc/pki/dod/dod-cas.pem"

# First-admin bootstrap: set to 1 to make the FIRST user to log in on the new
# (empty) database an admin automatically - convenient for initial stand-up.
# Self-disables once any user exists. Only enable if mTLS is verifying real
# CACs on this box (so "first user" is genuinely you). Otherwise leave 0 and
# use csr-bootstrap-admin after first login.
BOOTSTRAP_FIRST_ADMIN="0"

# --- DATA MIGRATION (optional) ---------------------------------------------

# To migrate an existing instance, set this to the path of a jobs.db you
# carried over (e.g. from `csrbackup` on the source box). It will be
# restored before first start. Leave BLANK for a fresh, empty database.
RESTORE_DB=""
STARTHERE

cat > "$OUT/install/offline-install.sh" <<'INSTALL'
#!/bin/bash
# offline-install.sh - one-shot offline installer for the CSR Dashboard.
#
# This script lives in the bundle's  install/  directory.
#
# FIRST-TIME SETUP (guided):
#     cd install
#     sudo ./offline-install.sh
#   With no answers file present, it walks you through a few prompts
#   (domain, hostname, optional email relay, etc.), shows a summary, then
#   installs. Each prompt explains itself and offers a sensible default.
#
# UNATTENDED / REPEATABLE:
#     sudo ./offline-install.sh --unattended
#   Reads install/START_HERE instead of prompting (for scripted deploys).
#
# Either way it then automates everything mechanical: the csrapi service
# account, all directories, the Python venv (from the bundled wheelhouse, no
# network), fapolicyd trust, config files written from your answers, optional
# data restore, and the app deploy. It STOPS with a clear message if an OS
# package or PKI prerequisite is missing - those cannot be scripted.
#
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PYBIN="${PYBIN:-python3.9}"
SVC_USER="csrapi"
log()  { echo -e "\n=== $* ==="; }
warn() { echo "  WARN: $*" >&2; }
die()  { echo "  ERROR: $*" >&2; exit 1; }

usage() {
    cat <<USAGE
CSR Dashboard offline installer

Usage:
  sudo ./offline-install.sh              Guided first-time setup (prompts for
                                         domain, hostname, optional email,
                                         CAC mTLS, first-admin, data restore),
                                         then installs.
  sudo ./offline-install.sh --unattended Read install/START_HERE instead of
                                         prompting (for scripted/repeatable
                                         deploys).
  ./offline-install.sh --help            Show this help.

What it does (both modes):
  Creates the csrapi service account, all directories and the sudoers
  drop-in, builds the Python venv from the bundled wheelhouse (no network),
  writes the config from your answers, optionally restores a database,
  generates the nginx server block (CAC mTLS enforced or not per your
  choice), refreshes fapolicyd trust, deploys the app, and starts the service.

  Email is OPTIONAL - leave the relay blank to run without notifications.

Cannot be scripted (you do these): install the enclave OS packages, the
PKI/CAC mTLS server certificate + DoD CA bundle, and - on a fresh database -
the first admin (unless first-login-admin is enabled during setup).
USAGE
}

UNATTENDED=false
case "${1:-}" in
    --help|-h) usage; exit 0 ;;
    --unattended) UNATTENDED=true ;;
    "") : ;;
    *) echo "unknown option: $1" >&2; echo "try --help" >&2; exit 2 ;;
esac

# root required for the actual install (but not for --help, handled above)
[[ $EUID -eq 0 ]] || { echo "run as root (or --help for usage)" >&2; exit 1; }

# --- prompt helpers --------------------------------------------------------
# ask VAR "Question text" "default" "explanation line(s)"
ask() {
    local __var="$1" __q="$2" __def="${3:-}" __help="${4:-}" __ans=""
    [[ -n "$__help" ]] && printf '  %s\n' "$__help"
    if [[ -n "$__def" ]]; then
        read -r -p "  ${__q} [${__def}]: " __ans
        __ans="${__ans:-$__def}"
    else
        read -r -p "  ${__q}: " __ans
    fi
    printf -v "$__var" '%s' "$__ans"
    echo
}
# ask_yn VAR "Question" "default(y/n)" "explanation"
ask_yn() {
    local __var="$1" __q="$2" __def="${3:-n}" __help="${4:-}" __ans=""
    [[ -n "$__help" ]] && printf '  %s\n' "$__help"
    read -r -p "  ${__q} [$( [[ $__def == y ]] && echo 'Y/n' || echo 'y/N')]: " __ans
    __ans="${__ans:-$__def}"
    case "$__ans" in [Yy]*) printf -v "$__var" '1';; *) printf -v "$__var" '0';; esac
    echo
}
# normalize a yes/no-ish value to 1/0
truthy() { [[ "${1:-}" =~ ^(1|[Yy]([Ee][Ss])?|[Tt][Rr][Uu][Ee]|[Oo][Nn])$ ]]; }

# --- gather configuration --------------------------------------------------
if $UNATTENDED; then
    [[ -f "$SCRIPT_DIR/START_HERE" ]] || die "--unattended needs install/START_HERE"
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/START_HERE"
    # map START_HERE's bootstrap var name to the internal one
    BOOTSTRAP_FIRST_ADMIN="${BOOTSTRAP_FIRST_ADMIN:-0}"
    ENABLE_MTLS="${ENABLE_MTLS:-no}"
    DOD_CA_BUNDLE="${DOD_CA_BUNDLE:-/etc/pki/dod/dod-cas.pem}"
    SMG_HOST="${SMG_HOST:-}"
    [[ "$SMG_HOST" == "CHANGEME" ]] && SMG_HOST=""   # treat placeholder as unset
else
    echo
    echo "=========================================================="
    echo "  CSR Dashboard - guided first-time setup"
    echo "  Answer the prompts below. Press Enter to accept a"
    echo "  [default]. This writes the config and then installs."
    echo "=========================================================="
    echo

    ask CSR_DOMAIN "Domain to append to bare hostnames" "eucom.mil" \
        "Bare cert names get this appended (e.g. 'web' -> 'web.<domain>')."
    ask CSR_HOSTNAME "This server's short hostname" "nipat-pl-rcdn01" \
        "Shown in UI titles; combined with the domain to form the FQDN."

    DASHBOARD_URL_DEFAULT="https://${CSR_HOSTNAME}.${CSR_DOMAIN}/csr/"
    ask DASHBOARD_URL "Dashboard URL" "$DASHBOARD_URL_DEFAULT" \
        "Used in notification email links. Usually the default is correct."

    echo "  ---- Email / SMG relay (OPTIONAL) ----"
    echo "  If this site has a mail relay (SMG) that will accept mail from"
    echo "  this server, enter it to enable expiry-warning emails. Leave"
    echo "  BLANK to disable email entirely - the dashboard works fine"
    echo "  without it (no notifications are sent)."
    echo
    ask SMG_HOST "SMG relay host or IP (blank = no email)" "" ""
    if [[ -n "$SMG_HOST" ]]; then
        ask SMG_PORT "SMG port" "25" "Plain SMTP port on the relay."
        ask FROM_ADDRESS "From: address for notifications" \
            "noreply-csr@${CSR_HOSTNAME}.${CSR_DOMAIN}" \
            "The relay must accept this sender from this server."
        ask GLOBAL_CC "Global Cc on all mail (optional, blank = none)" "" \
            "Comma-separated. Leave blank for none."
    else
        SMG_PORT=""; FROM_ADDRESS=""; GLOBAL_CC=""
        echo "  Email disabled - no relay configured."
        echo
    fi

    echo "  ---- CAC mTLS ----"
    ask_yn ENABLE_MTLS "Enforce CAC mTLS now (require a client cert)?" "n" \
        "Yes => the nginx server block REQUIRES a valid CAC (ssl_verify_client
  on) against the DoD CA bundle. Choose Yes only if you have the DoD CA
  bundle ready on this box. No => the box serves without requiring a client
  cert (the enforcing lines are written commented for you to enable later),
  and the app sees ip:<addr> identities."
    if [[ "$ENABLE_MTLS" == 1 ]]; then
        ask DOD_CA_BUNDLE "Path to the DoD CA bundle (PEM)" "/etc/pki/dod/dod-cas.pem" \
            "Concatenated DoD root+intermediate certs (strip CRLF). nginx -t
  will fail until this file is present."
    else
        DOD_CA_BUNDLE="${DOD_CA_BUNDLE:-/etc/pki/dod/dod-cas.pem}"
    fi

    ask_yn BOOTSTRAP_FIRST_ADMIN "Make the first user to log in an admin?" "n" \
        "Convenient for initial setup: the FIRST login on the empty database
  becomes admin (self-disables after). Only choose Yes if CAC mTLS is
  verifying real identities on this box - otherwise use csr-bootstrap-admin
  after logging in."
    if [[ "$BOOTSTRAP_FIRST_ADMIN" == 1 && "$ENABLE_MTLS" != 1 ]]; then
        warn "first-admin bootstrap WITHOUT mTLS: the first (possibly ip=) identity"
        warn "becomes admin. Prefer csr-bootstrap-admin, or enable mTLS."
    fi

    ask RESTORE_DB "Path to a database to restore (blank = fresh/empty)" "" \
        "Migrating an existing instance? Give the path to a jobs.db you
  carried over. Leave blank to start with a new empty database."

    SMG_TIMEOUT="${SMG_TIMEOUT:-10}"
    PYBIN="${PYBIN:-python3.9}"

    # --- confirm summary ---
    echo "=========================================================="
    echo "  Review:"
    echo "    Domain (suffix)   : ${CSR_DOMAIN}"
    echo "    Hostname          : ${CSR_HOSTNAME}"
    echo "    Dashboard URL     : ${DASHBOARD_URL}"
    if [[ -n "$SMG_HOST" ]]; then
        echo "    Email relay       : ${SMG_HOST}:${SMG_PORT}"
        echo "    From address      : ${FROM_ADDRESS}"
        echo "    Global Cc         : ${GLOBAL_CC:-<none>}"
    else
        echo "    Email             : DISABLED (no relay)"
    fi
    echo "    CAC mTLS          : $( [[ $ENABLE_MTLS == 1 ]] && echo "ENFORCED (${DOD_CA_BUNDLE})" || echo "not enforced (optional_no_ca)")"
    echo "    First-login admin : $( [[ $BOOTSTRAP_FIRST_ADMIN == 1 ]] && echo yes || echo no)"
    echo "    Restore database  : ${RESTORE_DB:-<fresh empty DB>}"
    echo "=========================================================="
    read -r -p "  Proceed with these settings? [y/N]: " __go
    case "${__go:-n}" in [Yy]*) : ;; *) echo "  Aborted - nothing changed."; exit 0;; esac
fi

# everything below operates on the extracted bundle
cd "$BUNDLE_ROOT"

# ---------------------------------------------------------------------------
log "0/9  Validating configuration"
# ---------------------------------------------------------------------------
: "${CSR_DOMAIN:=eucom.mil}"
: "${CSR_HOSTNAME:=nipat-pl-rcdn01}"
[[ -n "${DASHBOARD_URL:-}" ]] || DASHBOARD_URL="https://${CSR_HOSTNAME}.${CSR_DOMAIN}/csr/"
[[ "$DASHBOARD_URL" != *CHANGEME* ]] || die "DASHBOARD_URL not set"
ENABLE_MTLS="${ENABLE_MTLS:-no}"
DOD_CA_BUNDLE="${DOD_CA_BUNDLE:-/etc/pki/dod/dod-cas.pem}"
# Email is OPTIONAL: empty SMG_HOST = email disabled (valid).
if [[ -n "${SMG_HOST:-}" ]]; then
    [[ -n "${FROM_ADDRESS:-}" && "$FROM_ADDRESS" != *CHANGEME* ]] \
        || die "FROM_ADDRESS required when an SMG relay is set"
fi
echo "  domain=${CSR_DOMAIN} host=${CSR_HOSTNAME} email=$( [[ -n "${SMG_HOST:-}" ]] && echo "${SMG_HOST}" || echo disabled) mtls=$(truthy "$ENABLE_MTLS" && echo on || echo off)"

# ---------------------------------------------------------------------------
log "1/9  Checking OS prerequisites (from this enclave's repo)"
# ---------------------------------------------------------------------------
missing=()
command -v "$PYBIN"      >/dev/null || missing+=("$PYBIN")
command -v nginx         >/dev/null || missing+=("nginx")
command -v sqlite3       >/dev/null || missing+=("sqlite")
command -v openssl       >/dev/null || missing+=("openssl")
command -v restorecon    >/dev/null || missing+=("policycoreutils")
command -v fapolicyd-cli >/dev/null || warn "fapolicyd-cli absent - trust step skipped (OK if this host has no fapolicyd)"
(( ${#missing[@]} == 0 )) || die "install these first from the enclave repo: ${missing[*]}"
echo "  OK"

# ---------------------------------------------------------------------------
log "2/9  Service account: ${SVC_USER}"
# ---------------------------------------------------------------------------
if id "$SVC_USER" >/dev/null 2>&1; then
    echo "  exists - leaving as-is"
else
    useradd --system --no-create-home --shell /sbin/nologin \
            --comment "CSR Dashboard service account" "$SVC_USER"
    echo "  created"
fi
getent group nginx >/dev/null || warn "group 'nginx' missing - is nginx installed?"

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
    own="${og%%:*}"; grp="${og##*:}"
    getent group "$grp" >/dev/null 2>&1 || { warn "group $grp missing; using $own"; grp="$own"; }
    install -d -o "$own" -g "$grp" -m "$mode" "$d"
    echo "  $d ($own:$grp $mode)"
done
chmod o+x /home/ansible 2>/dev/null || warn "could not chmod /home/ansible - ensure csrapi can traverse it"

# ---------------------------------------------------------------------------
log "4/9  Sudoers drop-in"
# ---------------------------------------------------------------------------
SUDOERS=/etc/sudoers.d/csr-dashboard
if [[ -f "$SUDOERS" ]]; then
    echo "  exists - leaving as-is"
else
    printf '# CSR Dashboard: service account runs ONLY the helper as root.\n%s ALL=(root) NOPASSWD: /root/sslcerts/scripts/csr_dashboard_helper.sh\n' \
        "$SVC_USER" > "$SUDOERS"
    chmod 0440 "$SUDOERS"
    visudo -cf "$SUDOERS" >/dev/null || die "sudoers validation failed"
    echo "  wrote $SUDOERS"
fi

# ---------------------------------------------------------------------------
log "5/9  Python venv from bundled wheelhouse (offline)"
# ---------------------------------------------------------------------------
VENV=/opt/csr-dashboard/venv
[[ -x "$VENV/bin/python3" ]] || "$PYBIN" -m venv "$VENV"
[[ -d wheelhouse ]] || die "wheelhouse/ missing from bundle"
"$VENV/bin/pip" install --no-index --find-links wheelhouse --upgrade pip setuptools wheel
"$VENV/bin/pip" install --no-index --find-links wheelhouse -r requirements.txt
echo "  deps installed"

# CRITICAL: python -m venv creates the venv dir 0700 under root's STIG umask
# (077). That locks out the csrapi group, so the service cannot traverse into
# venv/ to exec gunicorn/python. Set group ownership AND traversal bits.
chown -R root:csrapi "$VENV"
chmod 0750 /opt/csr-dashboard
# group must READ all venv files (pyvenv.cfg + every site-packages .py are
# created 0600 under root umask 077) and TRAVERSE all dirs. g+rX does exactly
# that: read for files, and execute/search only where already set (dirs +
# executables). This is the correct generalization - the old find-based fix
# only covered executables and left pyvenv.cfg/modules unreadable (F10).
chmod -R g+rX "$VENV"
echo "  venv ownership/modes set for ${SVC_USER} (g+rX recursive)"

# Trust the freshly-created venv with fapolicyd, or the service cannot exec
# gunicorn/python on STIG hosts. deploy.sh later UPDATES trust for known
# files; the brand-new venv binaries must be ADDED here first.
if command -v fapolicyd-cli >/dev/null; then
    fapolicyd-cli --file add /opt/csr-dashboard/venv/ 2>/dev/null || true
    fapolicyd-cli --update 2>/dev/null || true
    echo "  fapolicyd: trusted /opt/csr-dashboard/venv/"
fi

# ---------------------------------------------------------------------------
log "6/9  Config files"
# ---------------------------------------------------------------------------
# email.conf - written from your answers. Empty host = email disabled, which
# the app honours (no notifications sent). Writing it either way keeps the
# file present and UI-manageable later.
cat > /etc/csr-dashboard/email.conf <<EMAILCONF
# /etc/csr-dashboard/email.conf  -  generated by offline-install
# Empty [smtp] host = email disabled. Set a relay here or via the admin UI.
[smtp]
host = ${SMG_HOST:-}
port = ${SMG_PORT:-25}
timeout = ${SMG_TIMEOUT:-10}

[from]
address = ${FROM_ADDRESS:-}

[recipients]
cc = ${GLOBAL_CC:-}

[content]
dashboard_url = ${DASHBOARD_URL}
EMAILCONF
chown "${SVC_USER}:${SVC_USER}" /etc/csr-dashboard/email.conf
chmod 0640 /etc/csr-dashboard/email.conf
if [[ -n "${SMG_HOST:-}" ]]; then
    echo "  wrote /etc/csr-dashboard/email.conf (relay ${SMG_HOST}:${SMG_PORT:-25})"
else
    echo "  wrote /etc/csr-dashboard/email.conf (email DISABLED - no relay)"
fi

# integrations.conf - present + csrapi-owned so the admin UI can rewrite it.
if [[ ! -f /etc/csr-dashboard/integrations.conf ]]; then
    printf '[gitlab]\nenabled = false\n' > /etc/csr-dashboard/integrations.conf
    chown "${SVC_USER}:${SVC_USER}" /etc/csr-dashboard/integrations.conf
    chmod 0640 /etc/csr-dashboard/integrations.conf
fi

# csr-dashboard.env - seed from example if absent (paths are defaults)
if [[ ! -f /etc/csr-dashboard/csr-dashboard.env && -f config/csr-dashboard.env.example ]]; then
    install -o "$SVC_USER" -g "$SVC_USER" -m 0640 \
        config/csr-dashboard.env.example /etc/csr-dashboard/csr-dashboard.env
    echo "  seeded /etc/csr-dashboard/csr-dashboard.env"
fi
# Reflect the START_HERE first-admin choice into the live env file (set or
# replace the line so the app picks it up). Only the value the operator chose.
if [[ -f /etc/csr-dashboard/csr-dashboard.env ]]; then
    want="${BOOTSTRAP_FIRST_ADMIN:-0}"
    if grep -q '^CSR_BOOTSTRAP_FIRST_ADMIN=' /etc/csr-dashboard/csr-dashboard.env; then
        sed -i "s/^CSR_BOOTSTRAP_FIRST_ADMIN=.*/CSR_BOOTSTRAP_FIRST_ADMIN=${want}/" \
            /etc/csr-dashboard/csr-dashboard.env
    else
        echo "CSR_BOOTSTRAP_FIRST_ADMIN=${want}" >> /etc/csr-dashboard/csr-dashboard.env
    fi
    echo "  first-admin bootstrap: CSR_BOOTSTRAP_FIRST_ADMIN=${want}"
fi

# ---------------------------------------------------------------------------
log "6.5/9  Rewriting domain/hostname in bundle files"
# ---------------------------------------------------------------------------
# Substitute the build-time defaults (eucom.mil / nipat-pl-rcdn01) with this
# deployment's values across the DEPLOYABLE files, before deploy.sh copies
# them live. Scoped to the specific files that carry these strings; skipped
# entirely if the operator left the defaults. Hostname is replaced first so
# the FQDN (host.domain) composes correctly, then the domain.
DEF_DOMAIN="eucom.mil"
DEF_HOST="nipat-pl-rcdn01"
if [[ "$CSR_DOMAIN" != "$DEF_DOMAIN" || "$CSR_HOSTNAME" != "$DEF_HOST" ]]; then
    files=(
        backend/app.py backend/notify.py
        frontend/app.js frontend/index.html
        helper/csr_dashboard_helper.d/00-common.sh
        nginx/30-csr.conf
    )
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        sed -i \
            -e "s/${DEF_HOST}/${CSR_HOSTNAME}/g" \
            -e "s/${DEF_DOMAIN//./\\.}/${CSR_DOMAIN}/g" \
            "$f"
    done
    echo "  rewrote -> host=${CSR_HOSTNAME} domain=${CSR_DOMAIN}"
else
    echo "  defaults unchanged - no rewrite needed"
fi

# ---------------------------------------------------------------------------
log "6.8/9  nginx server block (standalone box) + CAC mTLS"
# ---------------------------------------------------------------------------
# nginx/30-csr.conf is a LOCATION FRAGMENT (deploy.sh installs it under
# /etc/nginx/rcdn01.d). It must live inside a server{} block. On a site that
# already has one doing `include rcdn01.d/*.conf` (e.g. rcdn01) we leave nginx
# alone; on a fresh/air-gapped box we generate a standalone server block here.
# TLS + CAC mTLS live HERE.
NID=/etc/nginx/rcdn01.d
CERTDIR=/etc/pki/csr-dashboard
FQDN="${CSR_HOSTNAME}.${CSR_DOMAIN}"
install -d -m 0755 "$NID"
if [[ ! -f "$CERTDIR/server.crt" ]]; then
    install -d -m 0750 "$CERTDIR"
    if openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.crt" \
        -subj "/CN=${FQDN}" -addext "subjectAltName=DNS:${FQDN}" >/dev/null 2>&1; then
        chmod 0640 "$CERTDIR/server.key"; chmod 0644 "$CERTDIR/server.crt"
        echo "  generated self-signed placeholder cert for ${FQDN} (replace with the site cert)"
    else
        warn "openssl cert generation failed - place a real cert at $CERTDIR/server.{crt,key}"
    fi
fi
if truthy "$ENABLE_MTLS"; then
    [[ -s "$DOD_CA_BUNDLE" ]] || warn "ENABLE_MTLS=yes but $DOD_CA_BUNDLE missing/empty - nginx -t will fail until it is placed there"
    MTLS_STANZA="    # CAC mTLS ENFORCED. DoD chain: Root->Intermediate->CAC.
    ssl_client_certificate ${DOD_CA_BUNDLE};
    ssl_verify_client       on;
    ssl_verify_depth        3;"
    echo "  CAC mTLS: ENFORCED (CA bundle ${DOD_CA_BUNDLE})"
else
    MTLS_STANZA="    # CAC mTLS NOT enabled. To enforce later: place the DoD CA bundle at
    # ${DOD_CA_BUNDLE}, uncomment the next two lines, remove optional_no_ca,
    # then: nginx -t && systemctl reload nginx
    #   ssl_client_certificate ${DOD_CA_BUNDLE};
    #   ssl_verify_client       on;
    ssl_verify_client optional_no_ca;
    ssl_verify_depth  3;"
    echo "  CAC mTLS: not enforced (optional_no_ca) - app uses ip:<addr> identity"
fi
SERVER_CONF=/etc/nginx/conf.d/csr-dashboard.conf
if [[ -f "$SERVER_CONF" ]] || grep -rqs "$NID" /etc/nginx/conf.d; then
    echo "  a server block already includes ${NID} - leaving nginx server config alone"
else
    cat > "$SERVER_CONF" <<NGINXCONF
# Standalone CSR Dashboard server block (generated by offline-install for a
# fresh/air-gapped box). TLS + CAC mTLS live HERE; request routing is the
# location fragment in ${NID}/30-csr.conf. On rcdn01 an equivalent block
# already exists and this file is NOT created.
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${FQDN};

    ssl_certificate     ${CERTDIR}/server.crt;
    ssl_certificate_key ${CERTDIR}/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

${MTLS_STANZA}

    include ${NID}/*.conf;
}
NGINXCONF
    echo "  generated standalone server block ${SERVER_CONF} (server_name ${FQDN})"
fi
# SELinux: without this nginx is denied connecting to the gunicorn backend and
# every proxied request 502s.
if command -v getsebool >/dev/null && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
    setsebool -P httpd_can_network_connect 1 2>/dev/null \
        && echo "  setsebool httpd_can_network_connect=on (nginx -> backend)" \
        || warn "could not set httpd_can_network_connect - nginx->backend may 502"
fi
systemctl enable nginx >/dev/null 2>&1 || true
# Auto-publish the DoD CA bundle to the trust portal so clients can download
# it to build trust (CA cert only; the app validates + serves it).
if truthy "$ENABLE_MTLS" && [[ -s "$DOD_CA_BUNDLE" ]]; then
    install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 /var/lib/csr-dashboard/trust
    install -o "$SVC_USER" -g "$SVC_USER" -m 0644 "$DOD_CA_BUNDLE" \
        /var/lib/csr-dashboard/trust/dod-ca-bundle.crt 2>/dev/null \
        && echo "  published DoD CA bundle to the trust portal" || true
fi

# ---------------------------------------------------------------------------
log "7/9  Deploy code + optional data restore"
# ---------------------------------------------------------------------------
if [[ -n "${RESTORE_DB:-}" ]]; then
    [[ -f "$RESTORE_DB" ]] || die "RESTORE_DB set but file not found: $RESTORE_DB"
    install -o "$SVC_USER" -g "$SVC_USER" -m 0640 "$RESTORE_DB" /var/lib/csr-dashboard/jobs.db
    rm -f /var/lib/csr-dashboard/jobs.db-wal /var/lib/csr-dashboard/jobs.db-shm
    echo "  restored database from $RESTORE_DB"
fi
# Use -f (presence), not -x: the bundle preserves the build user's 0700 and
# under fapolicyd the script is run via `bash` (untrusted files can't exec by
# path). Calling `bash ./deploy.sh` keeps the whole chain fapolicyd-safe (F7/F8).
[[ -f ./deploy.sh ]] || die "deploy.sh missing in bundle root"
bash ./deploy.sh

# ---------------------------------------------------------------------------
log "8/9  PKI / mTLS check"
# ---------------------------------------------------------------------------
pki_ok=true
nginx -t >/dev/null 2>&1 || { warn "nginx -t fails - server cert / DoD CA bundle not in place yet"; pki_ok=false; }

# ---------------------------------------------------------------------------
log "9/9  Done"
# ---------------------------------------------------------------------------
echo ""
echo "==================================================================="
echo " Mechanical install COMPLETE for v$(cat VERSION 2>/dev/null || echo '?')."
echo "==================================================================="
if ! $pki_ok; then
cat <<MAN
 [ ] PKI: place this server's cert+key at ${CERTDIR}/server.{crt,key}$(truthy "$ENABLE_MTLS" && echo " and the DoD CA bundle at ${DOD_CA_BUNDLE}"). Then:
            nginx -t && systemctl reload nginx
MAN
fi
if [[ -z "${RESTORE_DB:-}" && "${BOOTSTRAP_FIRST_ADMIN:-0}" != "1" ]]; then
cat <<MAN
 [ ] ADMIN: fresh empty database - promote your CAC to admin:
            csr-bootstrap-admin "<YOUR CAC DN>"
MAN
fi
cat <<MAN
 Verify:
   systemctl status csr-api nginx
   curl -sk https://localhost/csr/api/health      # expect ok:true + version
===================================================================
MAN
INSTALL
chmod +x "$OUT/install/offline-install.sh"

cat > "$OUT/OFFLINE-INSTALL.md" <<DOC
# CSR Dashboard - Offline Install (v${VERSION})

This bundle installs the CSR Dashboard on an air-gapped RHEL host with no
network access. It contains the application code, a wheelhouse of all
Python dependencies, and this guide.

## Prerequisites on the target (from the enclave's own repo/Satellite)
Install these OS packages first (NOT included in this bundle unless your
enclave lacks them): \`${PYBIN}\`, \`nginx\`, \`sqlite\`, \`fapolicyd\`,
\`openssl\`, \`policycoreutils\` (restorecon), and \`sudo\`.

## Install (guided)
1. fapolicyd-safe launch (STIG hosts deny exec-by-path of untrusted files;
   running via \`bash\` avoids needing to trust the bundle):
\`\`\`bash
cd install
sudo bash ./offline-install.sh
\`\`\`
   The installer walks you through domain, hostname, optional email relay,
   **CAC mTLS (yes/no)**, first-admin, and optional DB restore, shows a
   summary, then installs. For scripted/repeatable deploys edit
   \`install/START_HERE\` and run \`sudo bash ./offline-install.sh --unattended\`.

2. What it does: creates the csrapi account, all directories + sudoers,
   builds the venv from the bundled wheelhouse (no network), writes
   email.conf/integrations.conf/csr-dashboard.env from your answers,
   **generates the nginx server block** (\`/etc/nginx/conf.d/csr-dashboard.conf\`)
   with CAC mTLS enforced or not per your choice, refreshes fapolicyd trust,
   deploys the code (\`bash ./deploy.sh\`), opens nothing on the firewall (see
   below), and starts the service. Idempotent.

## Remaining manual steps (the installer prints these)
- **firewalld**: the installer does NOT touch it. Open 443:
\`\`\`bash
firewall-cmd --permanent --add-service=https && firewall-cmd --reload
\`\`\`
- **PKI**: place this server's cert+key at
  \`/etc/pki/csr-dashboard/server.{crt,key}\`. If you chose CAC mTLS, put the
  DoD CA bundle (root+intermediate PEM, no CRLF) at the path you gave
  (default \`/etc/pki/dod/dod-cas.pem\`). Then \`nginx -t && systemctl reload nginx\`.
- **First admin** (fresh DB, if you did NOT enable first-login-admin):
\`\`\`bash
csr-bootstrap-admin "<YOUR CAC DN>"      # promotes a DN; no prior login needed
\`\`\`

## fapolicyd (STIG hosts)
deploy.sh refreshes trust for existing files; the FIRST install trusts the
venv (the installer does this). If you add NEW files under /opt/csr-dashboard
later: \`fapolicyd-cli --file add <file> && fapolicyd-cli --update\`.

## Build box requirements (where you run make-offline-bundle.sh)
This bundle must be BUILT on a connected box that has \`${PYBIN}\` + \`pip\` +
internet to PyPI (the target needs none of these - it installs from the
bundled wheelhouse), and is NOT fapolicyd-enforcing (or run the builder as
root), because fapolicyd denies non-root reads of .py source (F4/F5). The
build box must match the target's RHEL major / python / arch so the wheels
are compatible.

## Verify
\`\`\`bash
systemctl status csr-api nginx
curl -sk https://localhost/csr/api/health        # {"ok":true,"version":"${VERSION}"}
\`\`\`
The admin Overview tile should show v${VERSION}.

## Data migration (moving an existing instance)
On the SOURCE box: \`csrbackup\` (or copy /var/lib/csr-dashboard/jobs.db).
Carry it across; restore to /var/lib/csr-dashboard/jobs.db (owner
csrapi:csrapi) BEFORE first start, or pass its path at the restore prompt.
DOC

# --- archive ---
echo "=== packaging ==="
tar -C "$STAGE" -czf "${BUNDLE}.tar.gz" "$BUNDLE"
sha256sum "${BUNDLE}.tar.gz" > "${BUNDLE}.tar.gz.sha256"
rm -rf "$STAGE"

echo ""
echo "Built: ${BUNDLE}.tar.gz"
echo "       ${BUNDLE}.tar.gz.sha256   (verify on the far side before extracting)"
echo ""
echo "Burn both to disc. On the offline box: verify sha256, extract, follow"
echo "OFFLINE-INSTALL.md."
