#!/bin/bash
# make-offline-bundle.sh
#
# Builds a self-contained archive for deploying the Certheim to an
# AIR-GAPPED RHEL host. Run this on a CONNECTED box whose Python version
# and architecture MATCH THE OFFLINE TARGET (e.g. RHEL 9 / python3.9 /
# x86_64), because the downloaded wheels are version- and arch-specific.
#
# Produces:  certheim-offline-<version>.tar.gz
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

# The offline bundle is the Community/base build, so read the community edition
# version (falling back to the materialized root VERSION, then "unknown").
VERSION="$(cat editions/community.version 2>/dev/null || cat VERSION 2>/dev/null || echo unknown)"
# Build the wheelhouse with the best Python on THIS host (>=3.9), not a
# hardcoded 3.9 - an Alma 9 box updated to 3.12 would otherwise get a 3.9
# wheelhouse it can't load. The generated target scripts default to the exact
# X.Y we pick here (see PYVER below) so the target's venv matches these wheels.
_probe_py() {
    local p
    for p in python3.13 python3.12 python3.11 python3.10 python3.9; do
        command -v "$p" >/dev/null 2>&1 || continue
        "$p" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,9) else 1)' \
            >/dev/null 2>&1 && { echo "$p"; return 0; }
    done
    command -v python3 >/dev/null 2>&1 && { echo python3; return 0; }
    return 1
}
PYBIN="${PYBIN:-$(_probe_py)}" || { echo "ERROR: no suitable python3 (>=3.9) on build host" >&2; exit 1; }
STAGE="$(mktemp -d)"
BUNDLE="certheim-offline-${VERSION}"
OUT="${STAGE}/${BUNDLE}"

echo "=== Building offline bundle for v${VERSION} using ${PYBIN} ==="
command -v "$PYBIN" >/dev/null || { echo "ERROR: $PYBIN not found" >&2; exit 1; }
# Canonical pythonX.Y the wheelhouse is built for; baked into the target scripts.
PYVER="$("$PYBIN" -c 'import sys;print("python%d.%d"%sys.version_info[:2])')"

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
for item in VERSION deploy.sh gather.sh verify.sh README.md .gitignore .gitlab-ci.yml \
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
    echo "    /opt/certheim/venv/bin/pip freeze > requirements.txt"
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
# files to use these in place of the defaults (example.com / certinel-host):
#   - CERTHEIM_DOMAIN   = the domain appended to bare hostnames on cert requests
#                    (the helper's DOMAIN_SUFFIX) and shown in the UI.
#   - CERTHEIM_HOSTNAME = this server's short hostname, shown in UI titles and
#                    used to build the FQDN (CERTHEIM_HOSTNAME.CERTHEIM_DOMAIN).
CERTHEIM_DOMAIN="example.com"
CERTHEIM_HOSTNAME="certinel-host"

# SMG relay IP or hostname (the mail relay this server sends through).
# OPTIONAL: leave BLANK to disable email entirely (the dashboard works fine
# without notifications). If set, the relay must whitelist THIS server's IP.
SMG_HOST=""

# This server's dashboard URL (used in notification email links). If left
# blank the installer builds it from CERTHEIM_HOSTNAME.CERTHEIM_DOMAIN automatically.
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

# First-admin bootstrap: set to 1 to make the FIRST user to log in on the new
# (empty) database an admin automatically - convenient for initial stand-up.
# Self-disables once any user exists. Only enable if mTLS is verifying real
# CACs on this box (so "first user" is genuinely you). Otherwise leave 0 and
# use certheim-bootstrap-admin after first login.
BOOTSTRAP_FIRST_ADMIN="0"

# Authentication mode: "mtls" (CAC, default) or "local" (username/password,
# for environments without CAC tokens). If local, set the trusted email
# domain for self-registration (blank = self-reg disabled) and whether new
# accounts need admin approval.
AUTH_MODE="mtls"
TRUSTED_EMAIL_DOMAIN=""
REQUIRE_APPROVAL="0"

# --- DATA MIGRATION (optional) ---------------------------------------------

# To migrate an existing instance, set this to the path of a jobs.db you
# carried over (e.g. from `certheim-backup` on the source box). It will be
# restored before first start. Leave BLANK for a fresh, empty database.
RESTORE_DB=""
STARTHERE

cat > "$OUT/install/offline-install.sh" <<'INSTALL'
#!/bin/bash
# offline-install.sh - one-shot offline installer for the Certheim.
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
# Either way it then automates everything mechanical: the certheim service
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
SVC_USER="certheim"
log()  { echo -e "\n=== $* ==="; }
warn() { echo "  WARN: $*" >&2; }
die()  { echo "  ERROR: $*" >&2; exit 1; }

usage() {
    cat <<USAGE
Certheim offline installer

Usage:
  sudo ./offline-install.sh              Guided first-time setup (prompts for
                                         domain, hostname, optional email,
                                         first-admin, data restore), then
                                         installs.
  sudo ./offline-install.sh --unattended Read install/START_HERE instead of
                                         prompting (for scripted/repeatable
                                         deploys).
  ./offline-install.sh --help            Show this help.

What it does (both modes):
  Creates the certheim service account, all directories and the sudoers
  drop-in, builds the Python venv from the bundled wheelhouse (no network),
  writes the config from your answers, optionally restores a database,
  refreshes fapolicyd trust, deploys the app, and starts the service.

  Email is OPTIONAL - leave the relay blank to run without notifications.

Cannot be scripted (you do these): install the enclave OS packages, the
PKI/CAC mTLS certificates, and - on a fresh database - the first admin
(unless first-login-admin is enabled during setup).
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

# --- gather configuration --------------------------------------------------
if $UNATTENDED; then
    [[ -f "$SCRIPT_DIR/START_HERE" ]] || die "--unattended needs install/START_HERE"
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/START_HERE"
    # map START_HERE's bootstrap var name to the internal one
    BOOTSTRAP_FIRST_ADMIN="${BOOTSTRAP_FIRST_ADMIN:-0}"
    SMG_HOST="${SMG_HOST:-}"
    [[ "$SMG_HOST" == "CHANGEME" ]] && SMG_HOST=""   # treat placeholder as unset
    # auth mode from START_HERE (default mtls). AUTH_MODE=local enables
    # username/password; TRUSTED_EMAIL_DOMAIN + REQUIRE_APPROVAL apply then.
    AUTH_MODE="${AUTH_MODE:-mtls}"
    TRUSTED_EMAIL_DOMAIN="${TRUSTED_EMAIL_DOMAIN:-}"
    REQUIRE_APPROVAL="${REQUIRE_APPROVAL:-0}"
else
    echo
    echo "=========================================================="
    echo "  Certheim - guided first-time setup"
    echo "  Answer the prompts below. Press Enter to accept a"
    echo "  [default]. This writes the config and then installs."
    echo "=========================================================="
    echo

    ask CERTHEIM_DOMAIN "Domain to append to bare hostnames" "example.com" \
        "Bare cert names get this appended (e.g. 'web' -> 'web.<domain>')."
    ask CERTHEIM_HOSTNAME "This server's short hostname" "certinel-host" \
        "Shown in UI titles; combined with the domain to form the FQDN."

    DASHBOARD_URL_DEFAULT="https://${CERTHEIM_HOSTNAME}.${CERTHEIM_DOMAIN}/csr/"
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
            "noreply-csr@${CERTHEIM_HOSTNAME}.${CERTHEIM_DOMAIN}" \
            "The relay must accept this sender from this server."
        ask GLOBAL_CC "Global Cc on all mail (optional, blank = none)" "" \
            "Comma-separated. Leave blank for none."
    else
        SMG_PORT=""; FROM_ADDRESS=""; GLOBAL_CC=""
        echo "  Email disabled - no relay configured."
        echo
    fi

    echo "  ---- Authentication mode ----"
    echo "  This host can authenticate users by CAC (client-certificate mTLS)"
    echo "  or by username/password - for environments without CAC tokens."
    echo
    ask_yn USE_MTLS "Will this host use CAC mTLS for authentication?" "y" \
        "Yes -> CAC/mTLS auth (standard DoD path; you configure the DoD CA
          bundle + ssl_verify_client in nginx as a manual PKI step).
  No  -> username/password auth. Users self-register with a trusted email
          domain (asked next). CAC can still be enabled later from the admin UI."
    if [[ "$USE_MTLS" == "0" ]]; then
        AUTH_MODE="local"
        ask TRUSTED_EMAIL_DOMAIN "Trusted email domain for self-registration" "" \
            "Only emails at this exact domain may self-register (e.g. example.com).
  Leave blank to disable self-registration (admins create users instead)."
        ask_yn REQUIRE_APPROVAL "Require admin approval for new accounts?" "n" \
            "Yes -> new registrations are 'pending' until an admin approves.
  No  -> new registrations are active immediately."
    else
        AUTH_MODE="mtls"; TRUSTED_EMAIL_DOMAIN=""; REQUIRE_APPROVAL="0"
    fi

    ask_yn BOOTSTRAP_FIRST_ADMIN "Make the first user to log in an admin?" "n" \
        "Convenient for initial setup: the FIRST login on the empty database
  becomes admin (self-disables after). For mTLS, only choose Yes once CAC is
  verifying real identities; for username/password, the first registered user
  becomes admin."

    ask RESTORE_DB "Path to a database to restore (blank = fresh/empty)" "" \
        "Migrating an existing instance? Give the path to a jobs.db you
  carried over. Leave blank to start with a new empty database."

    SMG_TIMEOUT="${SMG_TIMEOUT:-10}"
    PYBIN="${PYBIN:-python3.9}"

    # --- confirm summary ---
    echo "=========================================================="
    echo "  Review:"
    echo "    Domain (suffix)   : ${CERTHEIM_DOMAIN}"
    echo "    Hostname          : ${CERTHEIM_HOSTNAME}"
    echo "    Dashboard URL     : ${DASHBOARD_URL}"
    if [[ "$AUTH_MODE" == "local" ]]; then
        echo "    Auth mode         : username/password (local)"
        echo "    Trusted domain    : ${TRUSTED_EMAIL_DOMAIN:-<self-reg disabled>}"
        echo "    Admin approval    : $( [[ $REQUIRE_APPROVAL == 1 ]] && echo required || echo no)"
    else
        echo "    Auth mode         : CAC mTLS"
    fi
    if [[ -n "$SMG_HOST" ]]; then
        echo "    Email relay       : ${SMG_HOST}:${SMG_PORT}"
        echo "    From address      : ${FROM_ADDRESS}"
        echo "    Global Cc         : ${GLOBAL_CC:-<none>}"
    else
        echo "    Email             : DISABLED (no relay)"
    fi
    echo "    First-login admin : $( [[ $BOOTSTRAP_FIRST_ADMIN == 1 ]] && echo yes || echo no)"
    echo "    Restore database  : ${RESTORE_DB:-<fresh empty DB>}"
    echo "=========================================================="
    read -r -p "  Proceed with these settings? [y/N]: " __go
    case "${__go:-n}" in [Yy]*) : ;; *) echo "  Aborted - nothing changed."; exit 0;; esac
fi

# everything below operates on the extracted bundle
cd "$BUNDLE_ROOT"

# ---------------------------------------------------------------------------
log "0/8  Validating configuration"
# ---------------------------------------------------------------------------
: "${CERTHEIM_DOMAIN:=example.com}"
: "${CERTHEIM_HOSTNAME:=certinel-host}"
[[ -n "${DASHBOARD_URL:-}" ]] || DASHBOARD_URL="https://${CERTHEIM_HOSTNAME}.${CERTHEIM_DOMAIN}/csr/"
[[ "$DASHBOARD_URL" != *CHANGEME* ]] || die "DASHBOARD_URL not set"
# Email is OPTIONAL: empty SMG_HOST = email disabled (valid).
if [[ -n "${SMG_HOST:-}" ]]; then
    [[ -n "${FROM_ADDRESS:-}" && "$FROM_ADDRESS" != *CHANGEME* ]] \
        || die "FROM_ADDRESS required when an SMG relay is set"
fi
echo "  domain=${CERTHEIM_DOMAIN} host=${CERTHEIM_HOSTNAME} email=$( [[ -n "${SMG_HOST:-}" ]] && echo "${SMG_HOST}" || echo disabled)"

# ---------------------------------------------------------------------------
log "1/8  Checking OS prerequisites (from this enclave's repo)"
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
log "2/8  Service account: ${SVC_USER}"
# ---------------------------------------------------------------------------
if id "$SVC_USER" >/dev/null 2>&1; then
    echo "  exists - leaving as-is"
else
    useradd --system --no-create-home --shell /sbin/nologin \
            --comment "Certheim service account" "$SVC_USER"
    echo "  created"
fi
getent group nginx >/dev/null || warn "group 'nginx' missing - is nginx installed?"

# ---------------------------------------------------------------------------
log "3/8  Directories"
# ---------------------------------------------------------------------------
DIRS=(
  "/opt/certheim|root:${SVC_USER}|0750"
  "/var/lib/certheim|${SVC_USER}:${SVC_USER}|0750"
  "/var/www/csr|root:nginx|0750"
  "/etc/certheim|root:${SVC_USER}|0750"
  "/root/sslcerts/scripts|root:root|0750"
  "/root/sslcerts/scripts/certheim_helper.d|root:root|0750"
  "/root/sslcerts/private|root:root|0700"
  "/home/ansible/new_request|root:root|0755"
  "/home/ansible/issued|root:${SVC_USER}|0750"
)
for entry in "${DIRS[@]}"; do
    IFS='|' read -r d og mode <<< "$entry"
    own="${og%%:*}"; grp="${og##*:}"
    getent group "$grp" >/dev/null 2>&1 || { warn "group $grp missing; using $own"; grp="$own"; }
    install -d -o "$own" -g "$grp" -m "$mode" "$d"
    echo "  $d ($own:$grp $mode)"
done
chmod o+x /home/ansible 2>/dev/null || warn "could not chmod /home/ansible - ensure certheim can traverse it"

# ---------------------------------------------------------------------------
log "4/8  Sudoers drop-in"
# ---------------------------------------------------------------------------
SUDOERS=/etc/sudoers.d/certheim
if [[ -f "$SUDOERS" ]]; then
    echo "  exists - leaving as-is"
else
    printf '# Certheim: service account runs ONLY the helper as root.\n%s ALL=(root) NOPASSWD: /root/sslcerts/scripts/certheim_helper.sh\n' \
        "$SVC_USER" > "$SUDOERS"
    chmod 0440 "$SUDOERS"
    visudo -cf "$SUDOERS" >/dev/null || die "sudoers validation failed"
    echo "  wrote $SUDOERS"
fi

# ---------------------------------------------------------------------------
log "5/8  Python venv from bundled wheelhouse (offline)"
# ---------------------------------------------------------------------------
VENV=/opt/certheim/venv
[[ -x "$VENV/bin/python3" ]] || "$PYBIN" -m venv "$VENV"
[[ -d wheelhouse ]] || die "wheelhouse/ missing from bundle"
"$VENV/bin/pip" install --no-index --find-links wheelhouse --upgrade pip setuptools wheel
"$VENV/bin/pip" install --no-index --find-links wheelhouse -r requirements.txt
echo "  deps installed"

# CRITICAL: python -m venv creates the venv dir 0700 under root's STIG umask
# (077). That locks out the certheim group, so the service cannot traverse into
# venv/ to exec gunicorn/python. Set group ownership AND traversal bits.
chown -R root:certheim "$VENV"
chmod 0750 /opt/certheim
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
    fapolicyd-cli --file add /opt/certheim/venv/ 2>/dev/null || true
    fapolicyd-cli --update 2>/dev/null || true
    echo "  fapolicyd: trusted /opt/certheim/venv/"
fi

# ---------------------------------------------------------------------------
log "6/8  Config files"
# ---------------------------------------------------------------------------
# email.conf - written from your answers. Empty host = email disabled, which
# the app honours (no notifications sent). Writing it either way keeps the
# file present and UI-manageable later.
cat > /etc/certheim/email.conf <<EMAILCONF
# /etc/certheim/email.conf  -  generated by offline-install
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
chown "${SVC_USER}:${SVC_USER}" /etc/certheim/email.conf
chmod 0640 /etc/certheim/email.conf
if [[ -n "${SMG_HOST:-}" ]]; then
    echo "  wrote /etc/certheim/email.conf (relay ${SMG_HOST}:${SMG_PORT:-25})"
else
    echo "  wrote /etc/certheim/email.conf (email DISABLED - no relay)"
fi

# certheim.env - seed from example if absent (paths are defaults)
if [[ ! -f /etc/certheim/certheim.env && -f config/certheim.env.example ]]; then
    install -o "$SVC_USER" -g "$SVC_USER" -m 0640 \
        config/certheim.env.example /etc/certheim/certheim.env
    echo "  seeded /etc/certheim/certheim.env"
fi
# Reflect the START_HERE first-admin choice into the live env file (set or
# replace the line so the app picks it up). Only the value the operator chose.
if [[ -f /etc/certheim/certheim.env ]]; then
    want="${BOOTSTRAP_FIRST_ADMIN:-0}"
    if grep -q '^CERTHEIM_BOOTSTRAP_FIRST_ADMIN=' /etc/certheim/certheim.env; then
        sed -i "s/^CERTHEIM_BOOTSTRAP_FIRST_ADMIN=.*/CERTHEIM_BOOTSTRAP_FIRST_ADMIN=${want}/" \
            /etc/certheim/certheim.env
    else
        echo "CERTHEIM_BOOTSTRAP_FIRST_ADMIN=${want}" >> /etc/certheim/certheim.env
    fi
    echo "  first-admin bootstrap: CERTHEIM_BOOTSTRAP_FIRST_ADMIN=${want}"
fi

# ---------------------------------------------------------------------------
log "6.5/8  Rewriting domain/hostname in bundle files"
# ---------------------------------------------------------------------------
# Substitute the build-time defaults (example.com / certinel-host) with this
# deployment's values across the DEPLOYABLE files, before deploy.sh copies
# them live. Scoped to the specific files that carry these strings; skipped
# entirely if the operator left the defaults. Hostname is replaced first so
# the FQDN (host.domain) composes correctly, then the domain.
DEF_DOMAIN="example.com"
DEF_HOST="certinel-host"
if [[ "$CERTHEIM_DOMAIN" != "$DEF_DOMAIN" || "$CERTHEIM_HOSTNAME" != "$DEF_HOST" ]]; then
    files=(
        backend/app.py backend/notify.py
        frontend/app.js frontend/index.html
        helper/certheim_helper.d/00-common.sh
        nginx/30-csr.conf
    )
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        sed -i \
            -e "s/${DEF_HOST}/${CERTHEIM_HOSTNAME}/g" \
            -e "s/${DEF_DOMAIN//./\\.}/${CERTHEIM_DOMAIN}/g" \
            "$f"
    done
    echo "  rewrote -> host=${CERTHEIM_HOSTNAME} domain=${CERTHEIM_DOMAIN}"
else
    echo "  defaults unchanged - no rewrite needed"
fi

# ---------------------------------------------------------------------------
log "7/8  Deploy code + optional data restore"
# ---------------------------------------------------------------------------
if [[ -n "${RESTORE_DB:-}" ]]; then
    [[ -f "$RESTORE_DB" ]] || die "RESTORE_DB set but file not found: $RESTORE_DB"
    install -o "$SVC_USER" -g "$SVC_USER" -m 0640 "$RESTORE_DB" /var/lib/certheim/jobs.db
    rm -f /var/lib/certheim/jobs.db-wal /var/lib/certheim/jobs.db-shm
    echo "  restored database from $RESTORE_DB"
fi
# Use -f (presence), not -x: the bundle preserves the build user's 0700 and
# under fapolicyd the script is run via `bash` (untrusted files can't exec by
# path). Calling `bash ./deploy.sh` keeps the whole chain fapolicyd-safe (F7/F8).
[[ -f ./deploy.sh ]] || die "deploy.sh missing in bundle root"
bash ./deploy.sh

# ---------------------------------------------------------------------------
log "7.5/8  Authentication mode"
# ---------------------------------------------------------------------------
# deploy.sh started certheim-api, which created the schema (incl. app_settings).
# Now write the auth settings into the DB via the helper. Default mtls needs
# nothing (app default), but we set it explicitly so `certheim-set-auth --show`
# always reflects the install choice.
if command -v certheim-set-auth >/dev/null 2>&1; then
    SETAUTH=certheim-set-auth
elif [[ -f tools/certheim-set-auth ]]; then
    SETAUTH="$PYBIN tools/certheim-set-auth"
else
    SETAUTH=""
fi
if [[ -n "$SETAUTH" ]]; then
    # brief wait so the app has created the schema on first start
    for _ in 1 2 3 4 5; do
        [[ -f /var/lib/certheim/jobs.db ]] && break; sleep 1
    done
    if [[ "$AUTH_MODE" == "local" ]]; then
        $SETAUTH --mode local --domain "${TRUSTED_EMAIL_DOMAIN:-}" \
            $( [[ "${REQUIRE_APPROVAL:-0}" == "1" ]] && echo --require-approval || echo --no-require-approval ) \
            || warn "could not set auth mode (run certheim-set-auth manually)"
        echo "  auth mode: username/password (domain=${TRUSTED_EMAIL_DOMAIN:-<none>})"
    else
        $SETAUTH --mode mtls || warn "could not set auth mode"
        echo "  auth mode: CAC mTLS"
    fi
else
    warn "certheim-set-auth not found - auth mode left at app default (mtls)."
    [[ "$AUTH_MODE" == "local" ]] && \
        warn "to enable password auth: certheim-set-auth --mode local --domain <domain>"
fi

# ---------------------------------------------------------------------------
log "8/8  PKI / mTLS check (cannot be scripted)"
# ---------------------------------------------------------------------------
pki_ok=true
nginx -t >/dev/null 2>&1 || { warn "nginx -t fails - server cert / CAC mTLS not configured for this site yet"; pki_ok=false; }

echo ""
echo "==================================================================="
echo " Mechanical install COMPLETE for v$(cat VERSION 2>/dev/null || echo '?')."
echo "==================================================================="
if ! $pki_ok; then
cat <<MAN
 [ ] PKI: install this enclave's DoD CA bundle (update-ca-trust), place this
         server's cert+key, and set ssl_client_certificate / ssl_verify_client
         for CAC mTLS in nginx (see nginx/30-csr.conf). Then:
            nginx -t && systemctl reload nginx
MAN
fi
if [[ -z "${RESTORE_DB:-}" ]]; then
cat <<MAN
 [ ] ADMIN: fresh empty database - bootstrap your CAC as the first admin
         (certheim-bootstrap-admin) or you will have no admin rights.
MAN
fi
cat <<MAN
 Verify:
   systemctl status certheim-api nginx
   curl -sk https://localhost/csr/api/health      # expect ok:true + version
===================================================================
MAN
INSTALL
chmod +x "$OUT/install/offline-install.sh"

# The two generated target scripts ship a hardcoded python3.9 default; rewrite
# them to the exact pythonX.Y this wheelhouse was built for, so the target's
# venv loads the bundled wheels. Env override on the target still wins.
sed -i "s|PYBIN=\"python3.9\"|PYBIN=\"$PYVER\"|g" "$OUT/install/START_HERE"
sed -i "s|PYBIN=\"\${PYBIN:-python3.9}\"|PYBIN=\"\${PYBIN:-$PYVER}\"|g" "$OUT/install/offline-install.sh"

# uninstaller: ship it in install/ next to the installer. It's tracked in the
# repo under tools/, so copy it in (fall back to a note if absent).
if [[ -f tools/certheim-uninstall.sh ]]; then
    cp tools/certheim-uninstall.sh "$OUT/install/certheim-uninstall.sh"
    chmod +x "$OUT/install/certheim-uninstall.sh"
    echo "  included install/certheim-uninstall.sh"
else
    echo "  (tools/certheim-uninstall.sh not found - uninstaller not bundled)"
fi

cat > "$OUT/OFFLINE-INSTALL.md" <<DOC
# Certheim - Offline Install (v${VERSION})

This bundle installs the Certheim on an air-gapped RHEL host with no
network access. It contains the application code, a wheelhouse of all
Python dependencies, and this guide.

## Prerequisites on the target (from the enclave's own repo/Satellite)
Install these OS packages first (NOT included in this bundle unless your
enclave lacks them): \`${PYBIN}\`, \`nginx\`, \`sqlite\`, \`fapolicyd\`,
\`openssl\`, \`policycoreutils\` (restorecon), and \`sudo\`.

## Environment prep (one time, as root)
1. **Service account**
   - Create \`certheim\` (system account, no login shell).
   - Install the sudoers drop-in granting certheim NOPASSWD on the helper
     dispatcher only. (See \`docs/runbook.md\`.)
2. **Directories**
   - \`/opt/certheim/\`            (app + venv)        root:certheim
   - \`/var/lib/certheim/\`        (SQLite DB)         certheim:certheim 0750
   - \`/var/www/csr/\`                  (frontend)          root:nginx
   - \`/etc/certheim/\`            (email.conf)        certheim:certheim
   - \`/root/sslcerts/scripts/\` + \`...d/\`, \`new_request/\`, \`private/\`
   - \`/home/ansible/issued/\`          (issued certs)      traversable by certheim
3. **PKI / mTLS**
   - Install the enclave's DoD CA bundle into the system trust store.
   - Place the dashboard's server cert + key for nginx.
   - Configure nginx server-level \`ssl_client_certificate\` /
     \`ssl_verify_client\` for CAC mTLS (see \`nginx/30-csr.conf\` and the
     runbook).
4. **email.conf**
   - Copy \`config/email.conf.example\` to \`/etc/certheim/email.conf\`
     and set the enclave's SMG relay host. Owner certheim:certheim, mode 0640.

## Install (three steps)
1. Edit the variables for THIS site:
\`\`\`bash
vi install/START_HERE          # set SMG_HOST, DASHBOARD_URL, FROM_ADDRESS
\`\`\`
2. **fapolicyd trust the bundle first (STIG hosts).** fapolicyd denies
   execute-by-path of any untrusted file, so a freshly extracted script
   cannot be run directly. Either trust the bundle, or launch via \`bash\`:
\`\`\`bash
# option A - trust the bundle scripts (then they exec by path):
sudo fapolicyd-cli --file add "\$(pwd)/install/offline-install.sh"
sudo fapolicyd-cli --file add "\$(pwd)/deploy.sh"
sudo fapolicyd-cli --update
# option B - just run via bash (the installer already calls its children
# via bash, so this is sufficient and needs no trust changes):
\`\`\`
3. Run the installer (via bash - fapolicyd-safe regardless of step 2):
\`\`\`bash
cd install
sudo bash ./offline-install.sh
\`\`\`
It reads START_HERE, then creates the certheim account, all directories,
sudoers drop-in, the venv (from the bundled wheelhouse, no network),
writes email.conf + certheim.env with YOUR values, optionally
restores a migrated database, refreshes fapolicyd trust for the venv,
deploys the code (\`bash ./deploy.sh\`), and starts the service.
Idempotent. When done it prints the only items it cannot script -
PKI/mTLS certs, and (fresh DB only) the first admin bootstrap.

## First-time host prerequisites (fresh box, one-time)
On a box that has never run this app, before/around install:
\`\`\`bash
# OS packages from the enclave repo (NOT in the bundle):
#   ${PYBIN} nginx sqlite fapolicyd openssl policycoreutils sudo
# nginx must include the certheim.d drop-in and be enabled (F9):
grep -q 'certheim.d' /etc/nginx/nginx.conf || \\
  sed -i '/http {/a\\    include /etc/nginx/certheim.d/*.conf;' /etc/nginx/nginx.conf
systemctl enable --now nginx
# open 443 (the installer does NOT touch firewalld) (F11):
firewall-cmd --permanent --add-service=https && firewall-cmd --reload
\`\`\`

## fapolicyd (STIG hosts)
deploy.sh refreshes trust for existing files, but the FIRST install needs
the venv + app trusted:
\`\`\`bash
fapolicyd-cli --file add /opt/certheim/
fapolicyd-cli --update
\`\`\`
Also add the rules.d allow for any Ansible/automation that runs as certheim.

## Build box requirements (where you run make-offline-bundle.sh)
This bundle must be BUILT on a connected box that:
- has \`${PYBIN}\` + \`pip\` + internet access to PyPI (the target needs none
  of these - it installs from the bundled wheelhouse), and
- is NOT fapolicyd-enforcing (or you run the builder as root), because
  fapolicyd denies non-root reads of .py source (F4/F5).
The build box must match the target's RHEL major / python / arch so the
wheels are compatible.

## First admin (fresh database)
A fresh DB has no admins and the app has no built-in promotion. After you
authenticate once over mTLS (so your DN row exists), promote yourself:
\`\`\`bash
sqlite3 /var/lib/certheim/jobs.db \\
  "UPDATE users SET is_admin=1 WHERE dn='<YOUR CAC DN>';"
systemctl restart certheim-api
\`\`\`
Preferred: the bundled tool does this for you (no prior login needed):
\`\`\`bash
certheim-bootstrap-admin "<YOUR CAC DN>"
\`\`\`

## Verify
\`\`\`bash
systemctl status certheim-api nginx
curl -sk https://localhost/csr/api/health        # {"ok":true,"version":"${VERSION}"}
\`\`\`
The admin Overview tile should show v${VERSION}.

## Data migration (if moving an existing instance, not a fresh stand-up)
On the SOURCE box: \`certheim-backup\` (or copy /var/lib/certheim/jobs.db).
Carry the backup across; restore to /var/lib/certheim/jobs.db,
owner certheim:certheim, BEFORE first start. WAL files (-wal/-shm) can be
omitted if the source app was stopped cleanly.
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
