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
#  Lines are KEY="value". Anything left blank or marked CHANGEME must be set.
# ===========================================================================

# --- REQUIRED: this site's values ------------------------------------------

# SMG relay IP or hostname (the mail relay this server sends through).
# The relay must whitelist THIS server's IP for unauthenticated relay.
SMG_HOST="CHANGEME"

# This server's dashboard URL (used in notification email bodies and links).
DASHBOARD_URL="https://CHANGEME.eucom.mil/csr/"

# From: address on outgoing notifications. The relay must accept it from
# this server's IP.
FROM_ADDRESS="noreply-csr@CHANGEME.eucom.mil"

# --- OPTIONAL: usually fine as-is ------------------------------------------

# Python interpreter on the target (must match the bundle's wheels).
PYBIN="python3.9"

# SMG port / timeout.
SMG_PORT="25"
SMG_TIMEOUT="10"

# Optional comma-separated Cc applied to every notification. Blank = none.
GLOBAL_CC=""

# --- CAC mTLS (the installer generates the nginx server block) -------------
# "yes" => ENFORCING server block (ssl_verify_client on against the DoD CA
# bundle below). "no" => those lines are written COMMENTED and optional_no_ca
# is used so the box serves; the app then sees ip:<addr> identities.
# WARNING: with mTLS "no", do NOT turn on first-admin bootstrap.
ENABLE_MTLS="no"
# Path to the DoD CA bundle (root+intermediate PEM, no CRLF) for mTLS "yes".
DOD_CA_BUNDLE="/etc/pki/dod/dod-cas.pem"

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
# This script lives in the bundle's  install/  directory. Before running it,
# edit  install/START_HERE  with this site's values. Then:
#
#     cd install
#     sudo ./offline-install.sh
#
# It reads START_HERE, then automates everything mechanical: the csrapi
# service account, all directories, the Python venv (from the bundled
# wheelhouse, no network), fapolicyd trust, config files written with YOUR
# values, optional data restore, and the app deploy. It STOPS with a clear
# message if an OS package or PKI prerequisite is missing - those cannot be
# scripted and must be provided from this enclave.
#
# Idempotent: safe to re-run.

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- read the operator's values ---
[[ -f "$SCRIPT_DIR/START_HERE" ]] || { echo "ERROR: START_HERE missing next to this script" >&2; exit 1; }
# shellcheck disable=SC1090
source "$SCRIPT_DIR/START_HERE"

PYBIN="${PYBIN:-python3.9}"
SVC_USER="csrapi"
log()  { echo -e "\n=== $* ==="; }
warn() { echo "  WARN: $*" >&2; }
die()  { echo "  ERROR: $*" >&2; exit 1; }

# everything below operates on the extracted bundle
cd "$BUNDLE_ROOT"

# ---------------------------------------------------------------------------
log "0/8  Validating START_HERE values"
# ---------------------------------------------------------------------------
[[ "${SMG_HOST:-CHANGEME}" != "CHANGEME" && -n "${SMG_HOST:-}" ]] \
    || die "SMG_HOST not set in install/START_HERE"
[[ "$DASHBOARD_URL" != *CHANGEME* ]] \
    || die "DASHBOARD_URL still contains CHANGEME in install/START_HERE"
[[ "$FROM_ADDRESS" != *CHANGEME* ]] \
    || die "FROM_ADDRESS still contains CHANGEME in install/START_HERE"
echo "  SMG_HOST=$SMG_HOST  URL=$DASHBOARD_URL  FROM=$FROM_ADDRESS"

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
            --comment "CSR Dashboard service account" "$SVC_USER"
    echo "  created"
fi
getent group nginx >/dev/null || warn "group 'nginx' missing - is nginx installed?"

# ---------------------------------------------------------------------------
log "3/8  Directories"
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
    own="${og%%:*}"; grp="${og##*:}"
    getent group "$grp" >/dev/null 2>&1 || { warn "group $grp missing; using $own"; grp="$own"; }
    install -d -o "$own" -g "$grp" -m "$mode" "$d"
    echo "  $d ($own:$grp $mode)"
done
chmod o+x /home/ansible 2>/dev/null || warn "could not chmod /home/ansible - ensure csrapi can traverse it"

# ---------------------------------------------------------------------------
log "4/8  Sudoers drop-in"
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
log "5/8  Python venv from bundled wheelhouse (offline)"
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
chmod 0750 /opt/csr-dashboard "$VENV" "$VENV/bin"
# ensure regular files stay readable by group, dirs traversable
find "$VENV" -type d -exec chmod g+rx {} +
find "$VENV" -type f -perm -u+x -exec chmod g+rx {} +
echo "  venv ownership/modes set for ${SVC_USER} traversal"

# Trust the freshly-created venv with fapolicyd, or the service cannot exec
# gunicorn/python on STIG hosts. deploy.sh later UPDATES trust for known
# files; the brand-new venv binaries must be ADDED here first.
if command -v fapolicyd-cli >/dev/null; then
    fapolicyd-cli --file add /opt/csr-dashboard/venv/ 2>/dev/null || true
    fapolicyd-cli --update 2>/dev/null || true
    echo "  fapolicyd: trusted /opt/csr-dashboard/venv/"
fi

# ---------------------------------------------------------------------------
log "6/8  Config files (written from START_HERE)"
# ---------------------------------------------------------------------------
# email.conf - written with the operator's real values
cat > /etc/csr-dashboard/email.conf <<EMAILCONF
# /etc/csr-dashboard/email.conf  -  generated by offline-install from START_HERE
[smtp]
host = ${SMG_HOST}
port = ${SMG_PORT:-25}
timeout = ${SMG_TIMEOUT:-10}

[from]
address = ${FROM_ADDRESS}

[recipients]
cc = ${GLOBAL_CC:-}

[content]
dashboard_url = ${DASHBOARD_URL}
EMAILCONF
chown "${SVC_USER}:${SVC_USER}" /etc/csr-dashboard/email.conf
chmod 0640 /etc/csr-dashboard/email.conf
echo "  wrote /etc/csr-dashboard/email.conf (SMG ${SMG_HOST}:${SMG_PORT:-25})"

# csr-dashboard.env - seed from example if absent (paths are defaults)
if [[ ! -f /etc/csr-dashboard/csr-dashboard.env && -f config/csr-dashboard.env.example ]]; then
    install -o "$SVC_USER" -g "$SVC_USER" -m 0640 \
        config/csr-dashboard.env.example /etc/csr-dashboard/csr-dashboard.env
    echo "  seeded /etc/csr-dashboard/csr-dashboard.env"
fi

# ---------------------------------------------------------------------------
log "7/9  nginx server block + self-signed cert (fresh/standalone boxes)"
# ---------------------------------------------------------------------------
# nginx/30-csr.conf is a LOCATION FRAGMENT (deploy.sh installs it to
# /etc/nginx/rcdn01.d) and must live inside a server{} block. On a site that
# already has one doing `include rcdn01.d/*.conf` (e.g. rcdn01) we leave nginx
# alone; on a fresh/air-gapped box we generate a standalone server block here
# so the box serves /csr/ with no hand-editing. TLS + CAC mTLS live HERE.
NID=/etc/nginx/rcdn01.d
CERTDIR=/etc/pki/csr-dashboard
FQDN="$(hostname -f 2>/dev/null || hostname)"
install -d -m 0755 "$NID"
if [[ ! -f "$CERTDIR/server.crt" ]]; then
    install -d -m 0750 "$CERTDIR"
    if openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.crt" \
        -subj "/CN=${FQDN}" -addext "subjectAltName=DNS:${FQDN},DNS:$(hostname -s)" >/dev/null 2>&1; then
        chmod 0640 "$CERTDIR/server.key"; chmod 0644 "$CERTDIR/server.crt"
        echo "  generated self-signed placeholder cert for ${FQDN}"
    else
        warn "openssl cert generation failed - place a real cert at $CERTDIR/server.{crt,key}"
    fi
fi
# CAC mTLS stanza per START_HERE's ENABLE_MTLS: enabled => enforcing; disabled
# => those lines COMMENTED + optional_no_ca active (the box still serves and the
# app sees ip:<addr> identities). If enabling, also auto-publish the DoD bundle
# to the trust portal (handled by the app's trust dir below).
if [[ "${ENABLE_MTLS:-no}" =~ ^([Yy]|[Yy][Ee][Ss]|[Tt][Rr][Uu][Ee]|1|[Oo][Nn])$ ]]; then
    [[ -s "${DOD_CA_BUNDLE:-}" ]] || warn "ENABLE_MTLS=yes but ${DOD_CA_BUNDLE:-<unset>} missing/empty - nginx -t will fail until the DoD CA bundle is placed there"
    MTLS_STANZA="    # CAC mTLS ENFORCED (ENABLE_MTLS=yes). DoD chain: Root->Intermediate->CAC.
    ssl_client_certificate ${DOD_CA_BUNDLE};
    ssl_verify_client       on;
    ssl_verify_depth        3;"
    echo "  CAC mTLS: ENFORCED (CA bundle ${DOD_CA_BUNDLE})"
else
    MTLS_STANZA="    # CAC mTLS NOT enabled (ENABLE_MTLS=no). To enforce later: place the DoD CA
    # bundle at ${DOD_CA_BUNDLE}, uncomment the next two lines, remove the
    # optional_no_ca line, then: nginx -t && systemctl reload nginx
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

# ---------------------------------------------------------------------------
log "8/9  Deploy code + optional data restore"
# ---------------------------------------------------------------------------
if [[ -n "${RESTORE_DB:-}" ]]; then
    [[ -f "$RESTORE_DB" ]] || die "RESTORE_DB set but file not found: $RESTORE_DB"
    install -o "$SVC_USER" -g "$SVC_USER" -m 0640 "$RESTORE_DB" /var/lib/csr-dashboard/jobs.db
    rm -f /var/lib/csr-dashboard/jobs.db-wal /var/lib/csr-dashboard/jobs.db-shm
    echo "  restored database from $RESTORE_DB"
fi
[[ -f ./deploy.sh ]] || die "deploy.sh missing in bundle root"
bash ./deploy.sh

# ---------------------------------------------------------------------------
log "9/9  PKI / mTLS check (cannot be scripted)"
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
         (csr-bootstrap-admin) or you will have no admin rights.
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

## Environment prep (one time, as root)
1. **Service account**
   - Create \`csrapi\` (system account, no login shell).
   - Install the sudoers drop-in granting csrapi NOPASSWD on the helper
     dispatcher only. (See \`docs/runbook.md\`.)
2. **Directories**
   - \`/opt/csr-dashboard/\`            (app + venv)        root:csrapi
   - \`/var/lib/csr-dashboard/\`        (SQLite DB)         csrapi:csrapi 0750
   - \`/var/www/csr/\`                  (frontend)          root:nginx
   - \`/etc/csr-dashboard/\`            (email.conf)        csrapi:csrapi
   - \`/root/sslcerts/scripts/\` + \`...d/\`, \`new_request/\`, \`private/\`
   - \`/home/ansible/issued/\`          (issued certs)      traversable by csrapi
3. **PKI / mTLS**
   - Install the enclave's DoD CA bundle into the system trust store.
   - Place the dashboard's server cert + key for nginx.
   - Configure nginx server-level \`ssl_client_certificate\` /
     \`ssl_verify_client\` for CAC mTLS (see \`nginx/30-csr.conf\` and the
     runbook).
4. **email.conf**
   - Copy \`config/email.conf.example\` to \`/etc/csr-dashboard/email.conf\`
     and set the enclave's SMG relay host. Owner csrapi:csrapi, mode 0640.

## Install (two steps)
1. Edit the variables for THIS site:
\`\`\`bash
vi install/START_HERE          # set SMG_HOST, DASHBOARD_URL, FROM_ADDRESS
\`\`\`
2. Run the installer:
\`\`\`bash
cd install
sudo ./offline-install.sh
\`\`\`
It reads START_HERE, then creates the csrapi account, all directories,
sudoers drop-in, the venv (from the bundled wheelhouse, no network),
writes email.conf + csr-dashboard.env with YOUR values, optionally
restores a migrated database, refreshes fapolicyd trust, deploys the
code, and starts the service. Idempotent. When done it prints the only
items it cannot script - PKI/mTLS certs, and (fresh DB only) the first
admin bootstrap.

## fapolicyd (STIG hosts)
deploy.sh refreshes trust for existing files, but the FIRST install needs
the venv + app trusted:
\`\`\`bash
fapolicyd-cli --file add /opt/csr-dashboard/
fapolicyd-cli --update
\`\`\`
Also add the rules.d allow for any Ansible/automation that runs as csrapi.

## Verify
\`\`\`bash
systemctl status csr-api nginx
curl -sk https://localhost/csr/api/health        # {"ok":true,"version":"${VERSION}"}
\`\`\`
The admin Overview tile should show v${VERSION}.

## Data migration (if moving an existing instance, not a fresh stand-up)
On the SOURCE box: \`csrbackup\` (or copy /var/lib/csr-dashboard/jobs.db).
Carry the backup across; restore to /var/lib/csr-dashboard/jobs.db,
owner csrapi:csrapi, BEFORE first start. WAL files (-wal/-shm) can be
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
