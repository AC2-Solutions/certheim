#!/bin/bash
# certinel-doctor.sh - read-only health check for a deployed Certheim host.
#
#   sudo certinel-doctor            run all checks, print PASS/WARN/FAIL
#   sudo certinel-doctor --quiet    only print WARN/FAIL lines + summary
#
# Probes the failure classes that have actually bitten installs (service
# crash-loops, app-dir CHDIR perms, SELinux exec labels, nginx/static root,
# the auth/mTLS license gate, TLS expiry, data-dir ownership, legacy
# remnants). Changes NOTHING. Exit code: 0 all-pass/warn, 1 if any FAIL.
#
# Complements verify.sh (which checks deployed-file drift vs the repo): this
# checks the RUNNING system instead.

set -uo pipefail
QUIET=false; [[ "${1:-}" == "--quiet" ]] && QUIET=true
[[ $EUID -eq 0 ]] || { echo "run as root (some checks need it)"; exit 2; }

# ---- config / paths (match deploy.sh) -------------------------------------
SVC_USER="$(systemctl show certinel-api -p User --value 2>/dev/null)"; SVC_USER="${SVC_USER:-certinel}"
APP_DIR=/opt/certinel
WWW_DIR=/var/www/csr
ENV_FILE=/etc/certinel/certinel.env
CERT=/etc/pki/certinel/server.crt
DB="$(grep -oE '^CSR_DB_PATH=\S+' "$ENV_FILE" 2>/dev/null | cut -d= -f2)"; DB="${DB:-/var/lib/certinel/jobs.db}"
BASE="https://localhost/csr"

pass=0 warn=0 fail=0
P() { $QUIET || printf '  \033[32mPASS\033[0m  %s\n' "$*"; pass=$((pass+1)); }
W() { printf '  \033[33mWARN\033[0m  %s\n' "$*"; warn=$((warn+1)); }
F() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail=$((fail+1)); }
sec() { $QUIET || printf '\n== %s ==\n' "$*"; }

echo "=== Certheim doctor ($(hostname)) - service user: ${SVC_USER} ==="

# ---- 1. systemd service ---------------------------------------------------
sec "service"
state="$(systemctl is-active certinel-api 2>/dev/null)"
if [[ "$state" == active ]]; then P "certinel-api is active"
else
    F "certinel-api is '$state' (not running)"
    code="$(systemctl show certinel-api -p ExecMainStatus --value 2>/dev/null)"
    case "$code" in
      203) F "  -> 203/EXEC: venv not executable (SELinux label? see 'app dir' below)";;
      200) F "  -> 200/CHDIR: service user cannot enter WorkingDirectory (perms? see below)";;
      *) [[ -n "$code" ]] && W "  last exit code: $code";;
    esac
fi

# ---- 2. app dir: service user must traverse it (CHDIR) ---------------------
sec "app dir + exec"
if sudo -u "$SVC_USER" test -x "$APP_DIR" 2>/dev/null; then P "$SVC_USER can traverse $APP_DIR"
else F "$SVC_USER CANNOT traverse $APP_DIR ($(stat -c '%U:%G %a' "$APP_DIR" 2>/dev/null)) -> 200/CHDIR risk"; fi
GUNI="$APP_DIR/venv/bin/gunicorn"
if sudo -u "$SVC_USER" test -x "$GUNI" 2>/dev/null; then P "$SVC_USER can exec gunicorn (DAC)"
else F "$SVC_USER cannot exec $GUNI (DAC)"; fi
if command -v getenforce >/dev/null && [[ "$(getenforce)" == Enforcing ]]; then
    ctx="$(matchpathcon -n "$GUNI" 2>/dev/null | awk -F: '{print $3}')"
    if [[ "$ctx" == var_lib_t ]]; then F "SELinux labels gunicorn '$ctx' -> systemd 203/EXEC (run: restorecon -RF $APP_DIR)"
    else P "SELinux exec label ok (${ctx:-n/a})"; fi
fi

# ---- 3. HTTP surface ------------------------------------------------------
sec "http"
code="$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/" 2>/dev/null)"
[[ "$code" == 200 ]] && P "GET /csr/ -> 200" || F "GET /csr/ -> $code (backend down / nginx 502?)"
# Retry briefly: on a fresh install the doctor runs right after the service
# starts, and gunicorn may not have bound :5002 yet — the same startup race
# deploy.sh already retries. Without this a healthy first install reports a
# scary (but false) "app not responding" FAIL.
running=""
for _ in 1 2 3; do
    running="$(curl -sk "$BASE/api/health" 2>/dev/null | grep -oE '"version":"[^"]+"' | cut -d'"' -f4)"
    [[ -n "$running" ]] && break
    sleep 2
done
deployed="$(cat "$APP_DIR/VERSION" 2>/dev/null)"
if [[ -n "$running" && "$running" == "$deployed" ]]; then P "serving v$running (matches deployed)"
elif [[ -n "$running" ]]; then W "serving v$running but deployed is v$deployed (restart needed?)"
else F "/api/health did not return a version (app not responding)"; fi

# ---- 4. nginx + static root ----------------------------------------------
sec "nginx"
nginx -t >/dev/null 2>&1 && P "nginx -t ok" || F "nginx -t FAILS"
dup="$(grep -rhoE 'server_name\s+\S+' /etc/nginx/conf.d/ 2>/dev/null | sort | uniq -d)"
[[ -z "$dup" ]] && P "no duplicate server_name" || W "duplicate server_name: $dup"
[[ -s "$WWW_DIR/index.html" ]] && P "static root $WWW_DIR/index.html present" \
    || F "missing $WWW_DIR/index.html (location /csr/ uses root /var/www -> serves $WWW_DIR)"

# ---- 5. auth / mTLS license-gate consistency ------------------------------
sec "auth"
am="$(sqlite3 "$DB" "select value from app_settings where key=char(97,117,116,104,95,109,111,100,101);" 2>/dev/null)"
mm="$(sqlite3 "$DB" "select value from app_settings where key=char(109,116,108,115,95,109,111,100,101);" 2>/dev/null)"
[[ "$am" =~ ^(local|mtls)$ ]] && P "auth_mode=${am}" || W "auth_mode='${am:-unset}' (unset defaults to mtls -> CAC login)"
if [[ "$mm" == optional || "$mm" == enforce ]]; then
    ent="$(cd "$APP_DIR" 2>/dev/null && set -a && . "$ENV_FILE" 2>/dev/null; set +a; \
           venv/bin/python -c 'import capabilities,sys; sys.exit(0 if capabilities.available("auth.cac") else 1)' 2>/dev/null && echo yes || echo no)"
    [[ "$ent" == yes ]] && P "mtls_mode=$mm and CAC is licensed" \
        || F "mtls_mode=$mm but CAC NOT licensed -> Auth-settings saves will 403 (set mtls_mode=off)"
else P "mtls_mode=${mm:-off} (no license gate)"; fi

# ---- 6. TLS cert + renewer ------------------------------------------------
sec "tls"
if [[ -r "$CERT" ]]; then
    end="$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null | cut -d= -f2)"
    es="$(date -d "$end" +%s 2>/dev/null)"; now="$(date +%s)"
    days=$(( (es - now) / 86400 ))
    renew_on=false; systemctl is-enabled certinel-tls-renew.timer >/dev/null 2>&1 && renew_on=true
    if (( days < 0 )); then F "TLS cert EXPIRED ($end)$($renew_on && echo ' (renew timer enabled but did not run)')"
    elif $renew_on; then P "TLS cert valid ${days}d (step-ca auto-renew enabled)"
    elif (( days <= 7 )); then W "TLS cert expires in ${days}d and there is NO renew timer"
    else P "TLS cert valid ${days}d"; fi
else W "no TLS cert at $CERT"; fi

# ---- 7. data dir writable by the service ----------------------------------
sec "data"
if [[ -f "$DB" ]]; then
    sudo -u "$SVC_USER" test -w "$DB" 2>/dev/null && P "$SVC_USER can write jobs.db" \
        || F "$SVC_USER cannot write $DB ($(stat -c '%U:%G %a' "$DB" 2>/dev/null))"
else W "no DB at $DB yet (pre-OOBE?)"; fi

# ---- 8. legacy csr-dashboard remnants -------------------------------------
sec "branding"
leg="$(ls -d /opt/csr-dashboard /etc/csr-dashboard 2>/dev/null; id csrapi 2>/dev/null | grep -o csrapi)"
[[ -z "$leg" ]] && P "no legacy csr-dashboard paths/account" || W "legacy remnants: $(echo $leg)"

# ---- summary --------------------------------------------------------------
printf '\n=== %d pass / %d warn / %d fail ===\n' "$pass" "$warn" "$fail"
(( fail == 0 )) && { echo "Certheim looks healthy."; exit 0; } || { echo "Problems found above."; exit 1; }
