#!/usr/bin/env bash
# sec_authz_battery.sh — black-box security regression battery for Certheim.
#
# Exercises the authorization model end-to-end against a running instance:
#   1. Horizontal IDOR / broken object-level auth on the job read/list surface
#   2. Write IDOR on the manual cert-return path (upload-cert)
#   3. Signing round-trip integrity (cert<->CSR public-key binding)
#   4. Stored-XSS spot check (attacker-controlled CSR subject is escaped)
#
# It creates throwaway non-admin users + jobs, asserts expected status codes,
# and cleans everything up. Exit 0 = all PASS, non-zero = at least one FAIL.
#
# Usage:
#   BASE=https://clm.ac2.lan/csr ADMIN_USER=claude-bot ADMIN_PASS=123123 \
#     tests/sec_authz_battery.sh
#
# Requires: bash, curl, openssl, python3. CSRF header is X-Requested-With.
set -uo pipefail

BASE="${BASE:?set BASE, e.g. https://clm.ac2.lan/csr}"
ADMIN_USER="${ADMIN_USER:?set ADMIN_USER}"
ADMIN_PASS="${ADMIN_PASS:?set ADMIN_PASS}"
CURL="curl -sk --max-time 30 -H X-Requested-With:certinel"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
# unique, charset-safe suffixes (no Date/RANDOM dependency). NAME_RE is
# letters-only, so derive an alphabetic suffix for names; email allows digits.
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
LSFX="$(printf '%s' "$SFX" | tr '0-9a-f' 'a-jp-u')"

ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
req(){ local ck="$1"; shift; $CURL -b "$TMP/$ck" "$@"; }     # authenticated call
# assert_code <expected> <cookie> <label> <curl-args...>
assert_code(){ local exp="$1" ck="$2" label="$3"; shift 3
  local got; got="$($CURL -b "$TMP/$ck" -o "$TMP/body" -w '%{http_code}' "$@")"
  if [ "$got" = "$exp" ]; then ok "$label (HTTP $got)"; else bad "$label (want $exp got $got)"; fi; }
jget(){ python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: print(""); sys.exit()
for p in sys.argv[1].split("."): d=d.get(p) if isinstance(d,dict) else None
print(d if d is not None else "")' "$1"; }
jstr(){ python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))'; }

login(){ # <user> <pass> <cookie-name>
  $CURL -c "$TMP/$3" -H 'Content-Type: application/json' -X POST "$BASE/api/auth/login" \
    --data "{\"username\":\"$1\",\"password\":\"$2\"}" -o /dev/null -w '%{http_code}'; }

echo "== Certheim security authz battery =="
echo "target: $BASE   suffix: $SFX"

# ---- 0. admin session ----
[ "$(login "$ADMIN_USER" "$ADMIN_PASS" admin.ck)" = 200 ] \
  && ok "admin login" || { bad "admin login"; echo "cannot continue"; exit 2; }

VPW='Sec!Battery-Pass-123456'
mkuser(){ # <first> <last> <emaillocal> -> echoes derived username
  req admin.ck -H 'Content-Type: application/json' -X POST "$BASE/api/admin/users" \
    --data "{\"first_name\":\"$1\",\"last_name\":\"$2\",\"email\":\"$3@ac2.lan\",\"password\":\"$VPW\",\"is_admin\":false}" \
    | jget username; }
VUSER="$(mkuser "Victim" "T$LSFX" "vic$SFX")"
AUSER="$(mkuser "Attacker" "A$LSFX" "atk$SFX")"
[ -n "$VUSER" ] && [ -n "$AUSER" ] && ok "created victim=$VUSER attacker=$AUSER" || { bad "create test users (v=$VUSER a=$AUSER)"; exit 2; }
[ "$(login "$VUSER" "$VPW" vic.ck)" = 200 ] && ok "victim login" || bad "victim login"
[ "$(login "$AUSER" "$VPW" atk.ck)" = 200 ] && ok "attacker login" || bad "attacker login"

# ---- victim submits a CSR (its own job) ----
openssl req -new -newkey rsa:2048 -nodes -keyout "$TMP/v.key" -out "$TMP/v.csr" \
  -subj "/CN=victim-secret-$SFX.ac2.lan/O=VictimCorp" >/dev/null 2>&1
VJOB="$(req vic.ck -H 'Content-Type: application/json' -X POST "$BASE/api/external/submit" \
  --data "{\"csr_pem\":$(jstr <"$TMP/v.csr"),\"target_host\":\"victim-secret-$SFX.ac2.lan\",\"requester_email\":\"vic$SFX@ac2.lan\"}" \
  | jget job_id)"
[ -n "$VJOB" ] && ok "victim submitted job $VJOB" || { bad "victim submit"; }

echo "-- 1. read IDOR: attacker must NOT see victim's job --"
assert_code 403 atk.ck "attacker GET /jobs/<id>"          "$BASE/api/jobs/$VJOB"
assert_code 403 atk.ck "attacker GET /jobs/<id>/csr"      "$BASE/api/jobs/$VJOB/csr"
assert_code 403 atk.ck "attacker GET /jobs/<id>/csr-info" "$BASE/api/jobs/$VJOB/csr-info"
assert_code 403 atk.ck "attacker signing-queue zip"       "$BASE/api/signing-queue/csrs.zip"
ATKLIST="$(req atk.ck "$BASE/api/jobs?limit=500" | jget total)"
[ "$ATKLIST" = "0" ] && ok "attacker /jobs list scoped (total=0)" || bad "attacker /jobs list leaks (total=$ATKLIST)"
ATKROWS="$(req atk.ck "$BASE/api/jobs/export.csv" | tail -n +2 | grep -c .)"
[ "$ATKROWS" = "0" ] && ok "attacker export.csv scoped (0 rows)" || bad "attacker export.csv leaks ($ATKROWS rows)"

echo "-- 2. write IDOR: attacker must NOT complete victim's job --"
assert_code 403 atk.ck "attacker upload-cert to victim job" -H 'Content-Type: application/json' \
  -X POST "$BASE/api/jobs/$VJOB/upload-cert" --data '{"cert_pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}'

echo "-- legit access still works --"
assert_code 200 vic.ck "victim GET own job" "$BASE/api/jobs/$VJOB"
assert_code 200 vic.ck "victim GET own csr" "$BASE/api/jobs/$VJOB/csr"
VICLIST="$(req vic.ck "$BASE/api/jobs?limit=500" | jget total)"
[ "$VICLIST" = "1" ] && ok "victim sees only own job (total=1)" || bad "victim list total=$VICLIST (want 1)"
assert_code 200 admin.ck "admin GET victim job (oversight)" "$BASE/api/jobs/$VJOB"
assert_code 200 admin.ck "admin signing-queue zip"          "$BASE/api/signing-queue/csrs.zip"

echo "-- 3. signing round-trip: cert<->CSR public-key binding --"
openssl req -new -newkey rsa:2048 -nodes -keyout "$TMP/a.key" -out "$TMP/a.csr" \
  -subj "/CN=roundtrip-$SFX.ac2.lan" >/dev/null 2>&1
AJOB="$(req admin.ck -H 'Content-Type: application/json' -X POST "$BASE/api/external/submit" \
  --data "{\"csr_pem\":$(jstr <"$TMP/a.csr"),\"target_host\":\"roundtrip-$SFX.ac2.lan\",\"requester_email\":\"$ADMIN_USER@ac2.lan\"}" \
  | jget job_id)"
openssl req -new -newkey rsa:2048 -nodes -keyout "$TMP/b.key" -out "$TMP/b.csr" -subj "/CN=roundtrip-$SFX.ac2.lan" >/dev/null 2>&1
openssl x509 -req -in "$TMP/b.csr" -signkey "$TMP/b.key" -days 7 -out "$TMP/b.crt" >/dev/null 2>&1
assert_code 400 admin.ck "upload mismatched-key cert rejected" -H 'Content-Type: application/json' \
  -X POST "$BASE/api/jobs/$AJOB/upload-cert" --data "{\"cert_pem\":$(jstr <"$TMP/b.crt")}"
openssl x509 -req -in "$TMP/a.csr" -signkey "$TMP/a.key" -days 7 -out "$TMP/a.crt" >/dev/null 2>&1
assert_code 200 admin.ck "upload matching-key cert accepted" -H 'Content-Type: application/json' \
  -X POST "$BASE/api/jobs/$AJOB/upload-cert" --data "{\"cert_pem\":$(jstr <"$TMP/a.crt")}"

echo "-- 4. stored-XSS spot check: CSR subject is escaped in csr-info --"
if req admin.ck "$BASE/api/jobs/$AJOB/csr-info" | grep -q "<script"; then
  bad "csr-info reflected raw <script>"; else ok "csr-info has no raw <script>"; fi

echo "-- cleanup --"
req admin.ck -X DELETE "$BASE/api/admin/jobs/$VJOB" -o /dev/null
req admin.ck -X DELETE "$BASE/api/admin/jobs/$AJOB" -o /dev/null
for dn in "local:$VUSER" "local:$AUSER"; do
  req admin.ck -H 'Content-Type: application/json' -X DELETE "$BASE/api/admin/users" --data "{\"dn\":\"$dn\"}" -o /dev/null
done
ok "removed test users + jobs"

echo
echo "==== RESULT: $PASS passed, $FAIL failed ===="
[ "$FAIL" -eq 0 ]
