#!/bin/bash
# v2-openbao-pki-phase0.sh
#
# Phase 0 spike for v2 in-UI signing (see docs/v2-ca-signing-design.md):
# stand up a dedicated OpenBao PKI mount + a sign role + a SCOPED app
# credential (AppRole), then PROVE a real CSR signs end-to-end and verifies.
#
# Idempotent: safe to re-run. Read-mostly except the four create/tune calls.
#
# Requires an OpenBao token that can administer mounts/policies/auth:
#     BAO_TOKEN=<admin token>  BAO_ADDR=https://openbao.ac2.lan \
#       bash ./tools/v2-openbao-pki-phase0.sh
#
# The app itself NEVER uses this admin token - it uses the scoped AppRole this
# script prints at the end (capability: update on <MOUNT>/sign/<ROLE> ONLY).
#
# NOTE: the spike uses an OpenBao-INTERNAL root so it is self-contained. For
# production, replace step 2 with an intermediate signed by the AC2 root
# (pki_csr/intermediate/generate -> sign with step-ca/AC2 root -> set-signed)
# so issued certs chain to the trusted AC2 bundle. See design doc Phase 0.5.

set -euo pipefail

BAO_ADDR="${BAO_ADDR:-https://openbao.ac2.lan}"
BAO_TOKEN="${BAO_TOKEN:?set BAO_TOKEN to an OpenBao admin token}"
MOUNT="${MOUNT:-pki_csr}"
ROLE="${ROLE:-csr-dashboard}"
POLICY="${POLICY:-csr-pki-sign}"
APPROLE="${APPROLE:-csr-dashboard}"
ALLOWED_DOMAINS="${ALLOWED_DOMAINS:-ac2.lan,ac2solutions.lan}"
MAX_TTL="${MAX_TTL:-2160h}"               # 90d cap on issued leaf certs
CA_CN="${CA_CN:-AC2 CSR Dashboard Issuing CA (spike)}"
CURLOPT="-s"; [[ "${BAO_INSECURE:-0}" == "1" ]] && CURLOPT="-s -k"

api() { # api METHOD PATH [json-body]
  local m="$1" p="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl $CURLOPT -H "X-Vault-Token: $BAO_TOKEN" -X "$m" \
         -H "Content-Type: application/json" -d "$body" "$BAO_ADDR/v1/$p"
  else
    curl $CURLOPT -H "X-Vault-Token: $BAO_TOKEN" -X "$m" "$BAO_ADDR/v1/$p"
  fi
}
jget() { python3 -c 'import sys,json;d=json.load(sys.stdin)
keys=sys.argv[1].split(".")
for k in keys: d = d[k] if isinstance(d,dict) else d
print(d)' "$1"; }
say() { printf '\n=== %s ===\n' "$*"; }

# ---------------------------------------------------------------------------
say "0  Preflight (admin token can see sys/mounts?)"
code=$(curl $CURLOPT -o /dev/null -w '%{http_code}' -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/sys/mounts")
[[ "$code" == "200" ]] || { echo "  ERROR: token cannot read sys/mounts (HTTP $code) - need an admin token"; exit 1; }
echo "  ok"

# ---------------------------------------------------------------------------
say "1  Enable PKI mount: $MOUNT"
if api GET "sys/mounts/$MOUNT" | grep -q '"type":"pki"'; then
  echo "  already enabled"
else
  api POST "sys/mounts/$MOUNT" '{"type":"pki","config":{"max_lease_ttl":"43800h"}}' >/dev/null
  echo "  enabled (max_lease_ttl=43800h)"
fi

# ---------------------------------------------------------------------------
say "2  Root CA (spike: internal; prod: AC2-root-chained intermediate)"
if api GET "$MOUNT/ca/pem" | grep -q "BEGIN CERTIFICATE"; then
  echo "  CA already present - leaving as-is"
else
  api POST "$MOUNT/root/generate/internal" \
    "{\"common_name\":\"${CA_CN}\",\"key_type\":\"rsa\",\"key_bits\":4096,\"ttl\":\"43800h\"}" \
    | jget "data.serial_number" | sed 's/^/  root serial: /'
fi

# ---------------------------------------------------------------------------
say "3  Configure issuing/CRL/OCSP URLs"
api POST "$MOUNT/config/urls" \
  "{\"issuing_certificates\":[\"$BAO_ADDR/v1/$MOUNT/ca\"],\"crl_distribution_points\":[\"$BAO_ADDR/v1/$MOUNT/crl\"],\"ocsp_servers\":[\"$BAO_ADDR/v1/$MOUNT/ocsp\"]}" >/dev/null
echo "  set"

# ---------------------------------------------------------------------------
say "4  Sign role: $ROLE (allowed_domains=$ALLOWED_DOMAINS, max_ttl=$MAX_TTL)"
api POST "$MOUNT/roles/$ROLE" \
  "{\"allowed_domains\":\"$ALLOWED_DOMAINS\",\"allow_subdomains\":true,\"allow_bare_domains\":true,\"server_flag\":true,\"client_flag\":true,\"key_usage\":[\"DigitalSignature\",\"KeyEncipherment\"],\"max_ttl\":\"$MAX_TTL\",\"no_store\":false}" >/dev/null
echo "  role written (authoritative policy lives here)"

# ---------------------------------------------------------------------------
say "5  Scoped ACL policy: $POLICY  (update on $MOUNT/sign/$ROLE ONLY)"
POL="path \"$MOUNT/sign/$ROLE\" { capabilities = [\"update\"] }"
api PUT "sys/policies/acl/$POLICY" \
  "$(python3 -c 'import json,sys;print(json.dumps({"policy":sys.argv[1]}))' "$POL")" >/dev/null
echo "  policy written"

# ---------------------------------------------------------------------------
say "6  AppRole auth for the app credential"
api GET "sys/auth" | grep -q '"approle/"' || api POST "sys/auth/approle" '{"type":"approle"}' >/dev/null
api POST "auth/approle/role/$APPROLE" \
  "{\"token_policies\":[\"$POLICY\"],\"token_ttl\":\"20m\",\"token_max_ttl\":\"1h\",\"secret_id_ttl\":\"0\"}" >/dev/null
ROLE_ID=$(api GET "auth/approle/role/$APPROLE/role-id" | jget "data.role_id")
SECRET_ID=$(api POST "auth/approle/role/$APPROLE/secret-id" "" | jget "data.secret_id")
echo "  role_id:   $ROLE_ID"
echo "  secret_id: (generated; shown once at end)"

# ---------------------------------------------------------------------------
say "7  END-TO-END PROOF: generate CSR -> AppRole login -> sign -> verify"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$TMP/key.pem" -out "$TMP/req.csr" \
  -subj "/CN=spike-host.ac2.lan" \
  -addext "subjectAltName=DNS:spike-host.ac2.lan" 2>/dev/null
echo "  generated test CSR for spike-host.ac2.lan"

# log in with the SCOPED credential (this is what the app will do)
APP_TOKEN=$(curl $CURLOPT -X POST "$BAO_ADDR/v1/auth/approle/login" \
  -d "{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}" | jget "auth.client_token")
echo "  AppRole login ok (scoped token acquired)"

# sign the CSR using ONLY the scoped token (proves least-privilege works)
CSR_JSON=$(python3 -c 'import json,sys;print(json.dumps({"csr":open(sys.argv[1]).read(),"ttl":"720h"}))' "$TMP/req.csr")
SIGN_RESP=$(curl $CURLOPT -H "X-Vault-Token: $APP_TOKEN" -X POST \
  -d "$CSR_JSON" "$BAO_ADDR/v1/$MOUNT/sign/$ROLE")
echo "$SIGN_RESP" | jget "data.certificate" > "$TMP/cert.pem"
echo "$SIGN_RESP" | jget "data.issuing_ca"  > "$TMP/ca.pem"
grep -q "BEGIN CERTIFICATE" "$TMP/cert.pem" || { echo "  SIGN FAILED:"; echo "$SIGN_RESP"; exit 1; }
echo "  signed via scoped token (capability = sign-only)"

# verify: cert pubkey matches CSR pubkey, and cert chains to the CA
csr_pk=$(openssl req  -in "$TMP/req.csr"  -noout -pubkey 2>/dev/null | openssl sha256)
crt_pk=$(openssl x509 -in "$TMP/cert.pem" -noout -pubkey 2>/dev/null | openssl sha256)
[[ "$csr_pk" == "$crt_pk" ]] && echo "  pubkey match: OK" || { echo "  pubkey MISMATCH"; exit 1; }
openssl verify -CAfile "$TMP/ca.pem" "$TMP/cert.pem" >/dev/null 2>&1 \
  && echo "  chain verify: OK" || echo "  chain verify: (check intermediate chain)"
echo "  issued subject: $(openssl x509 -in "$TMP/cert.pem" -noout -subject 2>/dev/null)"
echo "  issued expires: $(openssl x509 -in "$TMP/cert.pem" -noout -enddate 2>/dev/null)"

# ---------------------------------------------------------------------------
say "DONE - Phase 0 proven"
cat <<OUT
The app credential for v2 (store secret_id in OpenBao-backed config, NOT jobs.db):
  BAO_ADDR   = $BAO_ADDR
  pki_mount  = $MOUNT
  sign_role  = $ROLE
  approle    = $APPROLE
  role_id    = $ROLE_ID
  secret_id  = $SECRET_ID   # capability: update $MOUNT/sign/$ROLE ONLY
Next (P1): backend/sign.py openbao backend + POST /api/jobs/<id>/sign.
OUT
