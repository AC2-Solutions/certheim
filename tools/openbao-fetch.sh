#!/bin/bash
# openbao-fetch.sh - print one field of an OpenBao/Vault KV-v2 secret, auth'd via
# AppRole. The point: a consumer reads the secret at RUNTIME, so rotating the
# value is "bao kv put <path> field=NEW" and every consumer picks it up on its
# next run - no redeploy, no key baked into a config file. Works against OpenBao
# or HashiCorp Vault (same HTTP API). Dependency-free (curl + python3 stdlib).
#
#   openbao-fetch secret/data/mailgun api_key
#   MAILGUN_API_KEY="$(openbao-fetch secret/data/mailgun api_key)"
#
# Connection + AppRole creds come from $OPENBAO_ENV (default /etc/openbao/approle.env),
# which is the ONLY thing on the box - 0600 root:
#   OPENBAO_ADDR=https://openbao.ac2.lan
#   OPENBAO_ROLE_ID=...
#   OPENBAO_SECRET_ID=...
#   #OPENBAO_CACERT=/etc/pki/tls/certs/ca-bundle.crt   # optional (default: system trust)
set -euo pipefail

usage() { echo "usage: openbao-fetch <kv-v2-api-path> <field>   e.g. secret/data/mailgun api_key" >&2; exit 2; }
SECRET_PATH="${1:-}"; FIELD="${2:-}"
[[ -n "$SECRET_PATH" && -n "$FIELD" ]] || usage

ENV_FILE="${OPENBAO_ENV:-/etc/openbao/approle.env}"
[[ -r "$ENV_FILE" ]] && . "$ENV_FILE"
: "${OPENBAO_ADDR:?OPENBAO_ADDR not set (in $ENV_FILE)}"
: "${OPENBAO_ROLE_ID:?OPENBAO_ROLE_ID not set}"
: "${OPENBAO_SECRET_ID:?OPENBAO_SECRET_ID not set}"
CA=(); [[ -n "${OPENBAO_CACERT:-}" ]] && CA=(--cacert "$OPENBAO_CACERT")

# 1) AppRole login -> short-lived token
TOKEN="$(curl -s "${CA[@]}" --max-time 15 \
    --request POST "$OPENBAO_ADDR/v1/auth/approle/login" \
    --data "{\"role_id\":\"$OPENBAO_ROLE_ID\",\"secret_id\":\"$OPENBAO_SECRET_ID\"}" \
    | python3 -c 'import sys,json
d=json.load(sys.stdin)
a=d.get("auth")
if not a: sys.exit("openbao login failed: %s" % d.get("errors", d))
print(a["client_token"])')"

# 2) read the field (KV v2 wraps payload in data.data)
curl -s "${CA[@]}" --max-time 15 -H "X-Vault-Token: $TOKEN" "$OPENBAO_ADDR/v1/$SECRET_PATH" \
    | FIELD="$FIELD" python3 -c 'import os,sys,json
d=json.load(sys.stdin)
try: data=d["data"]["data"]            # KV v2
except (KeyError,TypeError): data=d.get("data",{})  # KV v1 fallback
f=os.environ["FIELD"]
if f not in data: sys.exit("field %r not in secret (have: %s)" % (f, ",".join(data)))
print(data[f])'

# 3) best-effort: drop the short-lived token
curl -s "${CA[@]}" --max-time 10 -H "X-Vault-Token: $TOKEN" \
    --request POST "$OPENBAO_ADDR/v1/auth/token/revoke-self" >/dev/null 2>&1 || true
