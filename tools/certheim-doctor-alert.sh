#!/bin/bash
# certheim-doctor-alert.sh - run certheim-doctor and email on failure (Mailgun).
#
# Driven by the certheim-doctor.timer (every ~15m). State-based so it doesn't
# spam: it emails on a healthy->FAIL transition, re-sends every RENOTIFY_HOURS
# while still failing, and sends a one-shot RECOVERED notice on FAIL->healthy.
# Config in /etc/certheim/doctor-alert.conf (see config/doctor-alert.conf.example).
# With no Mailgun config it still runs the check and logs to the journal - the
# email is purely additive, so the timer is safe to enable everywhere.
set -uo pipefail

CONF=/etc/certheim/doctor-alert.conf
STATE=/var/lib/certheim/.doctor-alert-state
DOCTOR=/usr/local/sbin/certheim-doctor
[[ -x "$DOCTOR" ]] || DOCTOR="$(cd "$(dirname "$0")" && pwd)/certheim-doctor.sh"
[[ -r "$CONF" ]] && . "$CONF"
# Optionally pull the Mailgun key/domain from OpenBao/Vault at RUNTIME so rotating
# the secret is a single 'bao kv put' with no redeploy. Set MAILGUN_OPENBAO_PATH
# (e.g. secret/data/mailgun) in the conf; openbao-fetch reads AppRole creds from
# /etc/openbao/approle.env. A static MAILGUN_API_KEY in the conf still wins.
if [[ -n "${MAILGUN_OPENBAO_PATH:-}" ]] && command -v openbao-fetch >/dev/null 2>&1; then
    : "${MAILGUN_API_KEY:=$(openbao-fetch "$MAILGUN_OPENBAO_PATH" "${MAILGUN_KEY_FIELD:-api_key}" 2>/dev/null || true)}"
    : "${MAILGUN_DOMAIN:=$(openbao-fetch "$MAILGUN_OPENBAO_PATH" "${MAILGUN_DOMAIN_FIELD:-domain}" 2>/dev/null || true)}"
fi
RENOTIFY_HOURS="${RENOTIFY_HOURS:-24}"
MAILGUN_BASE="${MAILGUN_BASE:-https://api.mailgun.net/v3}"
HOST="$(hostname -f 2>/dev/null || hostname)"
log() { logger -t certheim-doctor-alert -- "$*"; }

out="$("$DOCTOR" --quiet 2>&1)"; rc=$?
now="$(date +%s)"
prev_status=ok prev_alert=0
[[ -r "$STATE" ]] && IFS='|' read -r prev_status prev_alert < "$STATE" 2>/dev/null

send_mail() {
    local subj="$1" body="$2"
    if [[ -z "${MAILGUN_API_KEY:-}" || -z "${MAILGUN_DOMAIN:-}" || -z "${ALERT_EMAIL:-}" ]]; then
        log "no Mailgun config - skipping email: $subj"; return 0
    fi
    if curl -s --max-time 20 --user "api:${MAILGUN_API_KEY}" \
            "${MAILGUN_BASE}/${MAILGUN_DOMAIN}/messages" \
            -F from="${MAILGUN_FROM:-Certheim Monitor <certheim@${MAILGUN_DOMAIN}>}" \
            -F to="${ALERT_EMAIL}" -F subject="$subj" -F text="$body" >/dev/null; then
        log "email sent: $subj"
    else
        log "Mailgun send FAILED: $subj"
    fi
}

if [[ $rc -ne 0 ]]; then
    if [[ "$prev_status" != fail ]] || (( now - prev_alert >= RENOTIFY_HOURS * 3600 )); then
        send_mail "[Certheim] UNHEALTHY: ${HOST}" \
"certheim-doctor found problems on ${HOST} at $(date).

${out}

SSH in and run 'sudo certheim-doctor' for full detail."
        prev_alert="$now"
    fi
    log "health=FAIL (rc=$rc)"
    printf 'fail|%s\n' "$prev_alert" > "$STATE"
else
    if [[ "$prev_status" == fail ]]; then
        send_mail "[Certheim] RECOVERED: ${HOST}" "certheim-doctor is healthy again on ${HOST} at $(date)."
    fi
    printf 'ok|0\n' > "$STATE"
fi
exit 0
