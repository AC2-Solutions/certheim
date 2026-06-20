#!/bin/bash
# certinel-doctor-alert.sh - run certinel-doctor and email on failure (Mailgun).
#
# Driven by the certinel-doctor.timer (every ~15m). State-based so it doesn't
# spam: it emails on a healthy->FAIL transition, re-sends every RENOTIFY_HOURS
# while still failing, and sends a one-shot RECOVERED notice on FAIL->healthy.
# Config in /etc/certinel/doctor-alert.conf (see config/doctor-alert.conf.example).
# With no Mailgun config it still runs the check and logs to the journal - the
# email is purely additive, so the timer is safe to enable everywhere.
set -uo pipefail

CONF=/etc/certinel/doctor-alert.conf
STATE=/var/lib/certinel/.doctor-alert-state
DOCTOR=/usr/local/sbin/certinel-doctor
[[ -x "$DOCTOR" ]] || DOCTOR="$(cd "$(dirname "$0")" && pwd)/certinel-doctor.sh"
[[ -r "$CONF" ]] && . "$CONF"
RENOTIFY_HOURS="${RENOTIFY_HOURS:-24}"
MAILGUN_BASE="${MAILGUN_BASE:-https://api.mailgun.net/v3}"
HOST="$(hostname -f 2>/dev/null || hostname)"
log() { logger -t certinel-doctor-alert -- "$*"; }

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
            -F from="${MAILGUN_FROM:-Certinel Monitor <certinel@${MAILGUN_DOMAIN}>}" \
            -F to="${ALERT_EMAIL}" -F subject="$subj" -F text="$body" >/dev/null; then
        log "email sent: $subj"
    else
        log "Mailgun send FAILED: $subj"
    fi
}

if [[ $rc -ne 0 ]]; then
    if [[ "$prev_status" != fail ]] || (( now - prev_alert >= RENOTIFY_HOURS * 3600 )); then
        send_mail "[Certinel] UNHEALTHY: ${HOST}" \
"certinel-doctor found problems on ${HOST} at $(date).

${out}

SSH in and run 'sudo certinel-doctor' for full detail."
        prev_alert="$now"
    fi
    log "health=FAIL (rc=$rc)"
    printf 'fail|%s\n' "$prev_alert" > "$STATE"
else
    if [[ "$prev_status" == fail ]]; then
        send_mail "[Certinel] RECOVERED: ${HOST}" "certinel-doctor is healthy again on ${HOST} at $(date)."
    fi
    printf 'ok|0\n' > "$STATE"
fi
exit 0
