#!/bin/sh
# Certinel container entrypoint. The same image runs every role; pick one as the
# first argument (default: web). The DB schema is created on import (app.py calls
# init_db()), so `web` and `migrate` both build/upgrade it.
#
#   web                 gunicorn HTTP server on 0.0.0.0:$CERTINEL_PORT (default)
#   migrate             create/upgrade the DB schema, then exit
#   cron expiry-warn    run the expiry-warning pass once (for a k8s CronJob)
#   cron auto-renew     run the auto-renew pass once
#   cron deliver        run the delivery retry pass once
#   <other>             exec it verbatim (debugging: `docker run ... sh`)
#
# Tunables (env): CERTINEL_PORT (5002), GUNICORN_WORKERS (2), GUNICORN_THREADS (4).
set -e

# Everything launched through this entrypoint runs in container mode (no sudo
# helper, ingress-terminated mTLS) unless explicitly overridden.
export CERTINEL_CONTAINER="${CERTINEL_CONTAINER:-1}"
cd /opt/certinel

ROLE="${1:-web}"
[ $# -gt 0 ] && shift || true

case "$ROLE" in
  web)
    exec gunicorn \
      --workers "${GUNICORN_WORKERS:-2}" --threads "${GUNICORN_THREADS:-4}" \
      --bind "0.0.0.0:${CERTINEL_PORT:-5002}" \
      --access-logfile - --error-logfile - app:app
    ;;
  migrate)
    exec python3 -c 'import app; print("certinel: schema ready")'
    ;;
  cron)
    TASK="${1:-}"
    case "$TASK" in
      expiry-warn)
        exec python3 -c 'import app; s,e=app.run_expiry_warnings(); print(f"expiry: sent={s} errors={e}")' ;;
      auto-renew)
        exec python3 -c 'import app; r,s,e=app.run_auto_renew(); print(f"auto-renew: renewed={r} skipped={s} errors={e}")' ;;
      deliver)
        exec python3 -c 'import app; r=app.run_deliveries(); print(f"delivery: {r}")' ;;
      *)
        echo "certinel: unknown cron task '${TASK}' (expiry-warn|auto-renew|deliver)" >&2
        exit 2 ;;
    esac
    ;;
  *)
    exec "$ROLE" "$@"
    ;;
esac
