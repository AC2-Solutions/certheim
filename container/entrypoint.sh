#!/bin/sh
# Certheim container entrypoint. The same image runs every role; pick one as the
# first argument (default: web). The DB schema is created on import (app.py calls
# init_db()), so `web` and `migrate` both build/upgrade it.
#
#   web                 gunicorn HTTP server on 0.0.0.0:$CERTHEIM_PORT (default)
#   migrate             create/upgrade the DB schema, then exit
#   cron expiry-warn    run the expiry-warning pass once (for a k8s CronJob)
#   cron auto-renew     run the auto-renew pass once
#   cron deliver        run the delivery retry pass once
#   <other>             exec it verbatim (debugging: `docker run ... sh`)
#
# Tunables (env): CERTHEIM_PORT (5002), GUNICORN_WORKERS (2), GUNICORN_THREADS (4).
set -e

# Everything launched through this entrypoint runs in container mode (no sudo
# helper, ingress-terminated mTLS) unless explicitly overridden.
export CERTHEIM_CONTAINER="${CERTHEIM_CONTAINER:-${CERTINEL_CONTAINER:-1}}"

# Rename compat (Phase 2): an existing deployment may still mount its volumes at
# the pre-rename paths. If the old DB exists and no explicit override was given,
# keep reading the mounted data rather than starting empty at the new default.
if [ -e /var/lib/certinel/jobs.db ] && [ ! -e /var/lib/certheim/jobs.db ] \
   && [ -z "${CERTHEIM_DB_PATH:-}" ]; then
    export CERTHEIM_DB_PATH="/var/lib/certinel/jobs.db"
    echo "certheim: legacy volume detected - using /var/lib/certinel/jobs.db (remount at /var/lib/certheim when convenient)"
fi
if [ -d /var/opt/certinel/issued ] && [ ! -d /var/opt/certheim/issued ] \
   && [ -z "${CERTHEIM_ISSUED_DIR:-}" ]; then
    export CERTHEIM_ISSUED_DIR="/var/opt/certinel/issued"
fi
cd /opt/certheim

ROLE="${1:-web}"
[ $# -gt 0 ] && shift || true

case "$ROLE" in
  web)
    exec gunicorn \
      --workers "${GUNICORN_WORKERS:-2}" --threads "${GUNICORN_THREADS:-4}" \
      --bind "0.0.0.0:${CERTHEIM_PORT:-5002}" \
      --access-logfile - --error-logfile - app:app
    ;;
  migrate)
    exec python3 -c 'import app; print("certheim: schema ready")'
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
        echo "certheim: unknown cron task '${TASK}' (expiry-warn|auto-renew|deliver)" >&2
        exit 2 ;;
    esac
    ;;
  *)
    exec "$ROLE" "$@"
    ;;
esac
