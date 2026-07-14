"""diagnostics.py - configuration self-checks for supportability.

Runs a battery of read-only(ish) health checks against the live deployment and
returns structured results. Two consumers:

  * GET /api/admin/diagnostics - the admin UI's "Run health check" button, so
    an operator sees obvious misconfigurations (broken scheduler, unconfigured
    email, expired license, unreachable signing backend) BEFORE opening a
    support ticket, and
  * the support bundle - results are embedded as diagnostics.json + a
    human-readable summary, so a ticket that does get opened arrives with the
    obvious causes already ruled in or out.

Design rules: every check is exception-proofed (a diagnostics failure must
never 500 or block a bundle), no check output may contain secret material
(reuse only key NAMES / hostnames / counts), premium-only surfaces are probed
via import/table guards so the same module runs on every edition, and network
probes use short timeouts (5s) against endpoints the app is already configured
to talk to - nothing new is contacted.

Statuses: ok | warn | fail | skip | error.  `overall` is the worst status
present (fail > error > warn > ok; skip is neutral).
"""
import os
import shutil
import socket
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import envcompat

_SEVERITY = {"ok": 0, "skip": 0, "warn": 1, "error": 2, "fail": 3}

# Scheduler staleness: the expiry-warn pass is expected at least daily on every
# supported install (systemd timer / K8s CronJob); double it for slack.
STALE_PASS_SECONDS = 48 * 3600
STUCK_JOB_SECONDS = 7 * 24 * 3600


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _result(check_id, category, status, summary, hint=None):
    out = {"id": check_id, "category": category, "status": status,
           "summary": summary[:300]}
    if hint:
        out["hint"] = hint[:300]
    return out


def _table_exists(db, name):
    try:
        with db() as conn:
            try:
                r = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (name,)).fetchone()
            except Exception:               # postgres backend
                r = conn.execute(
                    "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                    "AND tablename=?", (name,)).fetchone()
        return r is not None
    except Exception:
        return False


def _http_reachable(url, timeout=5):
    """(reachable, note). Any HTTP status counts as reachable - we're testing
    the network path + TLS, not the endpoint's semantics."""
    try:
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "certheim-diagnostics"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return True, "HTTP %s" % r.status
    except urllib.error.HTTPError as e:
        return True, "HTTP %s" % e.code
    except Exception as e:                  # noqa: BLE001
        return False, str(e)[:120]


# --- individual checks -------------------------------------------------------

def check_database(get_setting, db):
    """DB reachable and WRITABLE (a read-only filesystem or lost PVC mount is a
    classic 'everything 500s' cause)."""
    probe_key = "diagnostics_probe"
    with db() as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (probe_key, _now()))
        conn.execute("DELETE FROM app_settings WHERE key = ?", (probe_key,))
    return _result("database", "core", "ok", "database reachable and writable")


def check_disk_space(get_setting, db):
    """Free space where the DB lives - sqlite corrupts workflows long before
    ENOSPC by failing WAL writes."""
    path = envcompat.getenv("CERTHEIM_DB_PATH", "/var/lib/certheim/jobs.db")
    d = os.path.dirname(path) or "."
    if not os.path.isdir(d):
        return _result("disk-space", "core", "skip",
                       "data directory not present (external DB backend)")
    usage = shutil.disk_usage(d)
    free_pct = usage.free * 100.0 / usage.total if usage.total else 0
    free_gb = usage.free / (1024 ** 3)
    label = "%.1f GB free (%.0f%%) at %s" % (free_gb, free_pct, d)
    if free_pct < 3 or free_gb < 0.2:
        return _result("disk-space", "core", "fail", label,
                       "the database will start failing writes - free space now")
    if free_pct < 10 or free_gb < 1:
        return _result("disk-space", "core", "warn", label,
                       "under 10% free - plan cleanup or growth")
    return _result("disk-space", "core", "ok", label)


def check_email(get_setting, db):
    """Email delivery configured - expiry warnings, signup links and alerts all
    silently go nowhere without it."""
    import notify
    if notify.is_enabled():
        return _result("email", "notifications", "ok",
                       "email delivery is configured and enabled")
    reason = ""
    try:
        reason = notify.disabled_reason() or ""
    except Exception:                       # noqa: BLE001
        pass
    return _result("email", "notifications", "warn",
                   "email delivery is DISABLED%s" % (
                       " (%s)" % reason[:120] if reason else ""),
                   "expiry warnings and account emails cannot be sent; "
                   "configure Admin -> Email")


def check_auth(get_setting, db):
    """Auth mode sanity: a local-auth install with no password-capable admin is
    locked out one session-expiry from now; a lingering bootstrap flag grants
    admin to the first stranger who logs in."""
    mode = (get_setting("auth_mode") or "mtls").strip().lower()
    if mode == "local":
        with db() as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM users WHERE is_admin = 1 "
                "AND password_hash IS NOT NULL AND password_hash != ''"
            ).fetchone()[0]
        if n == 0:
            return _result("auth", "access", "fail",
                           "local auth mode but NO admin has a password set",
                           "you will be locked out at session expiry; set an "
                           "admin password or bootstrap one")
    if envcompat.getenv("CERTHEIM_BOOTSTRAP_FIRST_ADMIN", "") in ("1", "true", "on"):
        return _result("auth", "access", "warn",
                       "CERTHEIM_BOOTSTRAP_FIRST_ADMIN is still enabled",
                       "the next new identity to sign in becomes an admin - "
                       "unset it now that setup is done")
    return _result("auth", "access", "ok", "auth mode '%s' looks sane" % mode)


def check_license(get_setting, db):
    """License validity + the edition/build mismatch that makes a paid license
    'do nothing' on a lower-tier image."""
    import build_mode
    import licensing
    info = licensing.info() or {}
    reason = (info.get("reason") or "")
    if "expired" in reason.lower():
        return _result("license", "licensing", "fail",
                       "license is EXPIRED",
                       "premium features are disabled; renew via your "
                       "customer portal")
    if info.get("edition_mismatch"):
        return _result("license", "licensing", "warn",
                       "license grants '%s' but this is the %s build" % (
                           info.get("edition"), info.get("build_edition")),
                       "upgrading means redeploying the matching edition image "
                       "(pull creds are in your license email), not just "
                       "installing the license")
    if info.get("licensed"):
        exp = info.get("expires")
        if exp:
            try:
                days = (float(exp) - time.time()) / 86400
                if days < 30:
                    return _result("license", "licensing", "warn",
                                   "license expires in %d day(s)" % max(0, int(days)),
                                   "renew before expiry to avoid a feature lapse")
            except (TypeError, ValueError):
                pass
        return _result("license", "licensing", "ok",
                       "license valid (%s edition)" % (info.get("edition") or "?"))
    if getattr(build_mode, "EDITION", "community") != "community":
        return _result("license", "licensing", "warn",
                       "%s build running without a license" % build_mode.EDITION,
                       reason or "premium features are locked until a license "
                       "is installed")
    return _result("license", "licensing", "ok",
                   "community build, no license required")


def check_signing_backend(get_setting, db):
    """The configured signing backend answers on the network - the most common
    'approve does nothing' cause is a dead/unreachable backend."""
    backend = (get_setting("signing_default_backend") or "manual").strip().lower()
    if backend in ("", "manual"):
        return _result("signing-backend", "issuance", "ok",
                       "manual signing (no backend to probe)")
    if backend == "openbao":
        addr = (get_setting("openbao_addr") or "").strip().rstrip("/")
        if not addr or "example.com" in addr:
            return _result("signing-backend", "issuance", "warn",
                           "openbao is the default backend but openbao_addr "
                           "is not configured")
        ok, note = _http_reachable(addr + "/v1/sys/health")
        return _result("signing-backend", "issuance", "ok" if ok else "warn",
                       "openbao at %s: %s" % (
                           urllib.parse.urlparse(addr).netloc, note),
                       None if ok else "signing requests will fail until the "
                       "backend is reachable (network/TLS trust/DNS)")
    if backend == "acme":
        url = (get_setting("acme_directory_url") or "").strip()
        if not url:
            return _result("signing-backend", "issuance", "warn",
                           "acme is the default backend but no directory URL is set")
        ok, note = _http_reachable(url)
        return _result("signing-backend", "issuance", "ok" if ok else "warn",
                       "ACME directory %s: %s" % (
                           urllib.parse.urlparse(url).netloc, note),
                       None if ok else "issuance will fail until the ACME "
                       "directory is reachable")
    return _result("signing-backend", "issuance", "ok",
                   "default backend '%s' (no generic probe)" % backend)


def check_scheduler(get_setting, db):
    """Background passes actually firing - a disabled timer/CronJob is the top
    silent failure (no warnings, no renewals, nobody notices until an outage)."""
    raw = get_setting("last_expiry_warn_at")
    if not raw:
        return _result("scheduler", "automation", "warn",
                       "no expiry-warning pass has ever recorded a run",
                       "check the certheim-expiry-warn timer / CronJob is "
                       "installed and enabled")
    try:
        age = time.time() - float(raw)
    except (TypeError, ValueError):
        return _result("scheduler", "automation", "error",
                       "last_expiry_warn_at is unreadable")
    if age > STALE_PASS_SECONDS:
        return _result("scheduler", "automation", "warn",
                       "expiry-warning pass last ran %.1f days ago" % (age / 86400),
                       "the scheduler looks broken - check the timer/CronJob")
    return _result("scheduler", "automation", "ok",
                   "expiry-warning pass ran %.1f hours ago" % (age / 3600))


def check_stuck_jobs(get_setting, db):
    """Requests sitting in 'pending' for over a week usually mean approvals are
    routing to nobody (or notifications are down - see the email check)."""
    cutoff = time.time() - STUCK_JOB_SECONDS
    with db() as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE status = 'pending' "
            "AND created_at < ?", (cutoff,)).fetchone()[0]
    if n:
        return _result("stuck-jobs", "issuance", "warn",
                       "%d request(s) pending for more than 7 days" % n,
                       "check approver group membership and email delivery")
    return _result("stuck-jobs", "issuance", "ok", "no long-pending requests")


def check_deliveries(get_setting, db):
    """Recent delivery failures (premium; skipped when the table is absent)."""
    if not _table_exists(db, "deliveries"):
        return _result("deliveries", "delivery", "skip",
                       "delivery engine not present in this edition")
    cutoff = time.time() - 7 * 86400
    with db() as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM deliveries WHERE status IN "
            "('failed', 'abandoned') AND updated_at > ?", (cutoff,)).fetchone()[0]
    if n:
        return _result("deliveries", "delivery", "warn",
                       "%d delivery failure(s) in the last 7 days" % n,
                       "see Admin -> Delivery for per-target errors")
    return _result("deliveries", "delivery", "ok", "no recent delivery failures")


def check_helper(get_setting, db):
    """VM installs: the privileged helper must exist and be executable
    (container installs run helperless by design)."""
    # Container detection from env, NOT `import app`: importing app has side
    # effects (db path resolution, data-dir mkdir) that poison bare-process
    # unit tests and any context where the app isn't meant to boot.
    if envcompat.getenv("CERTHEIM_CONTAINER", "0").strip().lower() in ("1", "true", "on"):
        return _result("helper", "core", "skip", "container mode (no helper)")
    path = envcompat.getenv("CERTHEIM_HELPER_PATH",
                            "/opt/certheim/helper/certheim_helper.sh")
    if not os.path.exists(path):
        return _result("helper", "core", "warn",
                       "helper not found at %s" % path,
                       "on-host key generation and trust-store installs will fail")
    if not os.access(path, os.X_OK):
        return _result("helper", "core", "warn",
                       "helper at %s is not executable" % path)
    return _result("helper", "core", "ok", "helper present and executable")


def check_fleet_scan(get_setting, db):
    """Fleet inventory freshness (premium; skipped when absent/empty): a stale
    fleet means the external scanner stopped reporting."""
    if not _table_exists(db, "fleet_certs"):
        return _result("fleet-scan", "visibility", "skip",
                       "fleet inventory not present in this edition")
    with db() as conn:
        row = conn.execute(
            "SELECT COUNT(*), MAX(last_seen) FROM fleet_certs").fetchone()
    count, last_seen = row[0], row[1]
    if not count:
        return _result("fleet-scan", "visibility", "skip", "no fleet records")
    age = time.time() - float(last_seen or 0)
    if age > STALE_PASS_SECONDS:
        return _result("fleet-scan", "visibility", "warn",
                       "no fleet scan for %.1f days (%d records)" % (
                           age / 86400, count),
                       "the external cert scanner has stopped reporting")
    return _result("fleet-scan", "visibility", "ok",
                   "fleet scan current (%d records, last %.1f hours ago)" % (
                       count, age / 3600))


CHECKS = (
    check_database,
    check_disk_space,
    check_email,
    check_auth,
    check_license,
    check_signing_backend,
    check_scheduler,
    check_stuck_jobs,
    check_deliveries,
    check_helper,
    check_fleet_scan,
)


def run_all(get_setting, db):
    """Run every check, never raising. Returns the full report dict."""
    results = []
    for fn in CHECKS:
        cid = fn.__name__.replace("check_", "").replace("_", "-")
        try:
            results.append(fn(get_setting, db))
        except Exception as e:              # noqa: BLE001
            results.append(_result(cid, "core", "error",
                                   "check crashed: %s" % str(e)[:160]))
    worst = max((_SEVERITY.get(r["status"], 0) for r in results), default=0)
    overall = {0: "ok", 1: "warn", 2: "error", 3: "fail"}[worst]
    return {"generated_at": _now(), "overall": overall, "checks": results}


def to_text(report):
    """Human-readable rendering for the support bundle."""
    lines = ["Certheim configuration self-check",
             "Generated: %s" % report["generated_at"],
             "Overall:   %s" % report["overall"].upper(), ""]
    for r in report["checks"]:
        lines.append("[%-5s] %-16s %s" % (r["status"].upper(), r["id"], r["summary"]))
        if r.get("hint"):
            lines.append("        hint: %s" % r["hint"])
    return "\n".join(lines) + "\n"
