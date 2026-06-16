#!/usr/bin/env python3
"""CSR Dashboard API - Linux generation, manual signing, optional cert upload-back."""
import json
import logging
import logging.handlers
import calendar
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import io
import csv
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify, Response, abort, g

import notify
import gitlab_integration

# ---------- Configuration ----------
# Deployment-specific values come from an env file so a new environment is
# a single file to edit. Search order: $CSR_DASHBOARD_ENV, then the default
# path. Missing file is fine - built-in defaults below match the rcdn01
# baseline. Format: plain KEY=value lines, # comments allowed, no shell
# expansion (read with stdlib, so no python-dotenv dependency - matters for
# the offline/air-gapped bundle).
_ENV_DEFAULTS = {
    "CSR_HELPER_PATH": "/root/sslcerts/scripts/csr_dashboard_helper.sh",
    "CSR_DB_PATH": "/var/lib/csr-dashboard/jobs.db",
    "CSR_ISSUED_DIR": "/home/ansible/issued",
    "CSR_SESSION_TTL": "28800",          # 8h in seconds
    "CSR_MAX_CERTLIST_BYTES": "65536",
    "CSR_MAX_CSR_BYTES": "32768",
    "CSR_MAX_CERT_BYTES": "65536",
}

def _load_env_file():
    """Merge an optional KEY=value env file over os.environ over defaults."""
    values = dict(_ENV_DEFAULTS)
    path = os.environ.get("CSR_DASHBOARD_ENV",
                          "/etc/csr-dashboard/csr-dashboard.env")
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass  # no env file - defaults + real environment win
    for k in list(values):
        if k in os.environ:
            values[k] = os.environ[k]
    return values

_ENV = _load_env_file()

def _env_int(key):
    try:
        return int(_ENV[key])
    except (KeyError, ValueError):
        return int(_ENV_DEFAULTS[key])

HELPER = ["sudo", "-n", _ENV["CSR_HELPER_PATH"]]
DB_PATH = _ENV["CSR_DB_PATH"]
ISSUED_DIR = _ENV["CSR_ISSUED_DIR"]

# Application version - read from the VERSION file deployed alongside app.py.
# Single source of truth is the repo's VERSION file; bump it per release.
def _read_version():
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "VERSION")) as f:
            return f.read().strip() or "unknown"
    except OSError:
        return "unknown"

APP_VERSION = _read_version()

MAX_CERTLIST_BYTES = _env_int("CSR_MAX_CERTLIST_BYTES")
MAX_CSR_BYTES = _env_int("CSR_MAX_CSR_BYTES")
MAX_CERT_BYTES = _env_int("CSR_MAX_CERT_BYTES")
SESSION_TTL = _env_int("CSR_SESSION_TTL")

CERTLIST_LINE_RE = re.compile(r"^[A-Za-z0-9._,@+:-]{0,253}$")
CSR_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}\.csr$")
KEY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}\.key$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")
JOB_ID_RE = re.compile(r"^[a-f0-9]{32}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
GROUP_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")

# Cert types supported by the helper's generate-typed subcommand. Must match
# CERT_TYPE_LIST in csr_dashboard_helper.d/10-certtypes.sh.
# "server-client" is a legacy alias accepted on input, expanded to client+web.
CERT_TYPES_ALLOWED = ("web", "client", "email", "codesign",
                      "ipsec", "ocsp", "timestamp", "8021x")
EXCLUSIVE_CERT_TYPES = {"codesign", "ocsp", "timestamp"}

# Key algorithms the helper can generate. Must match KEY_ALGO_RE in
# csr_dashboard_helper.d/20-generate.sh.
KEY_ALGOS_ALLOWED = ("rsa2048", "rsa3072", "rsa4096", "ecdsa256", "ecdsa384")

# Built-in templates seeded on first run, named after the familiar Windows
# AD CS certificate templates so people coming from certtmpl.msc recognize
# them. Global scope (owner_dn NULL, group_id NULL): visible to everyone,
# manageable by admins. (name, cert_types_csv, description)
BUILTIN_TEMPLATES = (
    ("Web Server", "web",
     "TLS server certificate (Windows 'Web Server' template equivalent)"),
    ("Computer", "client,web",
     "Machine identity: server + client auth (Windows 'Computer' template equivalent)"),
    ("Workstation Authentication", "client",
     "Client authentication only (Windows 'Workstation Authentication' equivalent)"),
    ("User", "client,email",
     "User identity: client auth + S/MIME email (Windows 'User' template equivalent)"),
    ("RAS and IAS Server", "client,web",
     "Network access server: server + client auth (Windows 'RAS and IAS Server' equivalent)"),
    ("Code Signing", "codesign",
     "Code signing (Windows 'Code Signing' template equivalent)"),
    ("OCSP Response Signing", "ocsp",
     "OCSP responder signing (Windows 'OCSP Response Signing' equivalent)"),
    ("IPSec", "ipsec",
     "IPSec/IKE endpoint (Windows 'IPSec' template equivalent)"),
)


def _normalize_cert_types(value):
    """Accepts a string ("web", "web,client", legacy "server-client") or a
    list of type strings. Returns (ok, canonical_csv_or_None, err).
    canonical form: deduped, sorted, comma-joined, e.g. "client,web".
    None input -> (True, None, None) so callers can apply their own default."""
    if value is None:
        return True, None, None
    if isinstance(value, str):
        parts = [p.strip().lower() for p in value.split(",")]
    elif isinstance(value, list):
        parts = [str(p).strip().lower() for p in value]
    else:
        return False, None, "cert_type must be a string or array"

    out = []
    for p in parts:
        if not p:
            continue
        if p == "server-client":  # legacy alias
            for q in ("client", "web"):
                if q not in out:
                    out.append(q)
            continue
        if p not in CERT_TYPES_ALLOWED:
            return False, None, f"unknown cert type: {p}"
        if p not in out:
            out.append(p)

    if not out:
        return True, None, None

    if len(out) > 1:
        bad = [p for p in out if p in EXCLUSIVE_CERT_TYPES]
        if bad:
            return False, None, f"type '{bad[0]}' cannot be combined with other types"

    return True, ",".join(sorted(out)), None

# ---------- Outbound webhooks ----------
WEBHOOK_EVENTS = (
    "job.created",
    "job.issued",
    "job.cancelled",
    "job.failed",
    "feedback.submitted",
)
WEBHOOK_TIMEOUT = 10  # seconds
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")

# Thread pool for fire-and-forget webhook dispatch. Bounded so a slow
# endpoint can't pile up unbounded threads.
_webhook_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="webhook")

DASHBOARD_URL_FALLBACK = "https://nipat-pl-rcdn01.eucom.mil/csr/"


def _webhook_payload(event, data):
    """Build the canonical JSON payload posted to webhooks."""
    return {
        "event": event,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dashboard_url": DASHBOARD_URL_FALLBACK,
        "data": data,
    }


def _send_webhook_sync(url, payload, headers, timeout=WEBHOOK_TIMEOUT):
    """POST a payload to a URL. Returns (status_code, error_msg or None).
    Runs in the caller's thread; safe to call from worker pool OR sync test."""
    body = json.dumps(payload).encode("utf-8")
    request_headers = {
        "Content-Type": "application/json",
        "User-Agent": "csr-dashboard/2.2",
    }
    if isinstance(headers, dict):
        for k, v in headers.items():
            if k and v is not None:
                request_headers[str(k)] = str(v)

    status_code = 0
    error_msg = None
    try:
        req = urllib.request.Request(
            url, data=body, headers=request_headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            # Drain a small amount of the body so connection closes cleanly
            try:
                resp.read(1024)
            except Exception:
                pass
    except urllib.error.HTTPError as e:
        status_code = e.code
        error_msg = f"HTTP {e.code}: {e.reason}"[:200]
    except urllib.error.URLError as e:
        error_msg = f"URLError: {e.reason}"[:200]
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)[:160]}"

    return status_code, error_msg


def _dispatch_webhook_worker(webhook_id, name, url, event, data, headers):
    """Worker function for a single webhook delivery. Logs result and
    updates the webhook row's last_* counters. Runs in webhook thread pool."""
    payload = _webhook_payload(event, data)
    status_code, error_msg = _send_webhook_sync(url, payload, headers)

    try:
        with db() as conn:
            conn.execute("""
                UPDATE webhooks
                   SET last_called_at = ?,
                       last_status_code = ?,
                       last_error = ?,
                       call_count = call_count + 1
                 WHERE id = ?
            """, (time.time(), status_code, error_msg, webhook_id))
    except Exception as e:
        sys.stderr.write(f"webhook status update failed for #{webhook_id}: {e}\n")

    # Background-safe audit log (no Flask g context available here)
    ok = (200 <= status_code < 300) and not error_msg
    audit.info(
        f"req=webhook-bg action=webhook_dispatch "
        f"result={'ok' if ok else 'fail'} "
        f"webhook_id={webhook_id} name={name!r} event={event} "
        f"status={status_code} error={error_msg or '-'}"
    )


def fire_webhooks(event, data):
    """Look up enabled webhooks subscribed to this event and dispatch them
    asynchronously. Caller's request continues immediately; never raises."""
    if event not in WEBHOOK_EVENTS:
        return
    try:
        with db() as conn:
            rows = conn.execute(
                "SELECT id, name, url, events, headers FROM webhooks WHERE enabled = 1"
            ).fetchall()
    except Exception as e:
        sys.stderr.write(f"webhook list failed: {e}\n")
        return

    for r in rows:
        try:
            subscribed = set(json.loads(r["events"] or "[]"))
        except (ValueError, TypeError):
            continue
        if event not in subscribed:
            continue
        try:
            headers = json.loads(r["headers"] or "{}") if r["headers"] else {}
        except (ValueError, TypeError):
            headers = {}

        try:
            _webhook_pool.submit(
                _dispatch_webhook_worker,
                r["id"], r["name"], r["url"], event, data, headers,
            )
        except RuntimeError:
            # Pool shutdown during interpreter exit, etc. Best-effort.
            pass



def _validate_email(addr):
    """Return (ok, normalized_or_none, error_message_or_none)."""
    if addr is None:
        return True, None, None
    if not isinstance(addr, str):
        return False, None, "email must be a string"
    addr = addr.strip()
    if not addr:
        return True, None, None
    if len(addr) > 254:
        return False, None, "email too long"
    if not EMAIL_RE.match(addr):
        return False, None, "invalid email format"
    return True, addr, None

# ---------- Logging ----------
audit = logging.getLogger("csr.audit")
audit.setLevel(logging.INFO)
_h = logging.handlers.SysLogHandler(
    address="/dev/log",
    facility=logging.handlers.SysLogHandler.LOG_AUTHPRIV,
)
_h.setFormatter(logging.Formatter("csr-dashboard[%(process)d]: %(message)s"))
audit.addHandler(_h)

app = Flask(__name__)

# ---------- DB ----------
def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id              TEXT PRIMARY KEY,
            created_at      REAL NOT NULL,
            requester_dn    TEXT NOT NULL,
            requester_serial TEXT,
            requester_ip    TEXT,
            requester_email TEXT,
            target_host     TEXT NOT NULL,
            sans_json       TEXT NOT NULL DEFAULT '[]',
            csr_pem         TEXT NOT NULL,
            cert_pem        TEXT,
            status          TEXT NOT NULL,
            completed_at    REAL,
            completed_by_dn TEXT,
            error           TEXT,
            has_local_key   INTEGER NOT NULL DEFAULT 0,
            local_key_name  TEXT,
            source          TEXT NOT NULL DEFAULT 'rhel'
        )
    """)
    # Migrations for existing databases (idempotent)
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    if "requester_email" not in existing_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN requester_email TEXT")
    # GitLab issue link (issue-driven signing loop)
    if "gitlab_issue_iid" not in existing_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN gitlab_issue_iid INTEGER")
    if "gitlab_issue_url" not in existing_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN gitlab_issue_url TEXT")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_requester_dn ON jobs(requester_dn)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_target_host ON jobs(target_host)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at)")

    # Users table for accounts auto-created on first CAC auth
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            dn              TEXT PRIMARY KEY,
            cn              TEXT,
            email           TEXT,
            is_admin        INTEGER NOT NULL DEFAULT 0,
            is_active       INTEGER NOT NULL DEFAULT 1,
            tutorial_dismissed INTEGER NOT NULL DEFAULT 0,
            created_at      REAL NOT NULL,
            last_seen_at    REAL NOT NULL,
            notes           TEXT
        )
    """)
    # Idempotent migration for tutorial_dismissed (pre-existing users table)
    user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "tutorial_dismissed" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN tutorial_dismissed INTEGER NOT NULL DEFAULT 0")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_admin ON users(is_admin)")

    # User feedback for the admin dashboard
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_dn         TEXT NOT NULL,
            submitted_at    REAL NOT NULL,
            category        TEXT NOT NULL,
            message         TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'new',
            read_at         REAL,
            read_by_dn      TEXT,
            resolved_at     REAL,
            resolved_by_dn  TEXT,
            resolution_notes TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_submitted ON feedback(submitted_at)")

    # Saved cert-type templates (personal or group-scoped)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cert_templates (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            description     TEXT,
            cert_types      TEXT NOT NULL,
            owner_dn        TEXT,
            group_id        INTEGER,
            created_at      REAL NOT NULL,
            created_by_dn   TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_templates_owner ON cert_templates(owner_dn)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_templates_group ON cert_templates(group_id)")

    # Seed the Windows-style built-in templates once (first run only, so
    # admin deletions stick across restarts).
    seeded = conn.execute(
        "SELECT COUNT(*) FROM cert_templates WHERE created_by_dn = 'system'"
    ).fetchone()[0]
    if seeded == 0:
        now = time.time()
        for t_name, t_types, t_desc in BUILTIN_TEMPLATES:
            conn.execute("""
                INSERT INTO cert_templates
                    (name, description, cert_types, owner_dn, group_id,
                     created_at, created_by_dn)
                VALUES (?, ?, ?, NULL, NULL, ?, 'system')
            """, (t_name, t_desc, t_types, now))

    # Outbound webhooks for integrations (ServiceNow, GitLab, Slack, etc.)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS webhooks (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            name                TEXT NOT NULL,
            url                 TEXT NOT NULL,
            events              TEXT NOT NULL,
            headers             TEXT,
            enabled             INTEGER NOT NULL DEFAULT 1,
            created_at          REAL NOT NULL,
            created_by_dn       TEXT,
            last_called_at      REAL,
            last_status_code    INTEGER,
            last_error          TEXT,
            call_count          INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks(enabled)")

    # Groups for team-shared key access
    conn.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL UNIQUE,
            description  TEXT,
            email        TEXT,
            created_at   REAL NOT NULL
        )
    """)
    # Idempotent migration for the email column (groups table may pre-date it)
    group_cols = {row[1] for row in conn.execute("PRAGMA table_info(groups)").fetchall()}
    if "email" not in group_cols:
        conn.execute("ALTER TABLE groups ADD COLUMN email TEXT")
    if "notify_on_new" not in group_cols:
        conn.execute("ALTER TABLE groups ADD COLUMN notify_on_new INTEGER NOT NULL DEFAULT 0")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_groups (
            user_dn   TEXT NOT NULL,
            group_id  INTEGER NOT NULL,
            added_at  REAL NOT NULL,
            PRIMARY KEY (user_dn, group_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_groups_dn ON user_groups(user_dn)")
    ug_cols = {row[1] for row in conn.execute("PRAGMA table_info(user_groups)").fetchall()}
    if "role" not in ug_cols:
        conn.execute("ALTER TABLE user_groups ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_groups_gid ON user_groups(group_id)")

    # Add group_id to jobs (idempotent)
    job_cols = {row[1] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    if "group_id" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN group_id INTEGER")
    if "cert_type" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN cert_type TEXT")
    if "expires_at" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN expires_at REAL")
    if "renewed_from" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN renewed_from TEXT")
    if "key_algo" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN key_algo TEXT")
    if "expiry_warned" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN expiry_warned INTEGER NOT NULL DEFAULT 0")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_group_id ON jobs(group_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_cert_type ON jobs(cert_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_expires ON jobs(expires_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_renewed_from ON jobs(renewed_from)")

    # In-database audit trail (mirrors the syslog audit stream, searchable
    # from the admin UI)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ts      REAL NOT NULL,
            actor   TEXT,
            action  TEXT NOT NULL,
            result  TEXT NOT NULL,
            detail  TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")

    # Fleet-imported certificates (populated by import_certs.py via the
    # fleet-cert-scan playbook; tracked for expiry alongside dashboard jobs)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fleet_certs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            host          TEXT NOT NULL,
            path          TEXT NOT NULL,
            fingerprint   TEXT NOT NULL,
            cn            TEXT,
            sans_json     TEXT,
            issuer        TEXT,
            serial        TEXT,
            not_before    REAL,
            expires_at    REAL,
            cert_types    TEXT,
            notify_email  TEXT,
            first_seen    REAL NOT NULL,
            last_seen     REAL NOT NULL,
            expiry_warned INTEGER NOT NULL DEFAULT 0,
            pem           TEXT,
            UNIQUE(host, path)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_expires ON fleet_certs(expires_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_host ON fleet_certs(host)")

    # One-time backfill: parse notAfter from already-issued certs that
    # pre-date the expires_at column. Best-effort.
    backfill = conn.execute(
        "SELECT id, cert_pem FROM jobs "
        "WHERE status = 'issued' AND cert_pem IS NOT NULL AND expires_at IS NULL"
    ).fetchall()
    for bf in backfill:
        exp = _cert_expiry(bf["cert_pem"])
        if exp:
            conn.execute("UPDATE jobs SET expires_at = ? WHERE id = ?",
                         (exp, bf["id"]))

    conn.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    conn.close()

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# ---------- Common helpers ----------
def client_identity():
    dn = request.headers.get("X-Client-DN", "").strip()
    verify = request.headers.get("X-Client-Verify", "").strip()
    serial = request.headers.get("X-Client-Serial", "").strip()
    if verify == "SUCCESS" and dn:
        return {"dn": dn, "serial": serial}
    return {"dn": f"ip:{request.remote_addr}", "serial": "-"}

def log_event(action, result, **extra):
    parts = [
        f"req={g.req_id}", f"action={action}", f"result={result}",
        f"src={request.remote_addr}",
        f"user=\"{(g.identity or {}).get('dn','-')}\"",
        f"serial={(g.identity or {}).get('serial','-')}",
    ]
    for k, v in extra.items():
        parts.append(f"{k}={v}")
    audit.info(" ".join(parts))
    # Mirror into the searchable audit table. Best-effort: never let audit
    # storage break the request path.
    try:
        actor = (g.identity or {}).get("dn")
        with db() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, actor, action, result, detail) "
                "VALUES (?, ?, ?, ?, ?)",
                (time.time(), actor, action, result,
                 json.dumps({k: str(v)[:256] for k, v in extra.items()})),
            )
    except Exception:
        pass

def run_helper(args, stdin=None, timeout=120):
    proc = subprocess.run(
        HELPER + args, input=stdin, capture_output=True, text=True,
        timeout=timeout, env={"PATH": "/usr/bin:/bin"},
    )
    if proc.returncode != 0:
        sys.stderr.write(
            f"run_helper FAILED args={args!r} rc={proc.returncode} "
            f"stderr={proc.stderr!r} stdout={proc.stdout!r}\n"
        )
        sys.stderr.flush()
    return proc.returncode, proc.stdout, proc.stderr

def require_auth(fn):
    """Authenticated CAC user with is_active=1. Auto-creates user row on first hit."""
    @wraps(fn)
    def w(*a, **kw):
        if not g.identity:
            log_event(fn.__name__, "deny_unauth")
            abort(403)
        if not g.user:
            g.user = _upsert_user(g.identity["dn"])
        if not g.user or not g.user.get("is_active"):
            log_event(fn.__name__, "deny_inactive",
                      dn=(g.identity.get("dn", "-"))[:128])
            abort(403)
        return fn(*a, **kw)
    return w

def require_admin(fn):
    """Authenticated, active user with is_admin=1."""
    @wraps(fn)
    def w(*a, **kw):
        if not g.identity:
            log_event(fn.__name__, "deny_unauth")
            abort(403)
        if not g.user:
            g.user = _upsert_user(g.identity["dn"])
        if not g.user or not g.user.get("is_active"):
            log_event(fn.__name__, "deny_inactive",
                      dn=(g.identity.get("dn", "-"))[:128])
            abort(403)
        if not g.user.get("is_admin"):
            log_event(fn.__name__, "deny_not_admin",
                      dn=g.identity["dn"][:128])
            abort(403)
        return fn(*a, **kw)
    return w

def require_csrf(fn):
    @wraps(fn)
    def w(*a, **kw):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if request.headers.get("X-Requested-With") != "csr-dashboard":
                log_event(fn.__name__, "deny_csrf")
                abort(403)
        return fn(*a, **kw)
    return w

# ---------- User account helpers ----------
def _cn_from_dn(dn):
    """Extract CN from a subject DN for display."""
    if not dn or "CN=" not in dn:
        return dn
    try:
        return dn.split("CN=", 1)[1].split(",", 1)[0].strip()
    except Exception:
        return dn

def _load_user(dn):
    """Fetch user row by DN. Returns dict or None."""
    if not dn:
        return None
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE dn = ?", (dn,)).fetchone()
    return dict(row) if row else None

def _upsert_user(dn):
    """Create user row if missing, update last_seen_at. Returns user dict."""
    if not dn:
        return None
    cn = _cn_from_dn(dn)
    now = time.time()
    with db() as conn:
        existing = conn.execute(
            "SELECT dn FROM users WHERE dn = ?", (dn,)
        ).fetchone()
        if not existing:
            conn.execute("""
                INSERT INTO users (dn, cn, email, is_admin, is_active,
                                   created_at, last_seen_at)
                VALUES (?, ?, NULL, 0, 1, ?, ?)
            """, (dn, cn, now, now))
            log_event("user_created", "ok", dn=dn[:128])
        else:
            conn.execute(
                "UPDATE users SET last_seen_at = ?, cn = ? WHERE dn = ?",
                (now, cn, dn),
            )
        row = conn.execute("SELECT * FROM users WHERE dn = ?", (dn,)).fetchone()
    return dict(row) if row else None

def _user_group_ids(dn):
    """Return set of group_ids the user belongs to."""
    if not dn:
        return set()
    with db() as conn:
        rows = conn.execute(
            "SELECT group_id FROM user_groups WHERE user_dn = ?", (dn,)
        ).fetchall()
    return {r["group_id"] for r in rows}

def _user_groups(dn):
    """Return list of group dicts the user belongs to."""
    if not dn:
        return []
    with db() as conn:
        rows = conn.execute("""
            SELECT g.id, g.name, g.description
              FROM groups g
              JOIN user_groups ug ON ug.group_id = g.id
             WHERE ug.user_dn = ?
             ORDER BY g.name
        """, (dn,)).fetchall()
    return [dict(r) for r in rows]

def _group_by_id(group_id):
    """Return group dict or None."""
    if group_id is None:
        return None
    with db() as conn:
        row = conn.execute(
            "SELECT id, name, description, email, created_at FROM groups WHERE id = ?",
            (group_id,),
        ).fetchone()
    return dict(row) if row else None

def _group_email(group_id):
    """Return the group's notification email, or None if unset/no group."""
    grp = _group_by_id(group_id)
    if not grp:
        return None
    e = (grp.get("email") or "").strip()
    return e or None

def _group_role(dn, group_id):
    """Return 'owner', 'member', or None for the user's role in a group."""
    if not dn or not group_id:
        return None
    with db() as conn:
        row = conn.execute(
            "SELECT role FROM user_groups WHERE user_dn = ? AND group_id = ?",
            (dn, group_id)).fetchone()
    return row["role"] if row else None


def _is_group_owner_or_admin(dn, group_id):
    if g.user and g.user.get("is_admin"):
        return True
    return _group_role(dn, group_id) == "owner"


def _group_owner_emails(group_id):
    """Emails of all owners of a group (active users with an email set)."""
    if not group_id:
        return []
    with db() as conn:
        rows = conn.execute("""
            SELECT u.email FROM user_groups ug
              JOIN users u ON u.dn = ug.user_dn
             WHERE ug.group_id = ? AND ug.role = 'owner'
               AND u.is_active = 1 AND u.email IS NOT NULL AND u.email != ''
        """, (group_id,)).fetchall()
    return [r["email"] for r in rows]


def _is_signer(dn):
    """True if the user is a member of any signer group (notify_on_new=1)."""
    if not dn:
        return False
    with db() as conn:
        row = conn.execute("""
            SELECT 1
              FROM user_groups ug
              JOIN groups gr ON gr.id = ug.group_id
             WHERE ug.user_dn = ? AND gr.notify_on_new = 1
             LIMIT 1
        """, (dn,)).fetchone()
    return row is not None

def _signer_recipients():
    """Emails to notify when new CSRs are created: for every group flagged
    notify_on_new, the group's distribution email plus every active member's
    email. Deduplicated, order-stable."""
    out, seen = [], set()
    with db() as conn:
        for r in conn.execute(
            "SELECT email FROM groups WHERE notify_on_new = 1 "
            "AND email IS NOT NULL AND TRIM(email) != ''"
        ).fetchall():
            e = r["email"].strip()
            if e.lower() not in seen:
                seen.add(e.lower()); out.append(e)
        for r in conn.execute("""
            SELECT DISTINCT u.email
              FROM users u
              JOIN user_groups ug ON ug.user_dn = u.dn
              JOIN groups gr ON gr.id = ug.group_id
             WHERE gr.notify_on_new = 1
               AND u.is_active = 1
               AND u.email IS NOT NULL AND TRIM(u.email) != ''
        """).fetchall():
            e = r["email"].strip()
            if e.lower() not in seen:
                seen.add(e.lower()); out.append(e)
    return out

@app.before_request
def _setup():
    g.req_id = request.headers.get("X-Request-Id") or uuid.uuid4().hex
    g.identity = client_identity()
    g.user = None
    if g.identity and g.identity["dn"]:
        # Cheap lookup; auto-creates happen in require_auth on first hit
        g.user = _load_user(g.identity["dn"])

@app.after_request
def _harden(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Request-Id"] = g.get("req_id", "-")
    return resp

@app.errorhandler(Exception)
def _err(e):
    code = getattr(e, "code", 500)
    # For 5xx (real exceptions, not aborts), include the message and a
    # one-line traceback summary so the journal points at the failing call.
    if code >= 500:
        import traceback
        tb = traceback.format_exc(limit=8)
        last = tb.strip().splitlines()[-1] if tb else ""
        log_event("error", "exception", code=code, type=type(e).__name__,
                  msg=str(e)[:160], where=last[:200])
    else:
        log_event("error", "exception", code=code, type=type(e).__name__)
    return jsonify(error="internal error", request_id=g.get("req_id", "-")), code

# ---------- Sessions ----------
_sessions = {}
_sessions_lock = threading.Lock()

def _expire_sessions():
    now = time.time()
    for sid in list(_sessions.keys()):
        if _sessions[sid].get("expires", 0) < now:
            _sessions.pop(sid, None)

def _get_or_create_session():
    if not g.identity:
        return None, False
    sid = request.cookies.get("csr_sid")
    with _sessions_lock:
        _expire_sessions()
        if sid and sid in _sessions and _sessions[sid]["dn"] == g.identity["dn"]:
            _sessions[sid]["expires"] = time.time() + SESSION_TTL
            return sid, False
        sid = secrets.token_urlsafe(32)
        _sessions[sid] = {"dn": g.identity["dn"], "created": time.time(),
                          "expires": time.time() + SESSION_TTL, "keys": []}
        return sid, True

def _set_session_cookie(resp, sid):
    if sid:
        resp.set_cookie("csr_sid", sid, httponly=True, secure=True,
                        samesite="Strict", path="/csr/")
    return resp

def _get_session_keys():
    sid = request.cookies.get("csr_sid")
    if not sid or not g.identity:
        return []
    with _sessions_lock:
        _expire_sessions()
        s = _sessions.get(sid)
        if not s or s["dn"] != g.identity["dn"]:
            return []
        return list(s.get("keys", []))

def _add_session_keys(sid, new_keys):
    with _sessions_lock:
        if sid in _sessions:
            existing = set(_sessions[sid].get("keys", []))
            existing.update(new_keys)
            _sessions[sid]["keys"] = sorted(existing)
            _sessions[sid]["expires"] = time.time() + SESSION_TTL

def _parse_helper_listing(output):
    rows = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            try:
                row = {"name": parts[0], "size": int(parts[1]), "mtime": parts[2]}
                if len(parts) >= 4:
                    row["mtime_epoch"] = float(parts[3])
                rows.append(row)
            except ValueError:
                continue
    return rows

def _parse_csr_subject(csr_pem):
    """Return (cn, sans) by parsing openssl req -text output. Best-effort."""
    try:
        proc = subprocess.run(
            ["openssl", "req", "-noout", "-text"],
            input=csr_pem, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            return "", []
    except Exception:
        return "", []

    cn = ""
    sans = []
    capture_san = False
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Subject:"):
            m = re.search(r"CN\s*=\s*([^,/]+)", stripped)
            if m:
                cn = m.group(1).strip()
        if "X509v3 Subject Alternative Name:" in stripped:
            capture_san = True
            continue
        if capture_san and stripped:
            for part in stripped.split(","):
                part = part.strip()
                if part.startswith("DNS:"):
                    sans.append(part[4:].strip())
                elif part.startswith("IP Address:"):
                    sans.append(part[11:].strip())
                elif part.startswith("IP:"):
                    sans.append(part[3:].strip())
            capture_san = False
    return cn, sans

def _csr_pubkey(csr_pem):
    try:
        proc = subprocess.run(
            ["openssl", "req", "-noout", "-pubkey"],
            input=csr_pem, capture_output=True, text=True, timeout=10,
        )
        return proc.stdout.strip() if proc.returncode == 0 else None
    except Exception:
        return None

def _cert_pubkey(cert_pem):
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-pubkey"],
            input=cert_pem, capture_output=True, text=True, timeout=10,
        )
        return proc.stdout.strip() if proc.returncode == 0 else None
    except Exception:
        return None

def _cert_expiry(cert_pem):
    """Parse the notAfter timestamp out of a PEM certificate. Returns epoch
    seconds (UTC) or None if it can't be determined. Never raises."""
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-enddate"],
            input=cert_pem, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            return None
        line = proc.stdout.strip()
        if not line.startswith("notAfter="):
            return None
        # Format: "notAfter=Jun 12 12:34:56 2027 GMT"
        ts = time.strptime(line[len("notAfter="):], "%b %d %H:%M:%S %Y %Z")
        return float(calendar.timegm(ts))
    except Exception:
        return None


def _cert_startdate(cert_pem):
    """Parse notBefore from a PEM cert -> epoch or None."""
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-startdate"],
            input=cert_pem, capture_output=True, text=True, timeout=10,
        )
        line = proc.stdout.strip()
        if proc.returncode != 0 or not line.startswith("notBefore="):
            return None
        ts = time.strptime(line[len("notBefore="):], "%b %d %H:%M:%S %Y %Z")
        return float(calendar.timegm(ts))
    except Exception:
        return None


CA_BUNDLE = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"

def _cert_upload_warnings(cert_pem):
    """Non-blocking sanity checks on an uploaded cert: chain trust against
    the system CA bundle (which includes the imported DoD CAs), and validity
    window sanity. Returns a list of human-readable warning strings."""
    warnings = []
    try:
        proc = subprocess.run(
            ["openssl", "verify", "-CAfile", CA_BUNDLE],
            input=cert_pem, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            detail = detail[-1] if detail else "unknown"
            warnings.append(
                "Certificate does not chain to a trusted CA in the system "
                f"bundle ({detail}). Verify the issuing CA is correct.")
    except Exception:
        pass

    now = time.time()
    nb = _cert_startdate(cert_pem)
    na = _cert_expiry(cert_pem)
    if nb and nb > now + 300:
        warnings.append("Certificate is not yet valid (notBefore is in the future).")
    if na and na <= now:
        warnings.append("Certificate is ALREADY EXPIRED - the job will immediately show as expired.")
    elif na and na <= now + 30 * 86400:
        days = int((na - now) / 86400)
        warnings.append(f"Certificate expires in only {days} day(s).")
    return warnings


def _verify_cert_matches_csr(csr_pem, cert_pem):
    csr_pk = _csr_pubkey(csr_pem)
    cert_pk = _cert_pubkey(cert_pem)
    if not csr_pk or not cert_pk:
        return False
    return secrets.compare_digest(csr_pk, cert_pk)

# ============================================================
# Misc
# ============================================================
@app.get("/api/health")
def health():
    return jsonify(ok=True, version=APP_VERSION)

@app.get("/api/whoami")
@require_auth
def whoami():
    log_event("whoami", "ok")
    return jsonify(dn=g.identity["dn"])

@app.get("/api/session")
@require_auth
def session_info():
    sid, is_new = _get_or_create_session()
    log_event("session", "created" if is_new else "renewed")
    return _set_session_cookie(jsonify(ok=True), sid)

@app.post("/api/session/end")
@require_auth
@require_csrf
def session_end():
    sid = request.cookies.get("csr_sid")
    if sid:
        with _sessions_lock:
            _sessions.pop(sid, None)
        log_event("session", "ended")
    resp = jsonify(ok=True)
    resp.delete_cookie("csr_sid", path="/csr/")
    return resp

# ============================================================
# Linux certlist
# ============================================================
def _certlist_get(subcmd, action_name):
    rc, out, err = run_helper([subcmd])
    if rc != 0:
        log_event(action_name, "error", rc=rc)
        return jsonify(error="read failed"), 500
    log_event(action_name, "ok", bytes=len(out))
    return jsonify(content=out)

def _certlist_put(subcmd, action_name):
    payload = request.get_json(silent=True) or {}
    content = payload.get("content", "")
    if not isinstance(content, str):
        return jsonify(error="content must be string"), 400
    if len(content.encode("utf-8")) > MAX_CERTLIST_BYTES:
        log_event(action_name, "deny_size")
        return jsonify(error="payload too large"), 413
    for n, line in enumerate(content.splitlines(), 1):
        if not CERTLIST_LINE_RE.match(line):
            log_event(action_name, "deny_invalid", line=n)
            return jsonify(error=f"invalid characters on line {n}"), 400
    rc, out, err = run_helper([subcmd], stdin=content)
    if rc != 0:
        log_event(action_name, "error", rc=rc)
        return jsonify(error="write failed"), 400
    log_event(action_name, "ok", bytes=len(content))
    return jsonify(ok=True)

@app.get("/api/rhel/certlist")
@require_auth
def get_certlist_rhel():
    return _certlist_get("read-certlist-rhel", "read_certlist_rhel")

@app.post("/api/rhel/certlist")
@require_auth
@require_csrf
def put_certlist_rhel():
    return _certlist_put("write-certlist-rhel", "write_certlist_rhel")

# ============================================================
# Linux generate -> ingest CSRs as jobs
# ============================================================
@app.post("/api/rhel/generate")
@require_auth
@require_csrf
def generate_rhel():
    payload = request.get_json(silent=True) or {}
    submitted_email = payload.get("requester_email")
    # If empty/missing, fall back to user's saved default
    if submitted_email is None or (isinstance(submitted_email, str) and not submitted_email.strip()):
        submitted_email = (g.user or {}).get("email")
    ok, requester_email, err = _validate_email(submitted_email)
    if not ok:
        log_event("generate_rhel", "deny_invalid_email")
        return jsonify(error=err), 400
    if not requester_email:
        log_event("generate_rhel", "deny_no_email")
        return jsonify(error="No notification email on file. Set your email "
                             "in Settings before creating requests."), 400

    # Cert type(s). String or array; defaults to "web" to preserve the
    # existing user experience. Stored canonically (sorted csv).
    ok_ct, cert_type, err_ct = _normalize_cert_types(payload.get("cert_type"))
    if not ok_ct:
        return jsonify(error=err_ct), 400
    if cert_type is None:
        cert_type = "web"

    # Optional group assignment. Users can only assign to groups they belong to.
    # Admins can assign to any existing group.
    group_id = payload.get("group_id")
    if group_id is not None:
        try:
            group_id = int(group_id)
        except (TypeError, ValueError):
            return jsonify(error="invalid group_id"), 400
        if not _group_by_id(group_id):
            return jsonify(error="group does not exist"), 400
        if not g.user.get("is_admin") and group_id not in _user_group_ids(g.identity["dn"]):
            return jsonify(error="you are not a member of that group"), 403

    key_algo = (payload.get("key_algo") or "rsa2048").strip().lower()
    if key_algo not in KEY_ALGOS_ALLOWED:
        return jsonify(error=f"invalid key_algo (allowed: {', '.join(KEY_ALGOS_ALLOWED)})"), 400

    log_event("generate_rhel", "start",
              email=("set" if requester_email else "none"),
              group_id=(group_id if group_id else "-"),
              cert_type=cert_type, key_algo=key_algo)
    sid, _ = _get_or_create_session()
    start_time = time.time() - 2

    rc, out, err = run_helper(["generate-typed", cert_type, key_algo], timeout=600)
    if rc != 0:
        log_event("generate_rhel", "error", rc=rc, cert_type=cert_type)
        return jsonify(returncode=rc, output=out + err, jobs=[]), 500

    rc_l, out_l, _ = run_helper(["list-csrs"])
    new_csrs = [r["name"] for r in _parse_helper_listing(out_l)
                if r.get("mtime_epoch", 0) >= start_time] if rc_l == 0 else []

    rc_k, out_k, _ = run_helper(["list-keys"])
    new_keys = [r["name"] for r in _parse_helper_listing(out_k)
                if r.get("mtime_epoch", 0) >= start_time] if rc_k == 0 else []
    if sid and new_keys:
        _add_session_keys(sid, new_keys)

    job_ids = []
    created_targets = []
    for csr_name in new_csrs:
        rc_g, csr_pem, _ = run_helper(["get-csr", csr_name])
        if rc_g != 0:
            continue
        cn, sans = _parse_csr_subject(csr_pem)
        target = cn or csr_name[:-4]
        local_key = csr_name[:-4] + ".key"
        has_key = local_key in new_keys

        job_id = uuid.uuid4().hex
        with db() as conn:
            conn.execute("""
                INSERT INTO jobs (id, created_at, requester_dn, requester_serial,
                                  requester_ip, requester_email, target_host, sans_json,
                                  csr_pem, status, has_local_key, local_key_name, source,
                                  group_id, cert_type, key_algo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, 'rhel', ?, ?, ?)
            """, (
                job_id, time.time(),
                g.identity["dn"], g.identity.get("serial", "-"), request.remote_addr,
                requester_email,
                target, json.dumps(sans), csr_pem,
                1 if has_key else 0, local_key if has_key else None,
                group_id, cert_type, key_algo,
            ))
        job_ids.append(job_id)
        created_targets.append(target)
        run_helper(["delete-csr", csr_name])
        log_event("job_created", "ok", job_id=job_id, target=target,
                  has_key=int(has_key), source="rhel",
                  email=("set" if requester_email else "none"),
                  group_id=(group_id if group_id else "-"),
                  cert_type=cert_type)
        fire_webhooks("job.created", {
            "job_id": job_id, "target_host": target, "source": "rhel",
            "requester_dn": g.identity["dn"], "requester_email": requester_email,
            "group_id": group_id, "cert_type": cert_type,
            "has_local_key": bool(has_key),
        })
        _open_signing_issue(job_id)

    log_event("generate_rhel", "ok", jobs=len(job_ids), keys=len(new_keys),
              cert_type=cert_type)

    # Notify signer groups (one aggregated email per batch). Best-effort.
    if job_ids:
        try:
            recipients = _signer_recipients()
            if recipients:
                ok_n, reason_n = notify.send_csrs_created(
                    created_targets, cert_type,
                    _cn_from_dn(g.identity["dn"]),
                    (g.user or {}).get("email"),
                    recipients,
                )
                log_event("email_notify", "ok" if ok_n else "skip",
                          event="csrs_created", count=len(created_targets),
                          recipients=len(recipients), reason=reason_n[:96])
        except Exception as e:
            log_event("email_notify", "exception", event="csrs_created",
                      error=str(e)[:128])

    # Clear the on-disk certlist after a successful run so the next page load
    # shows an empty editor. Best-effort: log a warning but don't fail the
    # response if the clear write fails.
    rc_clear, _, _ = run_helper(["write-certlist-rhel"], stdin="")
    if rc_clear != 0:
        log_event("certlist_clear", "warn_failed", rc=rc_clear)
    else:
        log_event("certlist_clear", "ok")

    resp = jsonify(returncode=rc, output=out + err, jobs=job_ids, new_keys=new_keys)
    return _set_session_cookie(resp, sid)

# ============================================================
# External CSR upload
# ============================================================
@app.post("/api/external/submit")
@require_auth
@require_csrf
def submit_external():
    payload = request.get_json(silent=True) or {}
    csr_pem = payload.get("csr_pem", "")
    target_host = payload.get("target_host", "").strip()

    if not isinstance(csr_pem, str) or not (50 < len(csr_pem) <= MAX_CSR_BYTES):
        return jsonify(error="invalid csr_pem"), 400
    if not target_host or not HOSTNAME_RE.match(target_host):
        return jsonify(error="invalid target_host"), 400

    ok, requester_email, err = _validate_email(payload.get("requester_email"))
    if not ok:
        return jsonify(error=err), 400
    if requester_email is None:
        requester_email = (g.user or {}).get("email")
    if not requester_email:
        log_event("submit_external", "deny_no_email")
        return jsonify(error="No notification email on file. Set your email "
                             "in Settings before creating requests."), 400

    group_id = payload.get("group_id")
    if group_id is not None:
        try:
            group_id = int(group_id)
        except (TypeError, ValueError):
            return jsonify(error="invalid group_id"), 400
        if not _group_by_id(group_id):
            return jsonify(error="group does not exist"), 400
        if not g.user.get("is_admin") and group_id not in _user_group_ids(g.identity["dn"]):
            return jsonify(error="you are not a member of that group"), 403

    # Cert type(s) are informational for external CSRs (we don't generate
    # them). Optional; string or array.
    ok_ct, cert_type_in, err_ct = _normalize_cert_types(payload.get("cert_type"))
    if not ok_ct:
        return jsonify(error=err_ct), 400

    try:
        proc = subprocess.run(
            ["openssl", "req", "-noout", "-verify"],
            input=csr_pem, capture_output=True, text=True, timeout=10,
        )
        verified = "verify OK" in (proc.stdout + proc.stderr) or proc.returncode == 0
        if not verified:
            log_event("submit_external", "deny_invalid_csr")
            return jsonify(error="CSR signature failed validation"), 400
    except Exception:
        log_event("submit_external", "error_validation")
        return jsonify(error="CSR validation error"), 400

    cn, sans = _parse_csr_subject(csr_pem)
    job_id = uuid.uuid4().hex
    with db() as conn:
        conn.execute("""
            INSERT INTO jobs (id, created_at, requester_dn, requester_serial,
                              requester_ip, requester_email, target_host, sans_json,
                              csr_pem, status, has_local_key, source, group_id,
                              cert_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, 'external', ?, ?)
        """, (
            job_id, time.time(),
            g.identity["dn"], g.identity.get("serial", "-"), request.remote_addr,
            requester_email,
            target_host, json.dumps(sans), csr_pem,
            group_id, cert_type_in,
        ))
    log_event("submit_external", "ok", job_id=job_id, target=target_host,
              cn=cn or "-", email=("set" if requester_email else "none"),
              group_id=(group_id if group_id else "-"),
              cert_type=(cert_type_in or "-"))
    fire_webhooks("job.created", {
        "job_id": job_id, "target_host": target_host, "source": "external",
        "requester_dn": g.identity["dn"], "requester_email": requester_email,
        "group_id": group_id, "cert_type": cert_type_in,
        "has_local_key": False, "cn": cn,
    })
    _open_signing_issue(job_id)

    # Notify signer groups about the new external CSR. Best-effort.
    try:
        recipients = _signer_recipients()
        if recipients:
            ok_n, reason_n = notify.send_csrs_created(
                [target_host], cert_type_in or "unspecified",
                _cn_from_dn(g.identity["dn"]),
                (g.user or {}).get("email"),
                recipients,
            )
            log_event("email_notify", "ok" if ok_n else "skip",
                      event="csrs_created", count=1,
                      recipients=len(recipients), reason=reason_n[:96])
    except Exception as e:
        log_event("email_notify", "exception", event="csrs_created",
                  error=str(e)[:128])

    return jsonify(job_id=job_id, status="pending", cn=cn, sans=sans)

# ============================================================
# Jobs API
# ============================================================
def _sweep_expired():
    """Flip issued jobs whose cert notAfter has passed to 'expired'. Runs
    lazily on job reads — cheap indexed query, no cron needed."""
    now = time.time()
    with db() as conn:
        rows = conn.execute(
            "SELECT id, target_host, requester_email, group_id FROM jobs "
            "WHERE status = 'issued' AND expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        ).fetchall()
        if not rows:
            return
        conn.execute(
            "UPDATE jobs SET status = 'expired' "
            "WHERE status = 'issued' AND expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        )
    for r in rows:
        log_event("job_expired", "ok", job_id=r["id"], target=r["target_host"])
        fire_webhooks("job.expired", {
            "job_id": r["id"], "target_host": r["target_host"],
            "requester_email": r["requester_email"],
            "group_id": r["group_id"],
        })


def _row_to_job(r, include_blobs=False, identity_dn=None,
                user_group_ids=None, user_is_admin=False,
                user_is_signer=False):
    cn = _cn_from_dn(r["requester_dn"])
    out = {
        "id": r["id"], "created_at": r["created_at"],
        "requester_dn": r["requester_dn"],
        "requester_cn": cn,
        "requester_email": r["requester_email"],
        # UI prefers email if set, falls back to CN
        "requester_display": r["requester_email"] or cn or r["requester_dn"],
        "target_host": r["target_host"],
        "sans": json.loads(r["sans_json"] or "[]"),
        "status": r["status"],
        "completed_at": r["completed_at"],
        "completed_by_dn": r["completed_by_dn"],
        "completed_by_cn": _cn_from_dn(r["completed_by_dn"]) if r["completed_by_dn"] else None,
        "error": r["error"],
        "has_local_key": bool(r["has_local_key"]),
        "local_key_name": r["local_key_name"], "source": r["source"],
        "group_id": r["group_id"] if "group_id" in r.keys() else None,
        "cert_type": r["cert_type"] if "cert_type" in r.keys() else None,
        "expires_at": r["expires_at"] if "expires_at" in r.keys() else None,
        "key_algo": r["key_algo"] if "key_algo" in r.keys() else None,
        "renewed_from": r["renewed_from"] if "renewed_from" in r.keys() else None,
    }
    if identity_dn is not None:
        out["is_requester"] = (r["requester_dn"] == identity_dn)
        # Mirrors get_job_key authorization: requester or group member.
        # Admin role does NOT grant key access.
        out["can_download_key"] = bool(r["has_local_key"]) and (
            out["is_requester"]
            or (user_group_ids is not None and out["group_id"] in user_group_ids)
        )
        # Mirrors update_job_group authorization: requester or admin.
        # Group membership alone does NOT grant the right to reassign.
        out["can_edit_group"] = out["is_requester"] or user_is_admin
        # Cancel is restricted to the requester or an admin, pending only.
        out["can_cancel"] = (r["status"] == "pending") and (
            out["is_requester"] or user_is_admin
        )
        # Mark-failed is restricted to signer-group members, pending only.
        out["can_mark_failed"] = (r["status"] == "pending") and user_is_signer
    if include_blobs:
        out["csr_pem"] = r["csr_pem"]
        out["cert_pem"] = r["cert_pem"]
    return out

@app.get("/api/jobs")
@require_auth
def list_jobs():
    _sweep_expired()
    a = request.args
    where, params = [], []
    if status := a.get("status"):
        if status not in ("pending", "issued", "failed", "cancelled", "expired"):
            return jsonify(error="invalid status"), 400
        where.append("status = ?"); params.append(status)
    if ew := a.get("expiring_within"):
        try:
            ew_days = max(1, min(int(ew), 365))
        except (TypeError, ValueError):
            return jsonify(error="invalid expiring_within"), 400
        where.append("status = 'issued' AND expires_at IS NOT NULL AND expires_at <= ?")
        params.append(time.time() + ew_days * 86400)
    if requester := a.get("requester"):
        where.append("requester_dn LIKE ?"); params.append(f"%{requester}%")
    if target := a.get("target"):
        where.append("target_host LIKE ?"); params.append(f"%{target}%")
    if source := a.get("source"):
        if source not in ("rhel", "external"):
            return jsonify(error="invalid source"), 400
        where.append("source = ?"); params.append(source)
    if search := a.get("q"):
        where.append("(target_host LIKE ? OR requester_dn LIKE ? OR id LIKE ?)")
        params.extend([f"%{search}%"] * 3)
    if days := a.get("days"):
        try:
            cutoff = time.time() - int(days) * 86400
            where.append("created_at >= ?"); params.append(cutoff)
        except ValueError:
            pass

    try:
        limit = min(int(a.get("limit", 100)), 500)
        offset = max(int(a.get("offset", 0)), 0)
    except ValueError:
        limit, offset = 100, 0

    sql = "SELECT * FROM jobs"
    count_sql = "SELECT COUNT(*) FROM jobs"
    if where:
        clause = " WHERE " + " AND ".join(where)
        sql += clause; count_sql += clause
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"

    with db() as conn:
        rows = conn.execute(sql, params + [limit, offset]).fetchall()
        total = conn.execute(count_sql, params).fetchone()[0]
        # Bulk-fetch group names for any group_ids referenced
        group_ids = {r["group_id"] for r in rows if r["group_id"]}
        groups_map = {}
        if group_ids:
            placeholders = ",".join("?" * len(group_ids))
            for grp_row in conn.execute(
                f"SELECT id, name FROM groups WHERE id IN ({placeholders})",
                list(group_ids),
            ).fetchall():
                groups_map[grp_row["id"]] = grp_row["name"]

    # User context for can_download_key / can_edit_group / can_mark_failed
    user_groups = _user_group_ids(g.identity["dn"])
    user_is_admin = bool(g.user and g.user.get("is_admin"))
    user_is_signer = _is_signer(g.identity["dn"])

    def _enrich(r):
        out = _row_to_job(r, identity_dn=g.identity["dn"],
                          user_group_ids=user_groups,
                          user_is_admin=user_is_admin,
                          user_is_signer=user_is_signer)
        if out["group_id"]:
            out["group_name"] = groups_map.get(out["group_id"])
        return out

    log_event("list_jobs", "ok", count=len(rows), total=total)
    return jsonify(jobs=[_enrich(r) for r in rows],
                   total=total, limit=limit, offset=offset)

@app.get("/api/jobs/<job_id>")
@require_auth
def get_job(job_id):
    if not JOB_ID_RE.match(job_id):
        abort(400)
    _sweep_expired()
    with db() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        abort(404)
    user_groups = _user_group_ids(g.identity["dn"])
    user_is_admin = bool(g.user and g.user.get("is_admin"))
    user_is_signer = _is_signer(g.identity["dn"])
    out = _row_to_job(row, identity_dn=g.identity["dn"],
                      user_group_ids=user_groups,
                      user_is_admin=user_is_admin,
                      user_is_signer=user_is_signer)
    if out["group_id"]:
        grp = _group_by_id(out["group_id"])
        if grp:
            out["group_name"] = grp["name"]
    log_event("get_job", "ok", job_id=job_id)
    return jsonify(out)

@app.get("/api/jobs/<job_id>/csr")
@require_auth
def get_job_csr(job_id):
    if not JOB_ID_RE.match(job_id):
        abort(400)
    with db() as conn:
        row = conn.execute("SELECT csr_pem, target_host FROM jobs WHERE id = ?",
                           (job_id,)).fetchone()
    if not row:
        abort(404)
    log_event("get_job_csr", "ok", job_id=job_id, target=row["target_host"])
    return Response(row["csr_pem"], mimetype="application/pkcs10",
                    headers={"Content-Disposition":
                             f'attachment; filename="{row["target_host"]}.csr"'})

@app.get("/api/jobs/<job_id>/cert")
@require_auth
def get_job_cert(job_id):
    if not JOB_ID_RE.match(job_id):
        abort(400)
    with db() as conn:
        row = conn.execute(
            "SELECT cert_pem, target_host, status FROM jobs WHERE id = ?",
            (job_id,)).fetchone()
    if not row:
        abort(404)
    if row["status"] != "issued" or not row["cert_pem"]:
        return jsonify(error="cert not yet available"), 404
    log_event("get_job_cert", "ok", job_id=job_id)
    return Response(row["cert_pem"], mimetype="application/x-pem-file",
                    headers={"Content-Disposition":
                             f'attachment; filename="{row["target_host"]}.cer"'})

@app.put("/api/jobs/<job_id>/group")
@require_auth
@require_csrf
def update_job_group(job_id):
    """Reassign (or unassign) a job's group after creation.

    Authorized for:
      - the original requester, OR
      - any admin user.

    Non-admins can only assign to groups they belong to. Anyone authorized
    can unassign (group_id=null) regardless of membership.
    """
    if not JOB_ID_RE.match(job_id):
        abort(400)

    payload = request.get_json(silent=True) or {}
    if "group_id" not in payload:
        return jsonify(error="group_id is required (use null to unassign)"), 400

    new_group_id = payload["group_id"]
    if new_group_id is not None:
        try:
            new_group_id = int(new_group_id)
        except (TypeError, ValueError):
            return jsonify(error="invalid group_id"), 400
        if not _group_by_id(new_group_id):
            return jsonify(error="group does not exist"), 400

    with db() as conn:
        row = conn.execute(
            "SELECT requester_dn, target_host, group_id FROM jobs WHERE id = ?",
            (job_id,),
        ).fetchone()
    if not row:
        abort(404)

    is_requester = row["requester_dn"] == g.identity["dn"]
    is_admin = bool(g.user and g.user.get("is_admin"))

    if not (is_requester or is_admin):
        log_event("update_job_group", "deny_not_authorized",
                  job_id=job_id, target=row["target_host"])
        abort(403)

    # Non-admin requesters can only assign to groups they belong to.
    if new_group_id is not None and not is_admin:
        if new_group_id not in _user_group_ids(g.identity["dn"]):
            log_event("update_job_group", "deny_not_in_group",
                      job_id=job_id, target_group=new_group_id)
            return jsonify(error="you are not a member of that group"), 403

    with db() as conn:
        conn.execute(
            "UPDATE jobs SET group_id = ? WHERE id = ?",
            (new_group_id, job_id),
        )

    log_event("update_job_group", "ok",
              job_id=job_id, target=row["target_host"],
              old_group=(row["group_id"] if row["group_id"] is not None else "-"),
              new_group=(new_group_id if new_group_id is not None else "-"),
              via=("admin" if is_admin and not is_requester else "requester"))
    return jsonify(ok=True, group_id=new_group_id)


@app.get("/api/jobs/<job_id>/key")
@require_auth
def get_job_key(job_id):
    """Per-job key download. Authorized for:
      - original requester (CAC DN match), OR
      - any user whose current session has the key claimed, OR
      - any user who is a member of the job's group.
    Admin role does NOT grant key access; admins must be added to the
    relevant group like any other team member.
    """
    if not JOB_ID_RE.match(job_id):
        abort(400)
    with db() as conn:
        row = conn.execute(
            "SELECT requester_dn, has_local_key, local_key_name, target_host, group_id "
            "FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
    if not row:
        abort(404)
    if not row["has_local_key"] or not row["local_key_name"]:
        return jsonify(error="no local key for this job"), 404
    if not KEY_NAME_RE.match(row["local_key_name"]):
        log_event("get_job_key", "deny_invalid_name", job_id=job_id)
        abort(400)

    is_requester = row["requester_dn"] == g.identity["dn"]
    in_session = row["local_key_name"] in _get_session_keys()
    in_group = False
    if row["group_id"] is not None:
        in_group = row["group_id"] in _user_group_ids(g.identity["dn"])

    if not (is_requester or in_session or in_group):
        log_event("get_job_key", "deny_not_authorized", job_id=job_id,
                  target=row["target_host"])
        abort(403)

    rc, out, err = run_helper(["get-key", row["local_key_name"]])
    if rc != 0:
        log_event("get_job_key", "not_found", job_id=job_id,
                  name=row["local_key_name"])
        return jsonify(error="key file not found"), 404

    if is_requester:
        auth_via = "requester"
    elif in_group:
        auth_via = f"group:{row['group_id']}"
    else:
        auth_via = "session"

    log_event("get_job_key", "ok", job_id=job_id,
              name=row["local_key_name"], target=row["target_host"],
              auth_via=auth_via)
    return Response(
        out, mimetype="application/x-pem-file",
        headers={"Content-Disposition":
                 f'attachment; filename="{row["local_key_name"]}"'},
    )

# ============================================================
# Cert upload (manual return path)
# ============================================================
def _attach_signed_cert(job_id, cert_pem, completed_by_dn, source="upload"):
    """Validate a signed cert and attach it to a PENDING job (status->issued),
    drop it to the issued dir, fire the job.issued webhook + email. Returns
    (ok, http_code, result_dict). Shared by the manual upload-cert endpoint
    and the GitLab inbound webhook so both paths behave identically."""
    if not cert_pem or not isinstance(cert_pem, str) or not (50 < len(cert_pem) <= MAX_CERT_BYTES):
        return False, 400, {"error": "invalid cert_pem"}
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-subject"],
            input=cert_pem, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            log_event("attach_cert", "deny_invalid_cert", job_id=job_id, src=source)
            return False, 400, {"error": "not a valid X.509 certificate"}
    except Exception:
        return False, 400, {"error": "cert validation error"}

    with db() as conn:
        row = conn.execute(
            "SELECT csr_pem, target_host, status, requester_email, group_id "
            "FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
        if not row:
            return False, 404, {"error": "job not found"}
        if row["status"] != "pending":
            return False, 409, {"error": f"job in status '{row['status']}', cannot accept cert"}
        if not _verify_cert_matches_csr(row["csr_pem"], cert_pem):
            log_event("attach_cert", "deny_pubkey_mismatch", job_id=job_id,
                      target=row["target_host"], src=source)
            return False, 400, {"error": "cert public key does not match this job's CSR. "
                                          "Verify you uploaded the cert for the correct job."}
        expires_at = _cert_expiry(cert_pem)
        conn.execute(
            "UPDATE jobs SET status='issued', cert_pem=?, completed_at=?, "
            "completed_by_dn=?, expires_at=?, error=NULL WHERE id=?",
            (cert_pem, time.time(), completed_by_dn, expires_at, job_id),
        )

    try:
        Path(ISSUED_DIR).mkdir(parents=True, exist_ok=True)
        target_path = Path(ISSUED_DIR) / f"{row['target_host']}.cer"
        target_path.write_text(cert_pem)
        os.chmod(target_path, 0o644)
        run_helper(["chown-issued", target_path.name])
    except Exception as e:
        sys.stderr.write(f"filesystem drop failed for {row['target_host']}: {e}\n")
        log_event("filesystem_drop", "error", job_id=job_id, error=str(e)[:128])

    upload_warnings = _cert_upload_warnings(cert_pem)
    group_id = row["group_id"] if "group_id" in row.keys() else None
    log_event("attach_cert", "ok", job_id=job_id, target=row["target_host"],
              uploader=completed_by_dn, src=source, warnings=len(upload_warnings))
    fire_webhooks("job.issued", {
        "job_id": job_id, "target_host": row["target_host"],
        "requester_email": row["requester_email"],
        "completed_by_dn": completed_by_dn,
        "completed_by_cn": _cn_from_dn(completed_by_dn),
        "group_id": group_id,
        "expires_at": expires_at,
    })
    try:
        group_email_addr = _group_email(group_id) if group_id else None
        ok_n, reason = notify.send_cert_issued(
            {"id": job_id, "target_host": row["target_host"],
             "requester_email": row["requester_email"]},
            completed_by_dn, group_email=group_email_addr,
        )
        log_event("email_notify", "ok" if ok_n else "skip", job_id=job_id,
                  event="cert_issued",
                  recipient=(row["requester_email"] or group_email_addr or "-"),
                  reason=reason[:96])
    except Exception as e:
        log_event("email_notify", "exception", job_id=job_id, error=str(e)[:128])

    return True, 200, {"ok": True, "status": "issued",
                       "target_host": row["target_host"],
                       "expires_at": expires_at, "warnings": upload_warnings}


def _open_signing_issue(job_id):
    """Best-effort: open a GitLab signing issue for a freshly-created job and
    store the issue iid/url back on it. No-op when the integration is off;
    never raises into the request path."""
    if not gitlab_integration.is_enabled():
        return
    try:
        with db() as conn:
            row = conn.execute(
                "SELECT id, target_host, sans_json, csr_pem, requester_dn, "
                "requester_email, group_id FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if not row:
                return
            group_name = None
            if row["group_id"]:
                grp = conn.execute(
                    "SELECT name FROM groups WHERE id=?", (row["group_id"],)
                ).fetchone()
                group_name = grp["name"] if grp else None
        try:
            sans = json.loads(row["sans_json"] or "[]")
        except (ValueError, TypeError):
            sans = []
        ok, iid, url, reason = gitlab_integration.create_issue({
            "id": row["id"], "target_host": row["target_host"], "sans": sans,
            "csr_pem": row["csr_pem"],
            "requester_cn": _cn_from_dn(row["requester_dn"]),
            "requester_email": row["requester_email"],
            "group_name": group_name,
        })
        if ok and iid:
            with db() as conn:
                conn.execute(
                    "UPDATE jobs SET gitlab_issue_iid=?, gitlab_issue_url=? WHERE id=?",
                    (iid, url, job_id),
                )
        log_event("gitlab_issue", "ok" if ok else "fail", job_id=job_id,
                  iid=(iid or "-"), reason=str(reason)[:120])
    except Exception as e:  # noqa: BLE001
        log_event("gitlab_issue", "exception", job_id=job_id, error=str(e)[:128])


@app.post("/api/jobs/<job_id>/upload-cert")
@require_auth
@require_csrf
def upload_cert(job_id):
    if not JOB_ID_RE.match(job_id):
        abort(400)
    payload = request.get_json(silent=True) or {}
    cert_pem = payload.get("cert_pem", "")
    ok, code, result = _attach_signed_cert(job_id, cert_pem, g.identity["dn"], source="upload")
    return jsonify(**result), code


# ============================================================
# GitLab inbound webhook (issue-driven signing loop)
# ============================================================
@app.post("/api/webhooks/gitlab")
def gitlab_inbound():
    """Inbound GitLab webhook receiver. Validated by the X-Gitlab-Token
    secret (NOT a dashboard session). Handles:
      - Note Hook: a signer pastes/attaches the signed cert in the linked
        issue -> attach it to the matching CSR job (status -> issued).
      - Issue Hook (close): logged as completion confirmation.
    Always returns 200 for handled-but-ignored events so GitLab doesn't retry."""
    if not gitlab_integration.verify_webhook_token(request.headers.get("X-Gitlab-Token", "")):
        log_event("gitlab_webhook", "deny_bad_token", src=request.remote_addr)
        abort(401)
    payload = request.get_json(silent=True) or {}
    kind = payload.get("object_kind") or ""

    if kind == "note":
        obj = payload.get("object_attributes") or {}
        if (obj.get("noteable_type") or "").lower() != "issue":
            return jsonify(ok=True, ignored="note not on an issue")
        iid = (payload.get("issue") or {}).get("iid")
        note_body = obj.get("note") or ""
        author = (payload.get("user") or {}).get("username") or "gitlab"
        project_web = (payload.get("project") or {}).get("web_url") or ""
        if not iid:
            return jsonify(ok=True, ignored="no issue iid")
        with db() as conn:
            row = conn.execute(
                "SELECT id FROM jobs WHERE gitlab_issue_iid=?", (iid,)
            ).fetchone()
        if not row:
            log_event("gitlab_webhook", "no_job_for_issue", iid=iid)
            return jsonify(ok=True, ignored=f"no job linked to issue {iid}")
        job_id = row["id"]
        cert_pem, why = gitlab_integration.extract_cert_from_note(note_body, project_web)
        if not cert_pem:
            log_event("gitlab_webhook", "note_no_cert", job_id=job_id, iid=iid, reason=why)
            return jsonify(ok=True, ignored=why)
        ok, code, result = _attach_signed_cert(
            job_id, cert_pem, f"gitlab:{author}", source="gitlab")
        log_event("gitlab_webhook", "attach_ok" if ok else "attach_fail",
                  job_id=job_id, iid=iid, code=code)
        if ok:
            gitlab_integration.comment_issue(
                iid, f"✅ Signed certificate attached to CSR job `{job_id}` "
                     "by the CSR Dashboard. You may close this issue.")
        else:
            gitlab_integration.comment_issue(
                iid, f"⚠️ Could not attach the certificate: "
                     f"{result.get('error', 'error')}")
        resp = dict(result)
        resp["job_id"] = job_id
        resp.setdefault("ok", ok)
        return jsonify(resp)

    if kind == "issue":
        obj = payload.get("object_attributes") or {}
        iid = obj.get("iid")
        action = obj.get("action")
        if iid and action:
            with db() as conn:
                row = conn.execute(
                    "SELECT id, status FROM jobs WHERE gitlab_issue_iid=?", (iid,)
                ).fetchone()
            if row:
                log_event("gitlab_webhook", f"issue_{action}",
                          job_id=row["id"], iid=iid, job_status=row["status"])
        return jsonify(ok=True)

    return jsonify(ok=True, ignored=f"unhandled object_kind '{kind}'")


# ============================================================
# Cancel / mark failed
# ============================================================
@app.post("/api/jobs/<job_id>/cancel")
@require_auth
@require_csrf
def cancel_job(job_id):
    """Cancel a pending job. Authorized for the original requester or an
    admin only."""
    if not JOB_ID_RE.match(job_id):
        abort(400)
    payload = request.get_json(silent=True) or {}
    reason = (payload.get("reason") or "")[:512]
    with db() as conn:
        row = conn.execute(
            "SELECT requester_dn, target_host, requester_email, group_id "
            "FROM jobs WHERE id = ? AND status='pending'", (job_id,),
        ).fetchone()
        if not row:
            return jsonify(error="job not in cancellable state"), 409

        is_requester = row["requester_dn"] == g.identity["dn"]
        is_admin = bool(g.user and g.user.get("is_admin"))
        if not (is_requester or is_admin):
            log_event("cancel_job", "deny_not_authorized", job_id=job_id,
                      target=row["target_host"])
            return jsonify(error="only the requester or an admin can cancel this job"), 403

        cur = conn.execute(
            "UPDATE jobs SET status='cancelled', completed_at=?, "
            "completed_by_dn=?, error=? WHERE id=? AND status='pending'",
            (time.time(), g.identity["dn"], reason or None, job_id),
        )
        if cur.rowcount == 0:
            return jsonify(error="job not in cancellable state"), 409
    log_event("cancel_job", "ok", job_id=job_id, reason=reason[:128],
              via=("admin" if is_admin and not is_requester else "requester"))
    fire_webhooks("job.cancelled", {
        "job_id": job_id, "target_host": row["target_host"],
        "requester_email": row["requester_email"],
        "cancelled_by_dn": g.identity["dn"],
        "cancelled_by_cn": _cn_from_dn(g.identity["dn"]),
        "reason": reason or None,
        "group_id": row["group_id"],
    })

    # Best-effort email notification. Never fail the cancel on email errors.
    try:
        group_email_addr = _group_email(row["group_id"])
        ok, nreason = notify.send_cancelled(
            {
                "id": job_id,
                "target_host": row["target_host"],
                "requester_email": row["requester_email"],
            },
            g.identity["dn"], reason,
            group_email=group_email_addr,
        )
        log_event("email_notify", "ok" if ok else "skip",
                  job_id=job_id, event="cancelled",
                  recipient=(row["requester_email"] or group_email_addr or "-"),
                  group_cc=(group_email_addr if (row["requester_email"] and group_email_addr) else "-"),
                  reason=nreason[:96])
    except Exception as e:
        log_event("email_notify", "exception", job_id=job_id,
                  error=str(e)[:128])

    return jsonify(ok=True)

@app.post("/api/jobs/<job_id>/renew")
@require_auth
@require_csrf
def renew_job(job_id):
    """One-click renewal: generate a fresh key+CSR with the same CN, SANs,
    cert types, and key algorithm as the original job. Allowed for the
    requester, members of the job's group, or admins, on issued/expired
    jobs. The new job is linked via renewed_from. External-source jobs
    renew as dashboard-generated (rhel) jobs."""
    if not JOB_ID_RE.match(job_id):
        abort(400)
    _sweep_expired()
    with db() as conn:
        old = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not old:
        abort(404)
    if old["status"] not in ("issued", "expired"):
        return jsonify(error=f"cannot renew a job in status '{old['status']}'"), 409

    me = g.identity["dn"]
    is_admin = bool(g.user and g.user.get("is_admin"))
    in_group = (old["group_id"] in _user_group_ids(me)) if old["group_id"] else False
    if not (is_admin or old["requester_dn"] == me or in_group):
        log_event("renew_job", "deny_not_authorized", job_id=job_id)
        return jsonify(error="only the requester, group members, or an admin can renew"), 403

    requester_email = (g.user or {}).get("email")
    if not requester_email:
        return jsonify(error="No notification email on file. Set your email "
                             "in Settings before creating requests."), 400

    cert_type = old["cert_type"] if "cert_type" in old.keys() and old["cert_type"] else "web"
    cert_type = cert_type.replace("server-client", "client,web")
    key_algo = old["key_algo"] if "key_algo" in old.keys() and old["key_algo"] else "rsa2048"
    if key_algo not in KEY_ALGOS_ALLOWED:
        key_algo = "rsa2048"

    sans = json.loads(old["sans_json"] or "[]")
    target = old["target_host"]
    # Build a single certlist line: CN + SANs that aren't the CN itself
    extra = [s for s in sans if s and s != target]
    line = ",".join([target] + extra) + "\n"

    # Preserve whatever is currently staged in the certlist, run the
    # renewal as its own single-line batch, then restore.
    rc_r, staged, _ = run_helper(["read-certlist-rhel"])
    staged = staged if rc_r == 0 else ""
    rc_w, _, err_w = run_helper(["write-certlist-rhel"], stdin=line)
    if rc_w != 0:
        return jsonify(error=f"could not stage renewal: {err_w[:200]}"), 500

    sid, _ = _get_or_create_session()
    start_time = time.time() - 2
    try:
        rc, out, err = run_helper(["generate-typed", cert_type, key_algo], timeout=600)
    finally:
        run_helper(["write-certlist-rhel"], stdin=staged)

    if rc != 0:
        log_event("renew_job", "error", job_id=job_id, rc=rc)
        return jsonify(error="generation failed", output=(out + err)[:500]), 500

    rc_l, out_l, _ = run_helper(["list-csrs"])
    new_csrs = [r["name"] for r in _parse_helper_listing(out_l)
                if r.get("mtime_epoch", 0) >= start_time] if rc_l == 0 else []
    rc_k, out_k, _ = run_helper(["list-keys"])
    new_keys = [r["name"] for r in _parse_helper_listing(out_k)
                if r.get("mtime_epoch", 0) >= start_time] if rc_k == 0 else []
    if sid and new_keys:
        _add_session_keys(sid, new_keys)

    if not new_csrs:
        return jsonify(error="generation produced no CSR"), 500

    csr_name = new_csrs[0]
    rc_g, csr_pem, _ = run_helper(["get-csr", csr_name])
    if rc_g != 0:
        return jsonify(error="could not read generated CSR"), 500
    cn, new_sans = _parse_csr_subject(csr_pem)
    local_key = csr_name[:-4] + ".key"
    has_key = local_key in new_keys

    new_id = uuid.uuid4().hex
    with db() as conn:
        conn.execute("""
            INSERT INTO jobs (id, created_at, requester_dn, requester_serial,
                              requester_ip, requester_email, target_host, sans_json,
                              csr_pem, status, has_local_key, local_key_name, source,
                              group_id, cert_type, key_algo, renewed_from)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, 'rhel', ?, ?, ?, ?)
        """, (
            new_id, time.time(), me, g.identity.get("serial", "-"),
            request.remote_addr, requester_email,
            cn or target, json.dumps(new_sans), csr_pem,
            1 if has_key else 0, local_key if has_key else None,
            old["group_id"], cert_type, key_algo, job_id,
        ))
    run_helper(["delete-csr", csr_name])

    log_event("renew_job", "ok", job_id=job_id, new_job_id=new_id,
              target=target, cert_type=cert_type, key_algo=key_algo)
    fire_webhooks("job.created", {
        "job_id": new_id, "target_host": cn or target, "source": "rhel",
        "requester_dn": me, "requester_email": requester_email,
        "group_id": old["group_id"], "cert_type": cert_type,
        "renewed_from": job_id, "has_local_key": bool(has_key),
    })
    _open_signing_issue(new_id)
    try:
        recipients = _signer_recipients()
        if recipients:
            notify.send_csrs_created([cn or target], cert_type,
                                     _cn_from_dn(me), requester_email, recipients)
    except Exception:
        pass
    return jsonify(ok=True, new_job_id=new_id)


@app.get("/api/jobs/export.csv")
@require_auth
def export_jobs_csv():
    """CSV export of jobs, honoring the same filters as the list view."""
    _sweep_expired()
    a = request.args
    where, params = [], []
    if status := a.get("status"):
        if status in ("pending", "issued", "failed", "cancelled", "expired"):
            where.append("status = ?"); params.append(status)
    if source := a.get("source"):
        if source in ("rhel", "external"):
            where.append("source = ?"); params.append(source)
    if ew := a.get("expiring_within"):
        try:
            where.append("status='issued' AND expires_at IS NOT NULL AND expires_at <= ?")
            params.append(time.time() + max(1, min(int(ew), 365)) * 86400)
        except (TypeError, ValueError):
            pass
    sql = "SELECT * FROM jobs"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT 10000"
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
        gnames = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM groups")}

    def iso(t):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t)) if t else ""

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "created_utc", "target_host", "sans", "cert_type",
                "key_algo", "status", "source", "requester_dn",
                "requester_email", "group", "expires_utc", "completed_utc",
                "renewed_from"])
    for r in rows:
        k = r.keys()
        w.writerow([
            r["id"], iso(r["created_at"]), r["target_host"],
            " ".join(json.loads(r["sans_json"] or "[]")),
            r["cert_type"] if "cert_type" in k else "",
            r["key_algo"] if "key_algo" in k else "",
            r["status"], r["source"], r["requester_dn"],
            r["requester_email"] or "",
            gnames.get(r["group_id"], "") if r["group_id"] else "",
            iso(r["expires_at"] if "expires_at" in k else None),
            iso(r["completed_at"]),
            r["renewed_from"] if "renewed_from" in k else "",
        ])
    log_event("export_csv", "ok", rows=len(rows))
    return app.response_class(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename=csr-jobs-{time.strftime('%Y%m%d-%H%M%S')}.csv"})


@app.get("/api/signing-queue/csrs.zip")
@require_auth
def signing_queue_zip():
    """All pending CSRs as one zip, for the signer to carry to the CA."""
    ids_param = (request.args.get("ids") or "").strip()
    with db() as conn:
        if ids_param:
            ids = [i for i in ids_param.split(",") if JOB_ID_RE.match(i)][:200]
            if not ids:
                return jsonify(error="no valid ids"), 400
            ph = ",".join("?" * len(ids))
            rows = conn.execute(
                f"SELECT id, target_host, csr_pem FROM jobs "
                f"WHERE status='pending' AND id IN ({ph})", ids).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, target_host, csr_pem FROM jobs "
                "WHERE status='pending' ORDER BY created_at").fetchall()
    if not rows:
        return jsonify(error="no pending CSRs"), 404
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        seen = {}
        for r in rows:
            base = re.sub(r"[^A-Za-z0-9._-]", "_", r["target_host"]) or r["id"][:8]
            n = seen.get(base, 0); seen[base] = n + 1
            name = f"{base}.csr" if n == 0 else f"{base}-{n}.csr"
            z.writestr(name, r["csr_pem"])
    buf.seek(0)
    log_event("signing_queue_zip", "ok", count=len(rows))
    return app.response_class(
        buf.getvalue(), mimetype="application/zip",
        headers={"Content-Disposition":
                 f"attachment; filename=pending-csrs-{time.strftime('%Y%m%d-%H%M%S')}.zip"})


@app.put("/api/admin/groups/<int:group_id>/members/role")
@require_admin
@require_csrf
def admin_set_member_role(group_id):
    """Promote/demote a member to/from group owner. Admin only."""
    payload = request.get_json(silent=True) or {}
    dn = (payload.get("dn") or "").strip()
    role = (payload.get("role") or "").strip()
    if role not in ("member", "owner"):
        return jsonify(error="role must be 'member' or 'owner'"), 400
    with db() as conn:
        cur = conn.execute(
            "UPDATE user_groups SET role = ? WHERE group_id = ? AND user_dn = ?",
            (role, group_id, dn))
        if cur.rowcount == 0:
            return jsonify(error="not a member of that group"), 404
    log_event("group_member_role", "ok", group_id=group_id,
              member=_cn_from_dn(dn) or dn, role=role)
    return jsonify(ok=True)


@app.get("/api/my-groups")
@require_auth
def my_groups():
    """Groups the current user belongs to, with role; owners also get the
    member list so they can manage it."""
    me = g.identity["dn"]
    with db() as conn:
        rows = conn.execute("""
            SELECT grp.id, grp.name, grp.description, grp.email,
                   grp.notify_on_new, ug.role,
                   (SELECT COUNT(*) FROM user_groups x
                     WHERE x.group_id = grp.id) AS member_count
              FROM user_groups ug
              JOIN groups grp ON grp.id = ug.group_id
             WHERE ug.user_dn = ?
             ORDER BY grp.name COLLATE NOCASE
        """, (me,)).fetchall()
        out = []
        for r in rows:
            entry = {
                "id": r["id"], "name": r["name"], "description": r["description"],
                "email": r["email"], "notify_on_new": bool(r["notify_on_new"]),
                "role": r["role"] or "member", "member_count": r["member_count"],
            }
            if entry["role"] == "owner":
                mems = conn.execute("""
                    SELECT u.dn, u.cn, u.email, ug2.role, ug2.added_at
                      FROM user_groups ug2 JOIN users u ON u.dn = ug2.user_dn
                     WHERE ug2.group_id = ?
                     ORDER BY ug2.role DESC, u.cn COLLATE NOCASE
                """, (r["id"],)).fetchall()
                entry["members"] = [{
                    "dn": m["dn"], "cn": m["cn"], "email": m["email"],
                    "role": m["role"] or "member", "added_at": m["added_at"],
                } for m in mems]
            out.append(entry)
    return jsonify(groups=out)


@app.post("/api/groups/<int:group_id>/members")
@require_auth
@require_csrf
def group_owner_add_member(group_id):
    """Group owners (or admins) add a member to the group by email. The
    person must have logged into the dashboard at least once and have an
    email set."""
    me = g.identity["dn"]
    if not _group_by_id(group_id):
        return jsonify(error="group not found"), 404
    if not _is_group_owner_or_admin(me, group_id):
        log_event("group_add_member", "deny_not_owner", group_id=group_id)
        return jsonify(error="only the group owner or an admin can add members"), 403
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    if not email or not EMAIL_RE.match(email):
        return jsonify(error="a valid member email is required"), 400
    with db() as conn:
        user = conn.execute(
            "SELECT dn, cn FROM users WHERE LOWER(email) = ? AND is_active = 1",
            (email,)).fetchone()
        if not user:
            return jsonify(error="no active user with that email - they must "
                                 "log into the dashboard and set their email "
                                 "in Settings first"), 404
        existing = conn.execute(
            "SELECT 1 FROM user_groups WHERE user_dn = ? AND group_id = ?",
            (user["dn"], group_id)).fetchone()
        if existing:
            return jsonify(error="already a member"), 409
        conn.execute(
            "INSERT INTO user_groups (user_dn, group_id, added_at, role) "
            "VALUES (?, ?, ?, 'member')",
            (user["dn"], group_id, time.time()))
    log_event("group_add_member", "ok", group_id=group_id,
              member=user["cn"] or email, by="owner")
    return jsonify(ok=True, cn=user["cn"])


@app.delete("/api/groups/<int:group_id>/members")
@require_auth
@require_csrf
def group_owner_remove_member(group_id):
    """Group owners (or admins) remove a member. Owners cannot remove other
    owners (admin only), and cannot remove themselves (ask an admin, so a
    group is never accidentally left ownerless)."""
    me = g.identity["dn"]
    if not _is_group_owner_or_admin(me, group_id):
        return jsonify(error="only the group owner or an admin can remove members"), 403
    payload = request.get_json(silent=True) or {}
    dn = (payload.get("dn") or "").strip()
    if not dn:
        return jsonify(error="dn required"), 400
    is_admin = bool(g.user and g.user.get("is_admin"))
    target_role = _group_role(dn, group_id)
    if target_role is None:
        return jsonify(error="not a member"), 404
    if not is_admin:
        if dn == me:
            return jsonify(error="owners cannot remove themselves - ask an admin"), 403
        if target_role == "owner":
            return jsonify(error="only an admin can remove a group owner"), 403
    with db() as conn:
        conn.execute("DELETE FROM user_groups WHERE user_dn = ? AND group_id = ?",
                     (dn, group_id))
    log_event("group_remove_member", "ok", group_id=group_id,
              member=_cn_from_dn(dn) or dn)
    return jsonify(ok=True)


@app.post("/api/jobs/bulk-cancel")
@require_auth
@require_csrf
def bulk_cancel_jobs():
    """Cancel multiple pending jobs in one call. Same authorization model as
    single cancel (any authenticated active user). Per-job notifications and
    webhooks fire as they would for individual cancels."""
    payload = request.get_json(silent=True) or {}
    job_ids = payload.get("job_ids")
    reason = (payload.get("reason") or "")[:512]

    if not isinstance(job_ids, list) or not job_ids:
        return jsonify(error="job_ids must be a non-empty array"), 400
    if len(job_ids) > 200:
        return jsonify(error="too many jobs in one call (max 200)"), 400
    for jid in job_ids:
        if not isinstance(jid, str) or not JOB_ID_RE.match(jid):
            return jsonify(error="invalid job id in list"), 400

    cancelled, skipped, denied = [], [], []
    is_admin = bool(g.user and g.user.get("is_admin"))
    for jid in job_ids:
        with db() as conn:
            row = conn.execute(
                "SELECT requester_dn, target_host, requester_email, group_id "
                "FROM jobs WHERE id = ? AND status='pending'", (jid,),
            ).fetchone()
            if not row:
                skipped.append(jid)
                continue
            if not (is_admin or row["requester_dn"] == g.identity["dn"]):
                denied.append(jid)
                log_event("cancel_job", "deny_not_authorized", job_id=jid,
                          target=row["target_host"], via="bulk")
                continue
            cur = conn.execute(
                "UPDATE jobs SET status='cancelled', completed_at=?, "
                "completed_by_dn=?, error=? WHERE id=? AND status='pending'",
                (time.time(), g.identity["dn"], reason or None, jid),
            )
            if cur.rowcount == 0:
                skipped.append(jid)
                continue
        cancelled.append(jid)
        log_event("cancel_job", "ok", job_id=jid, reason=reason[:128],
                  via="bulk")
        fire_webhooks("job.cancelled", {
            "job_id": jid, "target_host": row["target_host"],
            "requester_email": row["requester_email"],
            "cancelled_by_dn": g.identity["dn"],
            "cancelled_by_cn": _cn_from_dn(g.identity["dn"]),
            "reason": reason or None,
            "group_id": row["group_id"],
        })
        # Best-effort per-job email (requesters differ per job)
        try:
            group_email_addr = _group_email(row["group_id"])
            ok_n, nreason = notify.send_cancelled(
                {"id": jid, "target_host": row["target_host"],
                 "requester_email": row["requester_email"]},
                g.identity["dn"], reason,
                group_email=group_email_addr,
            )
            log_event("email_notify", "ok" if ok_n else "skip",
                      job_id=jid, event="cancelled",
                      recipient=(row["requester_email"] or group_email_addr or "-"),
                      reason=nreason[:96])
        except Exception as e:
            log_event("email_notify", "exception", job_id=jid,
                      error=str(e)[:128])

    log_event("bulk_cancel", "ok", requested=len(job_ids),
              cancelled=len(cancelled), skipped=len(skipped),
              denied=len(denied))
    return jsonify(ok=True, cancelled=cancelled, skipped=skipped, denied=denied)


@app.post("/api/jobs/<job_id>/mark-failed")
@require_auth
@require_csrf
def mark_failed(job_id):
    """Mark a pending job failed. Authorized only for members of a signer
    group (a group with notify_on_new=1). Admin role alone does not grant
    this; admins must join a signer group like anyone else."""
    if not JOB_ID_RE.match(job_id):
        abort(400)
    if not _is_signer(g.identity["dn"]):
        log_event("mark_failed", "deny_not_signer", job_id=job_id)
        return jsonify(error="only signer-group members can mark jobs failed"), 403
    payload = request.get_json(silent=True) or {}
    error = (payload.get("error") or "manual mark failed")[:2048]
    with db() as conn:
        row = conn.execute(
            "SELECT target_host, requester_email, group_id "
            "FROM jobs WHERE id = ? AND status='pending'", (job_id,),
        ).fetchone()
        if not row:
            return jsonify(error="job not in markable state"), 409
        cur = conn.execute(
            "UPDATE jobs SET status='failed', error=?, completed_at=?, "
            "completed_by_dn=? WHERE id=? AND status='pending'",
            (error, time.time(), g.identity["dn"], job_id),
        )
        if cur.rowcount == 0:
            return jsonify(error="job not in markable state"), 409
    log_event("mark_failed", "ok", job_id=job_id, error=error[:128])
    fire_webhooks("job.failed", {
        "job_id": job_id, "target_host": row["target_host"],
        "requester_email": row["requester_email"],
        "marked_by_dn": g.identity["dn"],
        "marked_by_cn": _cn_from_dn(g.identity["dn"]),
        "error": error,
        "group_id": row["group_id"],
    })

    # Best-effort email notification. Never fail the mark on email errors.
    try:
        group_email_addr = _group_email(row["group_id"])
        ok, nreason = notify.send_failed(
            {
                "id": job_id,
                "target_host": row["target_host"],
                "requester_email": row["requester_email"],
            },
            g.identity["dn"], error,
            group_email=group_email_addr,
        )
        log_event("email_notify", "ok" if ok else "skip",
                  job_id=job_id, event="failed",
                  recipient=(row["requester_email"] or group_email_addr or "-"),
                  group_cc=(group_email_addr if (row["requester_email"] and group_email_addr) else "-"),
                  reason=nreason[:96])
    except Exception as e:
        log_event("email_notify", "exception", job_id=job_id,
                  error=str(e)[:128])

    return jsonify(ok=True)

# ============================================================
# openssl-text views (CSR + cert)
# ============================================================
@app.get("/api/jobs/<job_id>/csr-info")
@require_auth
def get_job_csr_info(job_id):
    if not JOB_ID_RE.match(job_id):
        abort(400)
    with db() as conn:
        row = conn.execute("SELECT csr_pem FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        abort(404)
    try:
        proc = subprocess.run(
            ["openssl", "req", "-noout", "-text"],
            input=row["csr_pem"], capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            log_event("get_job_csr_info", "error", job_id=job_id)
            return jsonify(error="failed to parse CSR", stderr=proc.stderr[:512]), 500
    except Exception as e:
        log_event("get_job_csr_info", "exception", job_id=job_id, error=str(e)[:128])
        return jsonify(error="parse error"), 500
    log_event("get_job_csr_info", "ok", job_id=job_id)
    return jsonify(text=proc.stdout)


@app.get("/api/jobs/<job_id>/cert-info")
@require_auth
def get_job_cert_info(job_id):
    if not JOB_ID_RE.match(job_id):
        abort(400)
    with db() as conn:
        row = conn.execute(
            "SELECT cert_pem, status FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
    if not row:
        abort(404)
    if row["status"] != "issued" or not row["cert_pem"]:
        return jsonify(error="cert not yet available"), 404
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-text"],
            input=row["cert_pem"], capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            log_event("get_job_cert_info", "error", job_id=job_id)
            return jsonify(error="failed to parse cert", stderr=proc.stderr[:512]), 500
    except Exception as e:
        log_event("get_job_cert_info", "exception", job_id=job_id, error=str(e)[:128])
        return jsonify(error="parse error"), 500
    log_event("get_job_cert_info", "ok", job_id=job_id)
    return jsonify(text=proc.stdout)

# ============================================================
# Linux key downloads (kept; session-scoped)
# ============================================================
@app.get("/api/rhel/keys")
@require_auth
def list_session_keys():
    claimed = _get_session_keys()
    if not claimed:
        return jsonify(keys=[])
    rc, out, err = run_helper(["list-keys"])
    if rc != 0:
        log_event("list_keys", "error", rc=rc)
        return jsonify(keys=[])
    rows = [{"name": r["name"], "size": r["size"], "mtime": r["mtime"]}
            for r in _parse_helper_listing(out) if r["name"] in claimed]
    log_event("list_keys", "ok", count=len(rows))
    return jsonify(keys=rows)

@app.get("/api/rhel/keys/<name>")
@require_auth
def fetch_key(name):
    if not KEY_NAME_RE.match(name):
        log_event("fetch_key", "deny_invalid", name=name[:64])
        abort(400)
    if name not in _get_session_keys():
        log_event("fetch_key", "deny_not_in_session", name=name)
        abort(403)
    rc, out, err = run_helper(["get-key", name])
    if rc != 0:
        log_event("fetch_key", "not_found", name=name)
        return jsonify(error="not found"), 404
    log_event("fetch_key", "ok", name=name, bytes=len(out))
    return Response(out, mimetype="application/x-pem-file",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})

# ============================================================
# Current-user profile (any authenticated user)
# ============================================================
@app.get("/api/me")
@require_auth
def get_me():
    return jsonify({
        "dn":           g.user["dn"],
        "cn":           g.user["cn"],
        "email":        g.user["email"],
        "is_admin":     bool(g.user["is_admin"]),
        "is_active":    bool(g.user["is_active"]),
        "is_signer":    _is_signer(g.user["dn"]),
        "tutorial_dismissed": bool(g.user["tutorial_dismissed"]),
        "created_at":   g.user["created_at"],
        "last_seen_at": g.user["last_seen_at"],
        "version": APP_VERSION,
    })

@app.put("/api/me/prefs")
@require_auth
@require_csrf
def put_me_prefs():
    payload = request.get_json(silent=True) or {}
    fields, params = [], []
    log_extra = {}

    if "email" in payload:
        ok, email, err = _validate_email(payload["email"])
        if not ok:
            return jsonify(error=err), 400
        if not email:
            # Email is mandatory: it drives notifications and how the
            # requester is displayed. It can be changed but never cleared.
            return jsonify(error="email is required and cannot be cleared"), 400
        fields.append("email = ?"); params.append(email)
        log_extra["email"] = "set"

    if "tutorial_dismissed" in payload:
        td = bool(payload["tutorial_dismissed"])
        fields.append("tutorial_dismissed = ?"); params.append(1 if td else 0)
        log_extra["tutorial_dismissed"] = td

    if not fields:
        return jsonify(error="no fields to update"), 400

    params.append(g.user["dn"])
    with db() as conn:
        conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE dn = ?", params)

    log_event("me_prefs_update", "ok", **log_extra)
    resp = {"ok": True}
    if "email" in payload:
        resp["email"] = email
    return jsonify(**resp)

# ============================================================
# Admin: users
# ============================================================
@app.get("/api/admin/users")
@require_admin
def admin_list_users():
    with db() as conn:
        rows = conn.execute("""
            SELECT dn, cn, email, is_admin, is_active,
                   created_at, last_seen_at, notes
              FROM users
             ORDER BY last_seen_at DESC
        """).fetchall()
    log_event("admin_list_users", "ok", count=len(rows))
    return jsonify(users=[{
        "dn": r["dn"], "cn": r["cn"], "email": r["email"],
        "is_admin": bool(r["is_admin"]), "is_active": bool(r["is_active"]),
        "created_at": r["created_at"], "last_seen_at": r["last_seen_at"],
        "notes": r["notes"],
    } for r in rows])

@app.put("/api/admin/users")
@require_admin
@require_csrf
def admin_update_user():
    """Update a user. DN is in the request body since it contains characters
    that are awkward in a URL path."""
    payload = request.get_json(silent=True) or {}
    target_dn = (payload.get("dn") or "").strip()
    if not target_dn or len(target_dn) > 512:
        return jsonify(error="invalid dn"), 400

    # Self-demotion footgun protection
    if target_dn == g.user["dn"] and "is_admin" in payload and not payload["is_admin"]:
        return jsonify(error="cannot remove your own admin status"), 400
    if target_dn == g.user["dn"] and "is_active" in payload and not payload["is_active"]:
        return jsonify(error="cannot deactivate yourself"), 400

    fields = {}
    if "is_admin" in payload:
        fields["is_admin"] = 1 if payload["is_admin"] else 0
    if "is_active" in payload:
        fields["is_active"] = 1 if payload["is_active"] else 0
    if "email" in payload:
        ok, email, err = _validate_email(payload["email"])
        if not ok:
            return jsonify(error=f"email: {err}"), 400
        fields["email"] = email
    if "notes" in payload:
        notes = payload["notes"]
        if notes is not None and not isinstance(notes, str):
            return jsonify(error="notes must be string"), 400
        if isinstance(notes, str) and len(notes) > 4096:
            return jsonify(error="notes too long (max 4KB)"), 400
        fields["notes"] = notes

    if not fields:
        return jsonify(error="no fields to update"), 400

    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [target_dn]

    with db() as conn:
        cur = conn.execute(
            f"UPDATE users SET {set_clause} WHERE dn = ?", values
        )
        if cur.rowcount == 0:
            return jsonify(error="user not found"), 404

    log_event("admin_user_update", "ok",
              target_dn=target_dn[:128],
              fields=",".join(fields.keys()))
    return jsonify(ok=True)

@app.post("/api/admin/users")
@require_admin
@require_csrf
def admin_create_user():
    """Manually pre-create a user before they first log in (rare)."""
    payload = request.get_json(silent=True) or {}
    target_dn = (payload.get("dn") or "").strip()
    if not target_dn or len(target_dn) > 512:
        return jsonify(error="invalid dn"), 400

    ok, email, err = _validate_email(payload.get("email"))
    if not ok:
        return jsonify(error=f"email: {err}"), 400

    is_admin = 1 if payload.get("is_admin") else 0
    cn = _cn_from_dn(target_dn)
    now = time.time()

    with db() as conn:
        existing = conn.execute(
            "SELECT dn FROM users WHERE dn = ?", (target_dn,)
        ).fetchone()
        if existing:
            return jsonify(error="user already exists"), 409
        conn.execute("""
            INSERT INTO users (dn, cn, email, is_admin, is_active,
                               created_at, last_seen_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
        """, (target_dn, cn, email, is_admin, now, now))

    log_event("admin_user_create", "ok",
              target_dn=target_dn[:128], is_admin=is_admin)
    return jsonify(ok=True)

# ============================================================
# Admin: job cleanup
# ============================================================
def _delete_job_files(rows):
    """Delete key + issued cert files for the given job rows.
    Returns count of files actually removed."""
    removed = 0
    for r in rows:
        if r["has_local_key"] and r["local_key_name"]:
            rc, _, _ = run_helper(["delete-key", r["local_key_name"]])
            if rc == 0:
                removed += 1
        if r["status"] == "issued":
            cert_name = f"{r['target_host']}.cer"
            rc, _, _ = run_helper(["delete-issued", cert_name])
            if rc == 0:
                removed += 1
    return removed

@app.delete("/api/admin/jobs/<job_id>")
@require_admin
@require_csrf
def admin_delete_job(job_id):
    if not JOB_ID_RE.match(job_id):
        abort(400)
    delete_files = request.args.get("delete_files", "false").lower() == "true"

    with db() as conn:
        row = conn.execute(
            "SELECT id, target_host, local_key_name, has_local_key, status "
            "FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
    if not row:
        return jsonify(error="not found"), 404

    files_removed = _delete_job_files([row]) if delete_files else 0

    with db() as conn:
        conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))

    log_event("admin_delete_job", "ok", job_id=job_id,
              target=row["target_host"], files_removed=files_removed)
    return jsonify(ok=True, files_removed=files_removed)

@app.post("/api/admin/jobs/bulk-delete")
@require_admin
@require_csrf
def admin_bulk_delete_jobs():
    payload = request.get_json(silent=True) or {}
    delete_files = bool(payload.get("delete_files", False))

    where, params = [], []
    if ids := payload.get("ids"):
        if not isinstance(ids, list) or not all(isinstance(i, str) and JOB_ID_RE.match(i) for i in ids):
            return jsonify(error="invalid ids"), 400
        placeholders = ",".join("?" * len(ids))
        where.append(f"id IN ({placeholders})")
        params.extend(ids)
    status = payload.get("status")
    if ids:
        # Explicit id list may carry its own status filter, optional
        if status and status not in ("pending", "issued", "failed", "cancelled", "expired"):
            return jsonify(error="invalid status"), 400
        if status:
            where.append("status = ?"); params.append(status)
    else:
        # Criteria-based cleanup MUST name a status. "Any" is no longer
        # accepted -- too easy to wipe valid jobs by accident.
        if not status:
            return jsonify(error="status filter is required for bulk cleanup"), 400
        if status not in ("pending", "issued", "failed", "cancelled", "expired"):
            return jsonify(error="invalid status"), 400
        where.append("status = ?"); params.append(status)
    if source := payload.get("source"):
        if source not in ("rhel", "external"):
            return jsonify(error="invalid source"), 400
        where.append("source = ?"); params.append(source)
    if older_than_days := payload.get("older_than_days"):
        try:
            cutoff = time.time() - int(older_than_days) * 86400
            where.append("created_at < ?"); params.append(cutoff)
        except (TypeError, ValueError):
            return jsonify(error="invalid older_than_days"), 400

    if not where:
        return jsonify(error="at least one filter required"), 400

    with db() as conn:
        rows = conn.execute(
            f"SELECT id, target_host, local_key_name, has_local_key, status, "
            f"source, created_at, requester_email, requester_dn "
            f"FROM jobs WHERE {' AND '.join(where)} ORDER BY created_at DESC",
            params,
        ).fetchall()

    # Preview mode: return the matching records without deleting anything,
    # so the admin can review and deselect before committing.
    if payload.get("preview"):
        capped = rows[:500]
        log_event("admin_bulk_delete", "preview", matched=len(rows))
        return jsonify(
            preview=True, total=len(rows), truncated=(len(rows) > 500),
            jobs=[{
                "id": r["id"], "target_host": r["target_host"],
                "status": r["status"], "source": r["source"],
                "created_at": r["created_at"],
                "requester_display": r["requester_email"]
                    or _cn_from_dn(r["requester_dn"]) or r["requester_dn"],
            } for r in capped],
        )

    if not rows:
        return jsonify(ok=True, deleted=0, files_removed=0)

    files_removed = _delete_job_files(rows) if delete_files else 0

    with db() as conn:
        cur = conn.execute(
            f"DELETE FROM jobs WHERE {' AND '.join(where)}", params
        )
        deleted = cur.rowcount

    log_event("admin_bulk_delete", "ok", deleted=deleted,
              files_removed=files_removed,
              filters=",".join(payload.keys())[:128])
    return jsonify(ok=True, deleted=deleted, files_removed=files_removed)

# ============================================================
# Admin: orphan keys + certs
# ============================================================
@app.get("/api/admin/orphans/keys")
@require_admin
def admin_list_orphan_keys():
    rc, out, _ = run_helper(["list-keys"])
    all_keys = _parse_helper_listing(out) if rc == 0 else []

    with db() as conn:
        rows = conn.execute(
            "SELECT local_key_name FROM jobs "
            "WHERE has_local_key=1 AND local_key_name IS NOT NULL"
        ).fetchall()
    referenced = {r["local_key_name"] for r in rows}

    orphans = [k for k in all_keys if k["name"] not in referenced]
    log_event("admin_list_orphan_keys", "ok",
              total=len(all_keys), orphans=len(orphans))
    return jsonify(keys=orphans,
                   total=len(all_keys), orphan_count=len(orphans))

@app.delete("/api/admin/orphans/keys/<name>")
@require_admin
@require_csrf
def admin_delete_orphan_key(name):
    if not KEY_NAME_RE.match(name):
        abort(400)
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM jobs WHERE local_key_name = ?", (name,)
        ).fetchone()
    if row:
        return jsonify(error="key is still referenced by a job"), 409

    rc, _, _ = run_helper(["delete-key", name])
    if rc != 0:
        log_event("admin_delete_orphan_key", "error", name=name, rc=rc)
        return jsonify(error="delete failed"), 500
    log_event("admin_delete_orphan_key", "ok", name=name)
    return jsonify(ok=True)

@app.get("/api/admin/orphans/certs")
@require_admin
def admin_list_orphan_certs():
    issued_dir = Path(ISSUED_DIR)
    all_certs = []
    if issued_dir.exists():
        for f in issued_dir.iterdir():
            if not (f.is_file() and f.name.endswith(".cer")):
                continue
            st = f.stat()
            all_certs.append({
                "name": f.name,
                "size": st.st_size,
                "mtime": time.strftime("%Y-%m-%d %H:%M",
                                       time.localtime(st.st_mtime)),
                "mtime_epoch": st.st_mtime,
            })

    with db() as conn:
        rows = conn.execute(
            "SELECT target_host FROM jobs WHERE status='issued'"
        ).fetchall()
    referenced = {f"{r['target_host']}.cer" for r in rows}

    orphans = [c for c in all_certs if c["name"] not in referenced]
    log_event("admin_list_orphan_certs", "ok",
              total=len(all_certs), orphans=len(orphans))
    return jsonify(certs=orphans,
                   total=len(all_certs), orphan_count=len(orphans))

@app.delete("/api/admin/orphans/certs/<name>")
@require_admin
@require_csrf
def admin_delete_orphan_cert(name):
    if not re.match(r"^[A-Za-z0-9._-]+\.cer$", name):
        abort(400)
    rc, _, _ = run_helper(["delete-issued", name])
    if rc != 0:
        log_event("admin_delete_orphan_cert", "error", name=name, rc=rc)
        return jsonify(error="delete failed"), 500
    log_event("admin_delete_orphan_cert", "ok", name=name)
    return jsonify(ok=True)

# ============================================================
# Admin: service stats
# ============================================================
@app.get("/api/admin/stats")
@require_admin
def admin_stats():
    with db() as conn:
        status_rows = conn.execute(
            "SELECT status, COUNT(*) FROM jobs GROUP BY status"
        ).fetchall()
        source_rows = conn.execute(
            "SELECT source, COUNT(*) FROM jobs GROUP BY source"
        ).fetchall()
        user_total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        admin_total = conn.execute(
            "SELECT COUNT(*) FROM users WHERE is_admin=1"
        ).fetchone()[0]
        active_total = conn.execute(
            "SELECT COUNT(*) FROM users WHERE is_active=1"
        ).fetchone()[0]
        fb_rows = conn.execute(
            "SELECT status, COUNT(*) FROM feedback GROUP BY status"
        ).fetchall()
        expiring_60 = conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE status='issued' "
            "AND expires_at IS NOT NULL AND expires_at <= ?",
            (time.time() + 60 * 86400,),
        ).fetchone()[0]
        fleet_total = conn.execute("SELECT COUNT(*) FROM fleet_certs").fetchone()[0]
        fleet_expiring = conn.execute(
            "SELECT COUNT(*) FROM fleet_certs WHERE expires_at IS NOT NULL "
            "AND expires_at <= ?", (time.time() + 60 * 86400,),
        ).fetchone()[0]

    by_status = {r[0]: r[1] for r in status_rows}
    by_source = {r[0]: r[1] for r in source_rows}
    fb_by_status = {r[0]: r[1] for r in fb_rows}

    try:
        db_size = Path(DB_PATH).stat().st_size
    except Exception:
        db_size = 0

    email_status = {"enabled": False, "reason": "module not loaded"}
    try:
        import notify
        email_status = {
            "enabled": notify.is_enabled(),
            "reason": notify.disabled_reason() or "ok",
        }
    except Exception as e:
        email_status = {"enabled": False, "reason": str(e)[:128]}

    return jsonify({
        "jobs": {
            "by_status": by_status,
            "by_source": by_source,
            "total": sum(by_status.values()),
            "expiring_60d": expiring_60,
        },
        "fleet": {
            "total": fleet_total,
            "expiring_60d": fleet_expiring,
        },
        "users": {
            "total": user_total,
            "admin": admin_total,
            "active": active_total,
        },
        "db": {
            "path": DB_PATH,
            "size_bytes": db_size,
        },
        "feedback": {
            "by_status": fb_by_status,
            "total": sum(fb_by_status.values()),
            "new": fb_by_status.get("new", 0),
        },
        "email": email_status,
    })

# ============================================================
# Groups: read-mine (any auth user)
# ============================================================
@app.get("/api/me/groups")
@require_auth
def get_my_groups():
    groups = _user_groups(g.identity["dn"])
    return jsonify(groups=groups)

# ============================================================
# Cert-type templates (personal + group scoped)
# ============================================================
@app.get("/api/templates")
@require_auth
def list_templates():
    """Templates visible to the caller: their personal ones, plus group
    templates for groups they belong to. Admins additionally see every
    group template (so they can manage shared ones), but never other
    users' personal templates."""
    me = g.identity["dn"]
    is_admin = bool(g.user and g.user.get("is_admin"))
    my_groups = _user_group_ids(me)

    with db() as conn:
        rows = conn.execute("""
            SELECT t.*, gr.name AS group_name
              FROM cert_templates t
              LEFT JOIN groups gr ON gr.id = t.group_id
             ORDER BY t.name COLLATE NOCASE
        """).fetchall()

    out = []
    for r in rows:
        d = dict(r)
        is_global = d["group_id"] is None and d["owner_dn"] is None
        personal = d["group_id"] is None and d["owner_dn"] is not None
        if is_global:
            pass  # visible to everyone
        elif personal:
            if d["owner_dn"] != me:
                continue
        else:
            if not is_admin and d["group_id"] not in my_groups:
                continue
        d["scope"] = "builtin" if is_global else ("personal" if personal else "group")
        # Deletable from the user-facing Templates tab only by the person
        # who created it. Instance-wide templates are admin-UI-managed.
        d["can_edit"] = (
            (personal and d["owner_dn"] == me)
            or (not is_global and not personal and d["created_by_dn"] == me)
        )
        d["can_use"] = is_global or personal or (d["group_id"] in my_groups) or is_admin
        d.pop("owner_dn", None)
        out.append(d)

    return jsonify(templates=out)


@app.post("/api/templates")
@require_auth
@require_csrf
def create_template():
    """Create a template. group_id absent/null -> personal. Group templates
    require membership in that group (admins exempt)."""
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    description = (payload.get("description") or "").strip() or None

    if not name or len(name) > 64:
        return jsonify(error="name is required (max 64 chars)"), 400
    if description and len(description) > 256:
        return jsonify(error="description too long (max 256 chars)"), 400

    ok_ct, cert_types, err_ct = _normalize_cert_types(payload.get("cert_types"))
    if not ok_ct:
        return jsonify(error=err_ct), 400
    if not cert_types:
        return jsonify(error="cert_types is required"), 400

    group_id = payload.get("group_id")
    scope = (payload.get("scope") or "").strip().lower()
    is_admin = bool(g.user and g.user.get("is_admin"))

    if scope == "global":
        # Instance-wide template, visible to every user. Admin only.
        if not is_admin:
            return jsonify(error="only admins can create instance-wide templates"), 403
        if group_id is not None:
            return jsonify(error="global scope and group_id are mutually exclusive"), 400
        owner_dn = None
    elif group_id is not None:
        try:
            group_id = int(group_id)
        except (TypeError, ValueError):
            return jsonify(error="invalid group_id"), 400
        if not _group_by_id(group_id):
            return jsonify(error="group does not exist"), 400
        if not is_admin and _group_role(g.identity["dn"], group_id) != "owner":
            return jsonify(error="only the group owner or an admin can create "
                                 "group templates"), 403
        owner_dn = None
    else:
        owner_dn = g.identity["dn"]

    # Duplicate-name check within the same scope
    with db() as conn:
        if scope == "global":
            dup = conn.execute(
                "SELECT 1 FROM cert_templates WHERE group_id IS NULL "
                "AND owner_dn IS NULL AND name = ? COLLATE NOCASE",
                (name,),
            ).fetchone()
        elif group_id is not None:
            dup = conn.execute(
                "SELECT 1 FROM cert_templates WHERE group_id = ? AND name = ? COLLATE NOCASE",
                (group_id, name),
            ).fetchone()
        else:
            dup = conn.execute(
                "SELECT 1 FROM cert_templates WHERE owner_dn = ? AND name = ? COLLATE NOCASE",
                (owner_dn, name),
            ).fetchone()
        if dup:
            return jsonify(error="a template with that name already exists in this scope"), 409

        cur = conn.execute("""
            INSERT INTO cert_templates (name, description, cert_types,
                                        owner_dn, group_id, created_at, created_by_dn)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, description, cert_types, owner_dn, group_id,
              time.time(), g.identity["dn"]))
        tid = cur.lastrowid

    log_event("template_create", "ok", template_id=tid, name=name,
              scope=("global" if scope == "global"
                     else "group:%s" % group_id if group_id else "personal"),
              cert_types=cert_types)
    return jsonify(ok=True, id=tid, cert_types=cert_types)


@app.delete("/api/templates/<int:template_id>")
@require_auth
@require_csrf
def delete_template(template_id):
    me = g.identity["dn"]
    is_admin = bool(g.user and g.user.get("is_admin"))
    with db() as conn:
        row = conn.execute(
            "SELECT name, owner_dn, group_id, created_by_dn "
            "FROM cert_templates WHERE id = ?", (template_id,)
        ).fetchone()
        if not row:
            return jsonify(error="template not found"), 404

        is_global = row["group_id"] is None and row["owner_dn"] is None
        personal = row["group_id"] is None and row["owner_dn"] is not None
        if is_global:
            return jsonify(error="instance-wide templates are managed from "
                                 "the admin panel"), 403
        # Only the template's creator may delete it here. Admins use the
        # dedicated admin endpoint (admin UI) instead.
        allowed = (
            (personal and row["owner_dn"] == me)
            or (not personal and row["created_by_dn"] == me)
        )
        if not allowed:
            log_event("template_delete", "deny_not_authorized",
                      template_id=template_id)
            return jsonify(error="only the template's creator can delete it "
                                 "(admins: use the admin panel)"), 403

        conn.execute("DELETE FROM cert_templates WHERE id = ?", (template_id,))

    log_event("template_delete", "ok", template_id=template_id,
              name=row["name"])
    return jsonify(ok=True)


@app.delete("/api/admin/templates/<int:template_id>")
@require_admin
@require_csrf
def admin_delete_template(template_id):
    """Admin deletion of any template (personal, group, or instance-wide).
    This is the only path through which admins delete templates."""
    with db() as conn:
        row = conn.execute(
            "SELECT name, owner_dn, group_id FROM cert_templates WHERE id = ?",
            (template_id,)).fetchone()
        if not row:
            return jsonify(error="template not found"), 404
        conn.execute("DELETE FROM cert_templates WHERE id = ?", (template_id,))
    scope = ("global" if row["group_id"] is None and row["owner_dn"] is None
             else "personal" if row["group_id"] is None else f"group:{row['group_id']}")
    log_event("admin_template_delete", "ok", template_id=template_id,
              name=row["name"], scope=scope)
    return jsonify(ok=True)


# ============================================================
# Expiry warnings (run by systemd timer or the admin trigger)
# ============================================================
EXPIRY_WARN_THRESHOLDS = (30, 14, 7)

def run_expiry_warnings():
    """Send tiered expiry warnings (30/14/7 days) for issued certs. Each
    threshold fires at most once per job (tracked in jobs.expiry_warned).
    Safe to call repeatedly. Returns (sent, errors)."""
    now = time.time()
    horizon = now + max(EXPIRY_WARN_THRESHOLDS) * 86400
    with db() as conn:
        rows = conn.execute(
            "SELECT id, target_host, requester_email, group_id, expires_at, "
            "expiry_warned FROM jobs WHERE status='issued' "
            "AND expires_at IS NOT NULL AND expires_at > ? AND expires_at <= ?",
            (now, horizon),
        ).fetchall()

    sent = errors = 0
    for r in rows:
        days_left = int((r["expires_at"] - now) / 86400)
        eligible = [t for t in EXPIRY_WARN_THRESHOLDS if days_left <= t]
        if not eligible:
            continue
        level = min(eligible)
        last = r["expiry_warned"] or 0
        if last and last <= level:
            continue  # already warned at this tier or a closer one
        try:
            cc = [e for e in
                  ([_group_email(r["group_id"])] + _group_owner_emails(r["group_id"]))
                  if e]
            ok, reason = notify.send_expiry_warning(
                {"id": r["id"], "target_host": r["target_host"],
                 "requester_email": r["requester_email"],
                 "expires_at": r["expires_at"]},
                days_left,
                group_email=cc,
            )
            if ok:
                sent += 1
                with db() as conn:
                    conn.execute("UPDATE jobs SET expiry_warned = ? WHERE id = ?",
                                 (level, r["id"]))
            fire_webhooks("job.expiring", {
                "job_id": r["id"], "target_host": r["target_host"],
                "days_left": days_left, "expires_at": r["expires_at"],
                "requester_email": r["requester_email"],
            })
        except Exception:
            errors += 1

    # Fleet-imported certs: same tiers, but deduplicated by fingerprint -
    # one email per unique certificate listing every location it was found,
    # rather than one email per host:path. Recipient preference: the first
    # notify_email among the records, else the signer-group recipients.
    with db() as conn:
        frows = conn.execute(
            "SELECT id, host, path, cn, fingerprint, notify_email, "
            "expires_at, expiry_warned FROM fleet_certs "
            "WHERE expires_at IS NOT NULL AND expires_at > ? AND expires_at <= ?",
            (now, horizon),
        ).fetchall()

    by_fp = {}
    for r in frows:
        by_fp.setdefault(r["fingerprint"], []).append(r)

    fallback_recipients = None
    for fp, group in by_fp.items():
        expires_at = group[0]["expires_at"]
        days_left = int((expires_at - now) / 86400)
        eligible = [t for t in EXPIRY_WARN_THRESHOLDS if days_left <= t]
        if not eligible:
            continue
        level = min(eligible)
        # The group is due if ANY of its rows hasn't been warned at this tier
        due_ids = [r["id"] for r in group
                   if not (r["expiry_warned"] and r["expiry_warned"] <= level)]
        if not due_ids:
            continue
        recipient = next(((r["notify_email"] or "").strip() for r in group
                          if (r["notify_email"] or "").strip()), "")
        if not recipient:
            if fallback_recipients is None:
                fallback_recipients = _signer_recipients()
            if not fallback_recipients:
                continue
            recipient = fallback_recipients[0]
        locations = sorted({f"{r['host']}:{r['path']}" for r in group})
        cn = group[0]["cn"] or locations[0]
        label = (f"{cn} ({len(locations)} locations)" if len(locations) > 1
                 else f"{cn} on {group[0]['host']}")
        try:
            ok, _reason = notify.send_expiry_warning(
                {"id": f"fleet-{fp[:12]}", "target_host": label,
                 "requester_email": recipient, "expires_at": expires_at,
                 "locations": locations},
                days_left, group_email=None,
            )
            if ok:
                sent += 1
                ph = ",".join("?" * len(group))
                with db() as conn:
                    conn.execute(
                        f"UPDATE fleet_certs SET expiry_warned = ? WHERE id IN ({ph})",
                        [level] + [r["id"] for r in group])
            fire_webhooks("fleet_cert.expiring", {
                "fingerprint": fp, "cn": cn, "locations": locations,
                "days_left": days_left, "expires_at": expires_at,
            })
        except Exception:
            errors += 1
    return sent, errors


@app.post("/api/admin/run-expiry-warnings")
@require_admin
@require_csrf
def admin_run_expiry_warnings():
    sent, errors = run_expiry_warnings()
    log_event("expiry_warnings", "ok", sent=sent, errors=errors)
    return jsonify(ok=True, sent=sent, errors=errors)


# ============================================================
# Admin: audit log viewer
# ============================================================
@app.get("/api/admin/audit")
@require_admin
def admin_audit():
    a = request.args
    where, params = [], []
    if action := (a.get("action") or "").strip():
        where.append("action LIKE ?"); params.append(f"%{action}%")
    if actor := (a.get("actor") or "").strip():
        where.append("actor LIKE ?"); params.append(f"%{actor}%")
    if q := (a.get("q") or "").strip():
        where.append("(detail LIKE ? OR result LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    try:
        limit = min(int(a.get("limit", 100)), 500)
        offset = max(int(a.get("offset", 0)), 0)
    except ValueError:
        limit, offset = 100, 0
    sql = "SELECT * FROM audit_log"
    csql = "SELECT COUNT(*) FROM audit_log"
    if where:
        clause = " WHERE " + " AND ".join(where)
        sql += clause; csql += clause
    sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
    with db() as conn:
        total = conn.execute(csql, params).fetchone()[0]
        rows = conn.execute(sql, params + [limit, offset]).fetchall()
    return jsonify(total=total, events=[{
        "id": r["id"], "ts": r["ts"], "actor": r["actor"],
        "action": r["action"], "result": r["result"],
        "detail": json.loads(r["detail"] or "{}"),
    } for r in rows])


# ============================================================
# Fleet certificates (imported by the scan playbook)
# ============================================================
@app.get("/api/fleet-certs")
@require_auth
def list_fleet_certs():
    a = request.args
    where, params = [], []
    if host := (a.get("host") or "").strip():
        where.append("host LIKE ?"); params.append(f"%{host}%")
    if q := (a.get("q") or "").strip():
        where.append("(cn LIKE ? OR path LIKE ? OR host LIKE ? OR issuer LIKE ?)")
        params.extend([f"%{q}%"] * 4)
    if ew := a.get("expiring_within"):
        try:
            days = max(1, min(int(ew), 365))
            where.append("expires_at IS NOT NULL AND expires_at <= ?")
            params.append(time.time() + days * 86400)
        except (TypeError, ValueError):
            return jsonify(error="invalid expiring_within"), 400
    try:
        limit = min(int(a.get("limit", 200)), 1000)
        offset = max(int(a.get("offset", 0)), 0)
    except ValueError:
        limit, offset = 200, 0

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    dedupe = request.args.get("dedupe") in ("1", "true")

    with db() as conn:
        if dedupe:
            # One row per unique certificate (fingerprint); the representative
            # row is the lowest id, with a count + list of all locations.
            base = f"WITH filt AS (SELECT * FROM fleet_certs{clause})"
            total = conn.execute(
                base + " SELECT COUNT(DISTINCT fingerprint) FROM filt",
                params).fetchone()[0]
            rows = conn.execute(
                base + """
                SELECT f.*, g.location_count, g.locations
                FROM filt f
                JOIN (SELECT fingerprint, MIN(id) AS mid, COUNT(*) AS location_count,
                             GROUP_CONCAT(host || ':' || path, '\n') AS locations
                      FROM filt GROUP BY fingerprint) g
                  ON f.id = g.mid
                ORDER BY f.expires_at IS NULL, f.expires_at ASC
                LIMIT ? OFFSET ?""",
                params + [limit, offset]).fetchall()
        else:
            total = conn.execute(
                f"SELECT COUNT(*) FROM fleet_certs{clause}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT *, 1 AS location_count, host || ':' || path AS locations "
                f"FROM fleet_certs{clause} "
                f"ORDER BY expires_at IS NULL, expires_at ASC LIMIT ? OFFSET ?",
                params + [limit, offset]).fetchall()
    now = time.time()
    return jsonify(total=total, certs=[{
        "id": r["id"], "host": r["host"], "path": r["path"],
        "fingerprint": r["fingerprint"], "cn": r["cn"],
        "sans": json.loads(r["sans_json"] or "[]"),
        "issuer": r["issuer"], "not_before": r["not_before"],
        "expires_at": r["expires_at"], "cert_types": r["cert_types"],
        "notify_email": r["notify_email"],
        "first_seen": r["first_seen"], "last_seen": r["last_seen"],
        "expired": bool(r["expires_at"] and r["expires_at"] <= now),
        "location_count": r["location_count"],
        "locations": r["locations"],
    } for r in rows])


@app.delete("/api/fleet-certs/<int:cert_id>")
@require_admin
@require_csrf
def delete_fleet_cert(cert_id):
    with db() as conn:
        row = conn.execute("SELECT host, path FROM fleet_certs WHERE id = ?",
                           (cert_id,)).fetchone()
        if not row:
            return jsonify(error="not found"), 404
        conn.execute("DELETE FROM fleet_certs WHERE id = ?", (cert_id,))
    log_event("fleet_cert_delete", "ok", cert_id=cert_id,
              host=row["host"], path=row["path"])
    return jsonify(ok=True)


# ============================================================
# Admin: email / SMG settings
# ============================================================
@app.get("/api/admin/email-config")
@require_admin
def admin_get_email_config():
    return jsonify(notify.get_settings())


@app.put("/api/admin/email-config")
@require_admin
@require_csrf
def admin_put_email_config():
    payload = request.get_json(silent=True) or {}

    provider = (payload.get("provider") or "smg").strip().lower()
    if provider not in notify.VALID_PROVIDERS:
        return jsonify(error=f"provider must be one of {', '.join(notify.VALID_PROVIDERS)}"), 400

    host = (payload.get("host") or "").strip()
    from_address = (payload.get("from_address") or "").strip()
    dashboard_url = (payload.get("dashboard_url") or "").strip()
    cc = (payload.get("cc") or "").strip()
    security = (payload.get("security") or "none").strip().lower()
    username = (payload.get("username") or "").strip()
    mailgun_domain = (payload.get("mailgun_domain") or "").strip()
    mailgun_base_url = (payload.get("mailgun_base_url") or "https://api.mailgun.net").strip()

    try:
        port = int(payload.get("port") or (587 if provider == "smtp" else 25))
        timeout = int(payload.get("timeout", 10))
    except (TypeError, ValueError):
        return jsonify(error="port and timeout must be integers"), 400
    if not (1 <= port <= 65535):
        return jsonify(error="port out of range"), 400
    if not (1 <= timeout <= 120):
        return jsonify(error="timeout out of range (1-120s)"), 400

    if from_address:
        ok_e, from_address, err_e = _validate_email(from_address)
        if not ok_e or not from_address:
            return jsonify(error=f"invalid from address: {err_e or 'required'}"), 400
    else:
        return jsonify(error="from address is required"), 400

    # Per-provider required fields (only the selected provider is checked).
    if provider in ("smg", "smtp"):
        if not host or not re.match(r"^[A-Za-z0-9._-]+$", host):
            return jsonify(error="smtp host is required (hostname or IP)"), 400
        if provider == "smtp" and security not in ("none", "starttls", "ssl"):
            return jsonify(error="security must be none, starttls, or ssl"), 400
    elif provider == "mailgun":
        if not re.match(r"^[A-Za-z0-9._-]+$", mailgun_domain):
            return jsonify(error="mailgun domain is required"), 400
        if not mailgun_base_url.startswith("https://"):
            return jsonify(error="mailgun base_url must start with https://"), 400
        if not (payload.get("mailgun_api_key") or "").strip() \
                and not notify.get_settings().get("mailgun_api_key_set"):
            return jsonify(error="mailgun api_key is required"), 400

    if cc:
        for addr in [a.strip() for a in cc.split(",") if a.strip()]:
            if not EMAIL_RE.match(addr):
                return jsonify(error=f"invalid cc address: {addr}"), 400
    if dashboard_url and not dashboard_url.startswith("https://"):
        return jsonify(error="dashboard_url must start with https://"), 400

    ok, reason = notify.save_settings({
        "provider": provider,
        "host": host, "port": port, "timeout": timeout,
        "security": security, "username": username,
        "password": payload.get("password"),
        "mailgun_domain": mailgun_domain, "mailgun_base_url": mailgun_base_url,
        "mailgun_api_key": payload.get("mailgun_api_key"),
        "from_address": from_address, "cc": cc,
        "dashboard_url": dashboard_url,
    })
    if not ok:
        log_event("admin_email_config", "error", reason=reason[:128])
        return jsonify(error=reason), 500

    log_event("admin_email_config", "ok", provider=provider, host=host, port=port)
    return jsonify(ok=True, reason=reason, **notify.get_settings())


# ============================================================
# Admin: GitLab integration config
# ============================================================
@app.get("/api/admin/gitlab-config")
@require_admin
def admin_get_gitlab_config():
    return jsonify(gitlab_integration.get_settings())


@app.put("/api/admin/gitlab-config")
@require_admin
@require_csrf
def admin_put_gitlab_config():
    p = request.get_json(silent=True) or {}
    base_url = (p.get("base_url") or "").strip().rstrip("/")
    project = (p.get("project") or "").strip()
    enabled = bool(p.get("enabled"))
    assignee_ids = (p.get("assignee_ids") or "").strip()
    labels = (p.get("labels") or "").strip()

    if enabled:
        if not base_url.startswith("https://"):
            return jsonify(error="base_url must start with https://"), 400
        if not project:
            return jsonify(error="project (numeric id or group/name path) is required"), 400
        if not (p.get("api_token") or "").strip() \
                and not gitlab_integration.get_settings().get("api_token_set"):
            return jsonify(error="api_token is required to enable the integration"), 400
    if assignee_ids and not re.match(r"^[0-9,\s]+$", assignee_ids):
        return jsonify(error="assignee_ids must be comma-separated numeric GitLab user IDs"), 400

    ok, reason = gitlab_integration.save_settings({
        "enabled": enabled, "base_url": base_url, "project": project,
        "assignee_ids": ",".join(a.strip() for a in assignee_ids.split(",") if a.strip()),
        "labels": labels,
        "api_token": p.get("api_token"),
        "webhook_secret": p.get("webhook_secret"),
    })
    if not ok:
        log_event("admin_gitlab_config", "error", reason=reason[:128])
        return jsonify(error=reason), 500
    log_event("admin_gitlab_config", "ok", enabled=enabled, project=project)
    return jsonify(ok=True, reason=reason, **gitlab_integration.get_settings())


@app.post("/api/admin/gitlab-test")
@require_admin
@require_csrf
def admin_gitlab_test():
    ok, reason = gitlab_integration.test_connection()
    log_event("admin_gitlab_test", "ok" if ok else "fail", reason=reason[:128])
    if ok:
        return jsonify(ok=True, reason=reason)
    return jsonify(error=reason), 502


# ============================================================
# Admin: groups CRUD
# ============================================================
@app.get("/api/admin/groups")
@require_admin
def admin_list_groups():
    with db() as conn:
        rows = conn.execute("""
            SELECT g.id, g.name, g.description, g.email, g.notify_on_new, g.created_at,
                   (SELECT COUNT(*) FROM user_groups WHERE group_id = g.id) AS member_count,
                   (SELECT COUNT(*) FROM jobs WHERE group_id = g.id) AS job_count
              FROM groups g
             ORDER BY g.name
        """).fetchall()
    log_event("admin_list_groups", "ok", count=len(rows))
    return jsonify(groups=[dict(r) for r in rows])

@app.post("/api/admin/groups")
@require_admin
@require_csrf
def admin_create_group():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    description = (payload.get("description") or "").strip() or None
    email_raw = payload.get("email")
    if email_raw is not None and isinstance(email_raw, str):
        email_raw = email_raw.strip() or None
    else:
        email_raw = None

    if not GROUP_NAME_RE.match(name):
        return jsonify(error="group name must start with a letter and contain only [A-Za-z0-9._-], max 64 chars"), 400
    if description and len(description) > 512:
        return jsonify(error="description too long (max 512 chars)"), 400
    if email_raw:
        ok, _norm, err = _validate_email(email_raw)
        if not ok:
            return jsonify(error=f"invalid group email: {err}"), 400

    enabled_notify = 1 if payload.get("notify_on_new") else 0

    now = time.time()
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO groups (name, description, email, notify_on_new, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, description, email_raw, enabled_notify, now),
            )
            gid = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify(error="group name already exists"), 409

    log_event("admin_group_create", "ok", group_id=gid, name=name,
              email=("set" if email_raw else "none"),
              notify_on_new=enabled_notify)
    return jsonify(ok=True, id=gid, name=name, description=description,
                   email=email_raw, notify_on_new=bool(enabled_notify))

@app.put("/api/admin/groups/<int:group_id>")
@require_admin
@require_csrf
def admin_update_group(group_id):
    payload = request.get_json(silent=True) or {}
    fields, params = [], []
    if "name" in payload:
        name = (payload["name"] or "").strip()
        if not GROUP_NAME_RE.match(name):
            return jsonify(error="invalid group name"), 400
        fields.append("name = ?"); params.append(name)
    if "description" in payload:
        desc = payload["description"]
        if desc is not None and not isinstance(desc, str):
            return jsonify(error="description must be string"), 400
        if isinstance(desc, str) and len(desc) > 512:
            return jsonify(error="description too long"), 400
        fields.append("description = ?"); params.append(desc)
    if "email" in payload:
        e = payload["email"]
        if e is not None:
            if not isinstance(e, str):
                return jsonify(error="email must be string or null"), 400
            e = e.strip() or None
            if e:
                ok, _norm, err = _validate_email(e)
                if not ok:
                    return jsonify(error=f"invalid group email: {err}"), 400
        fields.append("email = ?"); params.append(e)

    if "notify_on_new" in payload:
        fields.append("notify_on_new = ?")
        params.append(1 if payload["notify_on_new"] else 0)

    if not fields:
        return jsonify(error="no fields to update"), 400
    params.append(group_id)

    try:
        with db() as conn:
            cur = conn.execute(
                f"UPDATE groups SET {', '.join(fields)} WHERE id = ?", params
            )
            if cur.rowcount == 0:
                return jsonify(error="group not found"), 404
    except sqlite3.IntegrityError:
        return jsonify(error="group name already exists"), 409

    log_event("admin_group_update", "ok", group_id=group_id)
    return jsonify(ok=True)

@app.delete("/api/admin/groups/<int:group_id>")
@require_admin
@require_csrf
def admin_delete_group(group_id):
    with db() as conn:
        row = conn.execute("SELECT name FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not row:
            return jsonify(error="group not found"), 404
        # Soft-cascade: clear job.group_id, drop memberships, then delete
        conn.execute("UPDATE jobs SET group_id = NULL WHERE group_id = ?", (group_id,))
        conn.execute("DELETE FROM user_groups WHERE group_id = ?", (group_id,))
        conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))

    log_event("admin_group_delete", "ok", group_id=group_id, name=row["name"])
    return jsonify(ok=True)

@app.get("/api/admin/groups/<int:group_id>/members")
@require_admin
def admin_group_members(group_id):
    with db() as conn:
        if not conn.execute("SELECT 1 FROM groups WHERE id = ?", (group_id,)).fetchone():
            return jsonify(error="group not found"), 404
        rows = conn.execute("""
            SELECT u.dn, u.cn, u.email, u.is_admin, u.is_active, ug.added_at,
                   ug.role
              FROM user_groups ug
              JOIN users u ON u.dn = ug.user_dn
             WHERE ug.group_id = ?
             ORDER BY ug.role DESC, u.cn COLLATE NOCASE
        """, (group_id,)).fetchall()
    return jsonify(members=[{
        "dn": r["dn"], "cn": r["cn"], "email": r["email"],
        "is_admin": bool(r["is_admin"]), "is_active": bool(r["is_active"]),
        "added_at": r["added_at"], "role": r["role"] or "member",
    } for r in rows])

@app.post("/api/admin/groups/<int:group_id>/members")
@require_admin
@require_csrf
def admin_group_add_member(group_id):
    payload = request.get_json(silent=True) or {}
    target_dn = (payload.get("dn") or "").strip()
    if not target_dn or len(target_dn) > 512:
        return jsonify(error="invalid dn"), 400

    with db() as conn:
        if not conn.execute("SELECT 1 FROM groups WHERE id = ?", (group_id,)).fetchone():
            return jsonify(error="group not found"), 404
        if not conn.execute("SELECT 1 FROM users WHERE dn = ?", (target_dn,)).fetchone():
            return jsonify(error="user not found (they must log in once before being added)"), 404
        try:
            conn.execute(
                "INSERT INTO user_groups (user_dn, group_id, added_at) VALUES (?, ?, ?)",
                (target_dn, group_id, time.time()),
            )
        except sqlite3.IntegrityError:
            return jsonify(error="user is already in this group"), 409

    log_event("admin_group_add_member", "ok",
              group_id=group_id, target_dn=target_dn[:128])
    return jsonify(ok=True)

@app.delete("/api/admin/groups/<int:group_id>/members")
@require_admin
@require_csrf
def admin_group_remove_member(group_id):
    # DN comes from request body (path-encoding DNs is awkward)
    payload = request.get_json(silent=True) or {}
    target_dn = (payload.get("dn") or "").strip()
    if not target_dn:
        return jsonify(error="missing dn"), 400

    with db() as conn:
        cur = conn.execute(
            "DELETE FROM user_groups WHERE group_id = ? AND user_dn = ?",
            (group_id, target_dn),
        )
        if cur.rowcount == 0:
            return jsonify(error="membership not found"), 404

    log_event("admin_group_remove_member", "ok",
              group_id=group_id, target_dn=target_dn[:128])
    return jsonify(ok=True)

@app.post("/api/admin/test-email")
@require_admin
@require_csrf
def admin_test_email():
    """Send a test email to verify SMTP wiring. Recipient defaults to the
    requesting admin's saved email; can be overridden by JSON {to: '...'}."""
    payload = request.get_json(silent=True) or {}
    recipient = (payload.get("to") or "").strip() or (g.user or {}).get("email")
    if not recipient:
        return jsonify(error="no recipient: set your email in Settings, or pass {\"to\":\"...\"}"), 400

    if not notify.is_enabled():
        return jsonify(error=f"notify disabled: {notify.disabled_reason()}"), 503

    fake_job = {
        "id": "TEST-" + uuid.uuid4().hex[:8],
        "target_host": "test.eucom.mil",
        "requester_email": recipient,
    }
    ok, reason = notify.send_cert_issued(fake_job, g.identity["dn"])
    log_event("admin_test_email", "ok" if ok else "fail",
              recipient=recipient, reason=reason)
    if ok:
        return jsonify(ok=True, sent_to=recipient, reason=reason)
    return jsonify(error=reason, sent_to=recipient), 502


FEEDBACK_CATEGORIES = ("bug", "feature", "general")


# ============================================================
# Admin: outbound webhooks
# ============================================================
def _validate_webhook_url(url):
    """Allow only http(s) URLs."""
    if not isinstance(url, str) or not url.strip():
        return False, "url is required"
    u = url.strip()
    if len(u) > 2048:
        return False, "url too long"
    if not (u.startswith("http://") or u.startswith("https://")):
        return False, "url must start with http:// or https://"
    return True, u


def _validate_webhook_events(events):
    """Events must be a list of allowed event names."""
    if not isinstance(events, list) or not events:
        return False, "events must be a non-empty array"
    bad = [e for e in events if e not in WEBHOOK_EVENTS]
    if bad:
        return False, f"unknown events: {', '.join(bad)}"
    return True, sorted(set(events))


def _validate_webhook_headers(headers):
    """Headers must be a flat dict of strings. Reject control chars to
    prevent header injection. Returns (ok, normalized_dict, err)."""
    if headers is None or headers == "":
        return True, {}, None
    if not isinstance(headers, dict):
        return False, None, "headers must be a JSON object"
    if len(headers) > 20:
        return False, None, "too many headers (max 20)"
    normalized = {}
    for k, v in headers.items():
        if not isinstance(k, str) or not isinstance(v, str):
            return False, None, "header names and values must be strings"
        if not HEADER_NAME_RE.match(k):
            return False, None, f"invalid header name: {k}"
        if "\r" in v or "\n" in v:
            return False, None, "header value contains control characters"
        if len(v) > 2048:
            return False, None, "header value too long"
        normalized[k] = v
    return True, normalized, None


@app.get("/api/admin/webhooks")
@require_admin
def admin_list_webhooks():
    with db() as conn:
        rows = conn.execute("""
            SELECT id, name, url, events, headers, enabled,
                   created_at, created_by_dn,
                   last_called_at, last_status_code, last_error, call_count
              FROM webhooks
             ORDER BY name COLLATE NOCASE
        """).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["enabled"] = bool(d["enabled"])
        try:
            d["events"] = json.loads(d["events"] or "[]")
        except (ValueError, TypeError):
            d["events"] = []
        try:
            d["headers"] = json.loads(d["headers"] or "{}") if d["headers"] else {}
        except (ValueError, TypeError):
            d["headers"] = {}
        out.append(d)
    return jsonify(webhooks=out, available_events=list(WEBHOOK_EVENTS))


@app.post("/api/admin/webhooks")
@require_admin
@require_csrf
def admin_create_webhook():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not name or len(name) > 128:
        return jsonify(error="name is required (max 128 chars)"), 400

    ok, url = _validate_webhook_url(payload.get("url"))
    if not ok:
        return jsonify(error=url), 400

    ok, events = _validate_webhook_events(payload.get("events"))
    if not ok:
        return jsonify(error=events), 400

    ok, headers, err = _validate_webhook_headers(payload.get("headers"))
    if not ok:
        return jsonify(error=err), 400

    enabled = bool(payload.get("enabled", True))

    with db() as conn:
        cur = conn.execute("""
            INSERT INTO webhooks (name, url, events, headers, enabled,
                                  created_at, created_by_dn)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            name, url, json.dumps(events), json.dumps(headers) if headers else None,
            1 if enabled else 0, time.time(), g.identity["dn"],
        ))
        wid = cur.lastrowid

    log_event("admin_webhook_create", "ok", webhook_id=wid, name=name,
              events=",".join(events))
    return jsonify(ok=True, id=wid)


@app.put("/api/admin/webhooks/<int:webhook_id>")
@require_admin
@require_csrf
def admin_update_webhook(webhook_id):
    payload = request.get_json(silent=True) or {}
    fields, params = [], []

    if "name" in payload:
        name = (payload["name"] or "").strip()
        if not name or len(name) > 128:
            return jsonify(error="invalid name"), 400
        fields.append("name = ?"); params.append(name)

    if "url" in payload:
        ok, url = _validate_webhook_url(payload["url"])
        if not ok:
            return jsonify(error=url), 400
        fields.append("url = ?"); params.append(url)

    if "events" in payload:
        ok, events = _validate_webhook_events(payload["events"])
        if not ok:
            return jsonify(error=events), 400
        fields.append("events = ?"); params.append(json.dumps(events))

    if "headers" in payload:
        ok, headers, err = _validate_webhook_headers(payload["headers"])
        if not ok:
            return jsonify(error=err), 400
        fields.append("headers = ?")
        params.append(json.dumps(headers) if headers else None)

    if "enabled" in payload:
        fields.append("enabled = ?")
        params.append(1 if bool(payload["enabled"]) else 0)

    if not fields:
        return jsonify(error="no fields to update"), 400
    params.append(webhook_id)

    with db() as conn:
        cur = conn.execute(
            f"UPDATE webhooks SET {', '.join(fields)} WHERE id = ?", params
        )
        if cur.rowcount == 0:
            return jsonify(error="webhook not found"), 404

    log_event("admin_webhook_update", "ok", webhook_id=webhook_id)
    return jsonify(ok=True)


@app.delete("/api/admin/webhooks/<int:webhook_id>")
@require_admin
@require_csrf
def admin_delete_webhook(webhook_id):
    with db() as conn:
        cur = conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        if cur.rowcount == 0:
            return jsonify(error="webhook not found"), 404
    log_event("admin_webhook_delete", "ok", webhook_id=webhook_id)
    return jsonify(ok=True)


@app.post("/api/admin/webhooks/<int:webhook_id>/test")
@require_admin
@require_csrf
def admin_test_webhook(webhook_id):
    """Send a synchronous test payload and return the result inline."""
    with db() as conn:
        row = conn.execute(
            "SELECT name, url, headers FROM webhooks WHERE id = ?", (webhook_id,)
        ).fetchone()
    if not row:
        return jsonify(error="webhook not found"), 404

    try:
        headers = json.loads(row["headers"] or "{}") if row["headers"] else {}
    except (ValueError, TypeError):
        headers = {}

    payload = _webhook_payload("test", {
        "message": "This is a test from the CSR Dashboard admin panel.",
        "triggered_by": _cn_from_dn(g.identity["dn"]),
    })
    status_code, error_msg = _send_webhook_sync(row["url"], payload, headers)

    # Update last_* on the row so the test result is visible like a real call
    try:
        with db() as conn:
            conn.execute("""
                UPDATE webhooks
                   SET last_called_at = ?, last_status_code = ?,
                       last_error = ?, call_count = call_count + 1
                 WHERE id = ?
            """, (time.time(), status_code, error_msg, webhook_id))
    except Exception:
        pass

    ok = (200 <= status_code < 300) and not error_msg
    log_event("admin_webhook_test", "ok" if ok else "fail",
              webhook_id=webhook_id, status=status_code,
              error=(error_msg or "-")[:96])
    return jsonify(ok=ok, status_code=status_code, error=error_msg)


# ============================================================
# Feedback
# ============================================================
FEEDBACK_CATEGORIES = ("bug", "feature", "general")


@app.post("/api/feedback")
@require_auth
@require_csrf
def submit_feedback():
    """Any authenticated user submits feedback."""
    payload = request.get_json(silent=True) or {}
    category = (payload.get("category") or "").strip().lower()
    message = (payload.get("message") or "").strip()

    if category not in FEEDBACK_CATEGORIES:
        return jsonify(error=f"category must be one of: {', '.join(FEEDBACK_CATEGORIES)}"), 400
    if not message:
        return jsonify(error="message is required"), 400
    if len(message) > 4000:
        return jsonify(error="message too long (max 4000 chars)"), 400

    with db() as conn:
        cur = conn.execute("""
            INSERT INTO feedback (user_dn, submitted_at, category, message, status)
            VALUES (?, ?, ?, ?, 'new')
        """, (g.identity["dn"], time.time(), category, message))
        fid = cur.lastrowid

    log_event("feedback_submit", "ok", feedback_id=fid, category=category,
              length=len(message))
    fire_webhooks("feedback.submitted", {
        "feedback_id": fid, "category": category, "message": message,
        "submitter_dn": g.identity["dn"],
        "submitter_cn": _cn_from_dn(g.identity["dn"]),
        "submitter_email": (g.user or {}).get("email"),
    })

    # Best-effort: email every active admin who has an email set.
    # Never let an SMTP problem fail the user's submission.
    try:
        with db() as conn:
            admin_rows = conn.execute("""
                SELECT email FROM users
                 WHERE is_admin = 1
                   AND is_active = 1
                   AND email IS NOT NULL
                   AND TRIM(email) != ''
            """).fetchall()
        admin_emails = [r["email"].strip() for r in admin_rows if r["email"]]

        submitter_cn = _cn_from_dn(g.identity["dn"]) or "(unknown)"
        submitter_email = (g.user or {}).get("email")

        if admin_emails:
            ok, reason = notify.send_feedback_received(
                {"id": fid, "category": category, "message": message},
                admin_emails, submitter_cn, submitter_email,
            )
            log_event("email_notify", "ok" if ok else "skip",
                      event="feedback_received", feedback_id=fid,
                      admin_count=len(admin_emails), reason=reason[:96])
        else:
            log_event("email_notify", "skip",
                      event="feedback_received", feedback_id=fid,
                      reason="no admins with email set")
    except Exception as e:
        log_event("email_notify", "exception",
                  event="feedback_received", feedback_id=fid,
                  error=str(e)[:128])

    return jsonify(ok=True, id=fid)


@app.get("/api/admin/feedback")
@require_admin
def admin_list_feedback():
    """List feedback. Optional ?status= filter (new/read/resolved/all)."""
    status = (request.args.get("status") or "all").lower()

    sql = """
        SELECT f.*, u.cn AS user_cn, u.email AS user_email,
               ru.cn AS resolved_by_cn
          FROM feedback f
          LEFT JOIN users u ON u.dn = f.user_dn
          LEFT JOIN users ru ON ru.dn = f.resolved_by_dn
    """
    params = []
    if status in ("new", "read", "resolved"):
        sql += " WHERE f.status = ?"
        params.append(status)
    sql += " ORDER BY f.submitted_at DESC"

    with db() as conn:
        rows = conn.execute(sql, params).fetchall()

    log_event("admin_list_feedback", "ok", status=status, count=len(rows))
    return jsonify(feedback=[dict(r) for r in rows])


@app.put("/api/admin/feedback/<int:feedback_id>")
@require_admin
@require_csrf
def admin_update_feedback(feedback_id):
    """Admin updates status or resolution_notes."""
    payload = request.get_json(silent=True) or {}
    fields, params = [], []

    if "status" in payload:
        new_status = (payload["status"] or "").strip().lower()
        if new_status not in ("new", "read", "resolved"):
            return jsonify(error="status must be new, read, or resolved"), 400
        fields.append("status = ?"); params.append(new_status)
        now = time.time()
        if new_status == "read":
            fields.append("read_at = ?"); params.append(now)
            fields.append("read_by_dn = ?"); params.append(g.identity["dn"])
        elif new_status == "resolved":
            fields.append("resolved_at = ?"); params.append(now)
            fields.append("resolved_by_dn = ?"); params.append(g.identity["dn"])

    if "resolution_notes" in payload:
        notes = payload["resolution_notes"]
        if notes is not None and not isinstance(notes, str):
            return jsonify(error="resolution_notes must be string or null"), 400
        if isinstance(notes, str) and len(notes) > 2000:
            return jsonify(error="resolution_notes too long"), 400
        fields.append("resolution_notes = ?"); params.append(notes)

    if not fields:
        return jsonify(error="no fields to update"), 400
    params.append(feedback_id)

    with db() as conn:
        cur = conn.execute(
            f"UPDATE feedback SET {', '.join(fields)} WHERE id = ?", params
        )
        if cur.rowcount == 0:
            return jsonify(error="feedback not found"), 404

    log_event("admin_feedback_update", "ok", feedback_id=feedback_id)
    return jsonify(ok=True)


@app.delete("/api/admin/feedback/<int:feedback_id>")
@require_admin
@require_csrf
def admin_delete_feedback(feedback_id):
    with db() as conn:
        cur = conn.execute("DELETE FROM feedback WHERE id = ?", (feedback_id,))
        if cur.rowcount == 0:
            return jsonify(error="feedback not found"), 404
    log_event("admin_feedback_delete", "ok", feedback_id=feedback_id)
    return jsonify(ok=True)


# ============================================================
init_db()
