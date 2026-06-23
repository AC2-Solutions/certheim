#!/usr/bin/env python3
"""Certinel API - Linux generation, manual signing, optional cert upload-back."""
import json
import logging
import logging.handlers
import calendar
import hashlib
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
import base64
import hmac
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify, Response, abort, g, has_request_context

import notify
import capabilities
import sign
import db as dbx  # pluggable DB backend (sqlite default / postgres); 'db' is the conn ctx-mgr

# ---------- Configuration ----------
# Deployment-specific values come from an env file so a new environment is
# a single file to edit. Search order: $CERTINEL_ENV, then the default
# path. Missing file is fine - sensible generic defaults below.
# Format: plain KEY=value lines, # comments allowed, no shell
# expansion (read with stdlib, so no python-dotenv dependency - matters for
# the offline/air-gapped bundle).
_ENV_DEFAULTS = {
    "CSR_HELPER_PATH": "/opt/certinel/helper/certinel_helper.sh",
    "CSR_DB_PATH": "/var/lib/certinel/jobs.db",
    "CSR_ISSUED_DIR": "/var/opt/certinel/issued",
    "CSR_SESSION_TTL": "28800",          # 8h in seconds
    "CSR_MAX_CERTLIST_BYTES": "65536",
    "CSR_MAX_CSR_BYTES": "32768",
    "CSR_MAX_CERT_BYTES": "65536",
    # When "1"/"true", the FIRST user to log in on a completely empty users
    # table is made admin (initial-setup convenience). Self-disables once any
    # user exists. Default off - on a box where mTLS isn't fully locked down,
    # auto-promoting "whoever logs in first" is a risk; enable it deliberately
    # for first-time setup, then turn it off (or it simply never fires again).
    "CSR_BOOTSTRAP_FIRST_ADMIN": "0",
    # Container mode: when "1"/"true", the app runs as a single user inside a
    # container (the container, not sudo, is the privilege boundary). The helper
    # is invoked directly (no `sudo -n`), and mTLS is terminated at the ingress
    # rather than rewritten into nginx at runtime. Default off = the VM/systemd
    # deployment is completely unchanged.
    "CERTINEL_CONTAINER": "0",
}

def _load_env_file():
    """Merge an optional KEY=value env file over os.environ over defaults."""
    values = dict(_ENV_DEFAULTS)
    path = os.environ.get("CERTINEL_ENV",
                          "/etc/certinel/certinel.env")
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

def _env_bool(key):
    return str(_ENV.get(key, _ENV_DEFAULTS.get(key, "0"))).strip().lower() \
        in ("1", "true", "yes", "on")

BOOTSTRAP_FIRST_ADMIN = _env_bool("CSR_BOOTSTRAP_FIRST_ADMIN")
CONTAINER_MODE = _env_bool("CERTINEL_CONTAINER")

# In container mode the app + helper run as the same user, so the helper is
# called directly; on a VM the unprivileged service account escalates to the
# root-owned helper via a single scoped sudoers rule.
def _helper_cmd(container_mode):
    path = _ENV["CSR_HELPER_PATH"]
    return [path] if container_mode else ["sudo", "-n", path]


HELPER = _helper_cmd(CONTAINER_MODE)
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
DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
GROUP_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")

# Cert types supported by the helper's generate-typed subcommand. Must match
# CERT_TYPE_LIST in certinel_helper.d/10-certtypes.sh.
# "server-client" is a legacy alias accepted on input, expanded to client+web.
CERT_TYPES_ALLOWED = ("web", "client", "email", "codesign",
                      "ipsec", "ocsp", "timestamp", "8021x")
EXCLUSIVE_CERT_TYPES = {"codesign", "ocsp", "timestamp"}

# Key algorithms the helper can generate. Must match KEY_ALGO_RE in
# certinel_helper.d/20-generate.sh.
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
    "job.revoked",
    "job.cancelled",
    "job.failed",
    "job.expired",
    "job.expiring",
    "job.renewed",
    "job.delivered",
    "job.delivery_failed",
    "fleet_cert.expiring",
    "feedback.submitted",
)
WEBHOOK_TIMEOUT = 10  # seconds
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")

# Thread pool for fire-and-forget webhook dispatch. Bounded so a slow
# endpoint can't pile up unbounded threads.
_webhook_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="webhook")

DASHBOARD_URL_FALLBACK = "https://csr.example.com/"


WEBHOOK_TYPES = ("generic", "slack", "teams", "discord")


def _dashboard_base():
    """Configured dashboard base URL (from email.conf), else the fallback."""
    try:
        u = (notify.get_settings() or {}).get("dashboard_url") or DASHBOARD_URL_FALLBACK
    except Exception:
        u = DASHBOARD_URL_FALLBACK
    return u or DASHBOARD_URL_FALLBACK


def _job_link(job_id):
    """Deep link to a specific job's detail (the SPA opens #job-<id>)."""
    if not job_id:
        return None
    base = _dashboard_base()
    if not base.endswith("/"):
        base += "/"
    return f"{base}#job-{job_id}"


def _webhook_payload(event, data):
    """Build the canonical JSON payload posted to generic webhooks."""
    return {
        "event": event,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dashboard_url": DASHBOARD_URL_FALLBACK,
        "data": data,
    }


def _webhook_summary(event, data):
    """A human title + one-line detail for chat integrations."""
    titles = {
        "job.created": "New CSR request",
        "job.issued": "Certificate issued",
        "job.cancelled": "CSR request cancelled",
        "job.failed": "CSR request failed",
        "job.expired": "Certificate expiring soon",
        "feedback.submitted": "Feedback submitted",
        "test": "Test notification from Certinel",
    }
    title = titles.get(event, event)
    bits = []
    if data.get("target_host"):
        bits.append(f"host: {data['target_host']}")
    if data.get("cert_type"):
        bits.append(f"type: {data['cert_type']}")
    # assignee = the group the job belongs to (best-effort name lookup)
    if data.get("group_id"):
        try:
            grp = _group_by_id(data["group_id"])
            if grp:
                bits.append(f"group: {grp['name']}")
        except Exception:
            pass
    if data.get("job_id"):
        bits.append(f"job: {data['job_id']}")
    who = (data.get("requester_email") or data.get("submitter_email")
           or data.get("completed_by_dn") or data.get("cancelled_by_dn"))
    if who:
        bits.append("by: " + (_cn_from_dn(who) if "CN=" in str(who) else str(who)))
    return title, "  •  ".join(bits)


def _format_webhook(wtype, event, data):
    """POST body for a webhook, formatted for its integration type. Includes a
    clickable "Open job" link/button to the job's dashboard deep link."""
    if wtype not in ("slack", "teams", "discord"):
        return _webhook_payload(event, data)
    title, detail = _webhook_summary(event, data)
    link = _job_link(data.get("job_id"))

    if wtype == "slack":
        text = f":bell: *{title}*" + (f"\n{detail}" if detail else "")
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
        elements = []
        if link:
            elements.append({"type": "button", "url": link,
                             "text": {"type": "plain_text", "text": "Open job"}})
        # Interactive "assign to group" select - only when Slack interactivity
        # is configured (app + signing secret) and this is a job event.
        jid = data.get("job_id")
        if jid and _slack_interactive_ready():
            opts = _slack_group_options()
            if opts:
                elements.append({
                    "type": "static_select", "action_id": "assign_group",
                    "placeholder": {"type": "plain_text", "text": "Assign to group"},
                    "options": opts})
        if elements:
            blocks.append({"type": "actions",
                           "block_id": f"job_{jid}" if jid else "noop",
                           "elements": elements})
        return {"text": text, "blocks": blocks}  # text = notification fallback

    if wtype == "discord":
        embed = {"title": title, "color": 1973492}
        if detail:
            embed["description"] = detail
        if link:
            embed["url"] = link
        return {"embeds": [embed]}

    # teams (Office 365 connector MessageCard) - OpenUri action button
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": title,
        "themeColor": "0076D7",
        "title": title,
        "text": detail or title,
    }
    if link:
        card["potentialAction"] = [{
            "@type": "OpenUri", "name": "Open job",
            "targets": [{"os": "default", "uri": link}]}]
    return card


def _slack_group_options():
    """Slack static_select options for the groups a job can be assigned to."""
    try:
        with db() as conn:
            rows = conn.execute(
                "SELECT id, name FROM groups ORDER BY name COLLATE NOCASE LIMIT 24"
            ).fetchall()
        return [{"text": {"type": "plain_text", "text": (r["name"] or "")[:75]},
                 "value": str(r["id"])} for r in rows]
    except Exception:
        return []


def _verify_slack_signature(body_bytes, timestamp, signature, secret):
    """Verify a Slack request signature (v0 HMAC-SHA256) with replay protection."""
    if not secret or not timestamp or not signature:
        return False
    try:
        if abs(time.time() - int(timestamp)) > 300:
            return False
    except (TypeError, ValueError):
        return False
    base = b"v0:" + timestamp.encode() + b":" + body_bytes
    mac = hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest("v0=" + mac, signature)


def _slack_assign_job(job_id, group_id, slack_user):
    """Reassign a job's group from a Slack interaction. Returns (ok, message)."""
    if not JOB_ID_RE.match(job_id or ""):
        return False, "invalid job id"
    try:
        gid = int(group_id)
    except (TypeError, ValueError):
        return False, "invalid group"
    grp = _group_by_id(gid)
    if not grp:
        return False, "group not found"
    with db() as conn:
        cur = conn.execute("UPDATE jobs SET group_id = ? WHERE id = ?", (gid, job_id))
        if cur.rowcount == 0:
            return False, f"job {job_id} not found"
    audit.info(f"req=slack action=slack_assign result=ok job_id={job_id} "
               f"group={grp['name']!r} slack_user={slack_user!r}")
    return True, (f":white_check_mark: Job `{job_id}` assigned to "
                  f"*{grp['name']}* by {slack_user}")


def _slack_interactive_ready():
    """True when interactive assignment is enabled AND the active transport is
    configured (http=signing secret, socket=app token)."""
    if get_setting("slack_interactive") != "1":
        return False
    if not capabilities.available("integrations.slack.interactive"):
        return False
    mode = get_setting("slack_interactive_mode") or "http"
    if mode == "socket":
        return bool(get_setting("slack_app_token"))
    return bool(get_setting("slack_signing_secret"))


def _send_webhook_sync(url, payload, headers, timeout=WEBHOOK_TIMEOUT):
    """POST a payload to a URL. Returns (status_code, error_msg or None).
    Runs in the caller's thread; safe to call from worker pool OR sync test."""
    body = json.dumps(payload).encode("utf-8")
    request_headers = {
        "Content-Type": "application/json",
        "User-Agent": "certinel/2.2",
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


def _dispatch_webhook_worker(webhook_id, name, url, event, data, headers,
                             wtype="generic"):
    """Worker function for a single webhook delivery. Logs result and
    updates the webhook row's last_* counters. Runs in webhook thread pool."""
    payload = _format_webhook(wtype, event, data)
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
                "SELECT id, name, url, events, headers, type FROM webhooks WHERE enabled = 1"
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

        wtype = r["type"] if "type" in r.keys() else "generic"
        # Chat integrations need outbound internet; skip them where the
        # capability isn't available (e.g. air-gapped). Generic webhooks may be
        # internal, so they're always allowed.
        if wtype in ("slack", "teams", "discord") \
                and not capabilities.available("integrations.chat"):
            continue

        try:
            _webhook_pool.submit(
                _dispatch_webhook_worker,
                r["id"], r["name"], r["url"], event, data, headers, wtype,
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
_h.setFormatter(logging.Formatter("certinel[%(process)d]: %(message)s"))
audit.addHandler(_h)

app = Flask(__name__)

# ---------- DB ----------
def init_db():
    if dbx.backend() == "sqlite":
        # mkdir the CURRENTLY-configured sqlite path, not the import-time DB_PATH
        # global: the migration tool (db_migrate) reconfigures dbx to a target
        # path before calling init_db(), and a Postgres deployment never sets
        # CSR_DB_PATH so the stale default (/var/lib/certinel) may be unwritable.
        Path(dbx.sqlite_path()).parent.mkdir(parents=True, exist_ok=True)
    # schema_connect() applies dialect translation (AUTOINCREMENT/REAL) so the
    # SQLite-flavored CREATE/ALTER below also build correctly on Postgres.
    conn = dbx.schema_connect()
    dbx.prepare(conn)  # backend setup (e.g. the nocase collation on Postgres)
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
    existing_cols = dbx.table_columns(conn, "jobs")
    if "requester_email" not in existing_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN requester_email TEXT")
    # Stamp set when the auto-renew pass has renewed this cert (idempotency guard).
    if "auto_renewed_at" not in existing_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN auto_renewed_at REAL")

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
    user_cols = dbx.table_columns(conn, "users")
    if "tutorial_dismissed" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN tutorial_dismissed INTEGER NOT NULL DEFAULT 0")
    # Local-auth (username/password) columns - added when password auth is an
    # option (mTLS not available). CAC users leave these NULL.
    if "username" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN username TEXT")
    if "password_hash" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    if "auth_status" not in user_cols:
        # active | pending (awaiting admin approval) | locked
        conn.execute("ALTER TABLE users ADD COLUMN auth_status TEXT NOT NULL DEFAULT 'active'")
    if "failed_attempts" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
    if "locked_until" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN locked_until REAL NOT NULL DEFAULT 0")
    # First/last name back the unified first.last username (Model A: username is
    # the display identity for CAC and local users alike; DN stays the auth key
    # for CAC). For CAC users these are auto-parsed from the DN and admin-editable.
    if "first_name" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
    if "last_name" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN last_name TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_admin ON users(is_admin)")
    # Unique username (only enforced for rows that have one; NULLs are exempt
    # in SQLite unique indexes, so CAC users with NULL username are fine).
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username "
                 "ON users(username) WHERE username IS NOT NULL")

    # Instance settings (key/value) - auth mode, trusted email domain, etc.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # Local-auth sessions (only used in local/password mode; mTLS mode gets
    # identity from the cert on every request and needs no session table).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS local_sessions (
            token       TEXT PRIMARY KEY,
            user_dn     TEXT NOT NULL,
            created_at  REAL NOT NULL,
            expires_at  REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_localsess_exp ON local_sessions(expires_at)")

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
    # v2 in-UI signing: per-template signing backend + policy (additive,
    # idempotent). signer_backend defaults to 'manual' so existing templates
    # keep the human/upload loop until an admin opts a template into a backend.
    tmpl_cols = dbx.table_columns(conn, "cert_templates")
    if "signer_backend" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN signer_backend TEXT NOT NULL DEFAULT 'manual'")
    if "openbao_role" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN openbao_role TEXT")
    if "max_ttl" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN max_ttl INTEGER")
    if "auto_sign" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN auto_sign INTEGER NOT NULL DEFAULT 0")
    # Automated renewal opt-in (per template) + optional override of the global
    # renewal window (days before expiry to renew); NULL window = use global.
    if "auto_renew" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 0")
    if "renew_before_days" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN renew_before_days INTEGER")
    # Certificate delivery (P1): ship the issued cert (and per key_mode, the key)
    # to its destination. Per-template; off ('none') by default.
    if "delivery_backend" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN delivery_backend TEXT NOT NULL DEFAULT 'none'")
    if "key_mode" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN key_mode TEXT NOT NULL DEFAULT 'destination'")
    if "delivery_target" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN delivery_target TEXT")
    if "delivery_reload" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN delivery_reload TEXT")
    # Key-handling Phase 3: per-template private-key storage override.
    # NULL = use the global key_storage policy (vault | return_once | host).
    if "key_storage" not in tmpl_cols:
        conn.execute("ALTER TABLE cert_templates ADD COLUMN key_storage TEXT")

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
    # Idempotent migration: integration type controls the payload format
    # (generic JSON, or Slack/Teams/Discord chat message).
    wh_cols = dbx.table_columns(conn, "webhooks")
    if "type" not in wh_cols:
        conn.execute("ALTER TABLE webhooks ADD COLUMN type TEXT NOT NULL DEFAULT 'generic'")

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
    group_cols = dbx.table_columns(conn, "groups")
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
    ug_cols = dbx.table_columns(conn, "user_groups")
    if "role" not in ug_cols:
        conn.execute("ALTER TABLE user_groups ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_groups_gid ON user_groups(group_id)")

    # Add group_id to jobs (idempotent)
    job_cols = dbx.table_columns(conn, "jobs")
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
    # v2 in-UI signing audit: who approved the sign, when, and via which backend.
    if "approved_by_dn" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN approved_by_dn TEXT")
    if "approved_at" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN approved_at REAL")
    if "signed_via" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN signed_via TEXT")
    # v2 per-template signing policy: the template the request was made under,
    # so the sign route resolves THAT template's backend/role/ttl (not a global).
    if "template_id" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN template_id INTEGER")
    # v2 revocation: when an issued cert is revoked (status -> 'revoked') + by whom.
    if "revoked_at" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN revoked_at REAL")
    if "revoked_by_dn" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN revoked_by_dn TEXT")
    # Certificate delivery (P1): per-job delivery state for the certinel-deliver timer.
    if "delivery_status" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN delivery_status TEXT")
    if "delivery_detail" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN delivery_detail TEXT")
    if "delivered_at" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN delivered_at REAL")
    if "delivery_attempts" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN delivery_attempts INTEGER NOT NULL DEFAULT 0")
    if "delivery_next_attempt" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN delivery_next_attempt REAL")
    # Key-handling Phase 2: where a server-generated private key lives.
    # key_vault_path set -> in OpenBao (host copy shredded); key_storage snapshots
    # the policy at generation (vault | return_once | host | returned).
    if "key_vault_path" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN key_vault_path TEXT")
    if "key_storage" not in job_cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN key_storage TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_group_id ON jobs(group_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_cert_type ON jobs(cert_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_expires ON jobs(expires_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_renewed_from ON jobs(renewed_from)")

    # Pull-delivery tokens (delivery_backend='pull'): the dashboard stores the
    # issued bundle and the destination fetches it once with a scoped, short-
    # lived token at GET /deliver/pull/<token>. Rows are deleted on the final
    # pull and purged when expired (deliver.purge_expired_pulls).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS delivery_pulls (
            token        TEXT PRIMARY KEY,
            job_id       INTEGER,
            target_host  TEXT,
            certificate  TEXT NOT NULL,
            private_key  TEXT,
            created_at   REAL NOT NULL,
            expires_at   REAL NOT NULL,
            max_uses     INTEGER NOT NULL DEFAULT 1,
            uses         INTEGER NOT NULL DEFAULT 0,
            last_pull_at REAL,
            last_pull_ip TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_delivery_pulls_exp ON delivery_pulls(expires_at)")

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

    # ACME server (Phase 4): state for the dashboard's own RFC 8555 directory.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS acme_accounts (
            id          TEXT PRIMARY KEY,
            thumbprint  TEXT UNIQUE NOT NULL,
            jwk_json    TEXT NOT NULL,
            contact     TEXT,
            status      TEXT NOT NULL DEFAULT 'valid',
            created_at  REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS acme_orders (
            id               TEXT PRIMARY KEY,
            account_id       TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'pending',
            identifiers_json TEXT NOT NULL,
            csr_pem          TEXT,
            cert_id          TEXT,
            error            TEXT,
            created_at       REAL NOT NULL,
            expires_at       REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS acme_authzs (
            id         TEXT PRIMARY KEY,
            order_id   TEXT NOT NULL,
            identifier TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'pending'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS acme_challenges (
            id       TEXT PRIMARY KEY,
            authz_id TEXT NOT NULL,
            token    TEXT NOT NULL,
            status   TEXT NOT NULL DEFAULT 'pending',
            error    TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS acme_certs (
            id         TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            pem        TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS acme_nonces (
            nonce      TEXT PRIMARY KEY,
            created_at REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authzs(order_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_acme_chal_authz ON acme_challenges(authz_id)")
    # 4b migrations: per-challenge type (http-01/dns-01); cert serial + revoked.
    chal_cols = dbx.table_columns(conn, "acme_challenges")
    if "type" not in chal_cols:
        conn.execute("ALTER TABLE acme_challenges ADD COLUMN type TEXT NOT NULL DEFAULT 'http-01'")
    cert_cols = dbx.table_columns(conn, "acme_certs")
    if "serial" not in cert_cols:
        conn.execute("ALTER TABLE acme_certs ADD COLUMN serial TEXT")
    if "revoked" not in cert_cols:
        conn.execute("ALTER TABLE acme_certs ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0")

    # Trust store: admin-uploaded root/intermediate CAs, assembled into one
    # bundle and distributed to fleet hosts (truststore.py / routes_truststore.py).
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trust_certs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            fingerprint  TEXT NOT NULL UNIQUE,
            pem          TEXT NOT NULL,
            role         TEXT NOT NULL DEFAULT 'intermediate',
            subject      TEXT,
            issuer       TEXT,
            serial       TEXT,
            not_before   REAL,
            expires_at   REAL,
            enabled      INTEGER NOT NULL DEFAULT 1,
            created_at   REAL NOT NULL,
            created_by   TEXT,
            notes        TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_trust_certs_exp ON trust_certs(expires_at)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trust_targets (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            host           TEXT NOT NULL UNIQUE,
            label          TEXT,
            enabled        INTEGER NOT NULL DEFAULT 1,
            last_status    TEXT,
            last_pushed_at REAL,
            last_detail    TEXT,
            created_at     REAL NOT NULL,
            created_by     TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trust_pulls (
            token        TEXT PRIMARY KEY,
            created_at   REAL NOT NULL,
            expires_at   REAL NOT NULL,
            max_uses     INTEGER NOT NULL DEFAULT 0,
            uses         INTEGER NOT NULL DEFAULT 0,
            last_pull_at REAL,
            last_pull_ip TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_trust_pulls_exp ON trust_pulls(expires_at)")

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
    conn = dbx.connect()
    conn.execute("PRAGMA foreign_keys=ON")  # sqlite enforces FKs; no-op on postgres
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

# ---------------------------------------------------------------------------
# Local (username/password) authentication
#
# Used when CAC mTLS is not available (auth_mode == "local"). CAC remains the
# PRIMARY method: in mtls mode a verified cert always wins; password accounts
# stay usable as a fallback. Passwords use PBKDF2-HMAC-SHA256 (stdlib, FIPS-
# approved) - no third-party crypto deps, which matters for the offline
# wheelhouse. STIG-aligned policy + failed-attempt lockout.
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS = 600_000
LOCKOUT_THRESHOLD = 5          # failed attempts before lockout
LOCKOUT_SECONDS = 900          # 15 minutes
LOCAL_SESSION_TTL = SESSION_TTL  # reuse the configured session lifetime
PWPOLICY_MIN_LEN = 15

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
# Name fields for derived usernames: letters plus common name punctuation
# (space, hyphen, apostrophe, period). We strip the punctuation when building
# the username but allow it in the typed name.
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{0,63}$")

def _normalize_name_part(s):
    """Lowercase a name part and reduce it to [a-z0-9] (drop spaces,
    apostrophes, hyphens, accents-as-typed). 'O'Brien' -> 'obrien'."""
    s = (s or "").strip().lower()
    # keep ascii letters/digits only
    return re.sub(r"[^a-z0-9]", "", s)

def derive_username(first, last, conn):
    """Build a 'first.last' username, auto-suffixing on collision:
    john.smith, john.smith2, john.smith3, ... Returns the assigned username.
    Must be called inside an open db() transaction so the existence check and
    the caller's INSERT are consistent; the UNIQUE index is the final guard."""
    f = _normalize_name_part(first)
    l = _normalize_name_part(last)
    base = ".".join(p for p in (f, l) if p) or "user"
    base = base[:60]  # leave room for a numeric suffix within 64
    # A local user's PRIMARY KEY is its dn = "local:<username>", so treat BOTH
    # the username column AND the local:<name> dn space as taken. A row can
    # occupy "local:<base>" with a NULL username column (e.g. admin-created
    # users, or older-schema rows); checking the username column alone misses
    # that, derive returns the colliding base, and the INSERT then fails on the
    # dn PK - which the retry loop can't escape (same base re-derived forever).
    rows = conn.execute(
        "SELECT username, dn FROM users "
        "WHERE username = ? OR username LIKE ? OR dn = ? OR dn LIKE ?",
        (base, base + "%", "local:" + base, "local:" + base + "%")
    ).fetchall()
    taken = set()
    for r in rows:
        if r["username"]:
            taken.add(r["username"])
        if r["dn"] and r["dn"].startswith("local:"):
            taken.add(r["dn"][len("local:"):])
    if base not in taken:
        return base
    n = 2
    while f"{base}{n}" in taken:
        n += 1
    return f"{base}{n}"

def parse_dod_cn(dn):
    """Best-effort (first, last) from a CAC/PIV DN. Such CNs are typically
    LAST.FIRST.MIDDLE.EDIPI (e.g. SMITH.JOHN.ANDREW.1234567890). Returns
    title-cased (first, last); empty strings when it can't tell (admin can
    then correct via the user edit form)."""
    cn = _cn_from_dn(dn) if dn else ""
    if not cn or cn == dn:  # _cn_from_dn returns the dn unchanged if no CN=
        # only treat as CN if the dn actually had a CN= component
        m = None
        for part in (dn or "").split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                m = part[3:]
                break
        cn = m or ""
    if not cn:
        return ("", "")
    toks = [t for t in cn.split(".") if t]
    if toks and toks[-1].isdigit():   # drop trailing EDIPI
        toks = toks[:-1]
    if len(toks) >= 2:
        return (toks[1].title(), toks[0].title())   # FIRST, LAST
    if len(toks) == 1:
        return ("", toks[0].title())
    return ("", "")

def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode())

def verify_password(password, stored):
    try:
        algo, iters, b64salt, b64dk = (stored or "").split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(b64salt)
        expected = base64.b64decode(b64dk)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

def password_policy_errors(pw):
    """Return a list of human-readable policy violations (empty = OK)."""
    e = []
    if len(pw or "") < PWPOLICY_MIN_LEN:
        e.append(f"at least {PWPOLICY_MIN_LEN} characters")
    if not re.search(r"[A-Z]", pw or ""): e.append("an uppercase letter")
    if not re.search(r"[a-z]", pw or ""): e.append("a lowercase letter")
    if not re.search(r"[0-9]", pw or ""): e.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", pw or ""): e.append("a special character")
    return e


def parse_trusted_domains(raw):
    """Normalize the trusted-registration-domain setting into a list.

    Stored as a single string for backward compatibility, but may now hold
    MULTIPLE domains separated by comma / whitespace / semicolon. Each entry is
    lowercased and stripped of a leading '@'; blanks and duplicates are dropped
    and order is preserved. Empty input -> [] (meaning 'any valid email may
    self-register')."""
    if not raw:
        return []
    out = []
    for part in re.split(r"[\s,;]+", str(raw).strip().lower()):
        part = part.strip().lstrip("@")
        if part and part not in out:
            out.append(part)
    return out

# --- login banners ----------------------------------------------------------
# The login page can show a consent/notice banner gated by an "I agree"
# checkbox. The banner is chosen post-install from the admin UI (or "none").
# Each preset: label (admin dropdown), link (the agreement link text), title
# (modal heading), paragraphs[] and items[] (rendered as <p> then a <ul>).
LOGIN_BANNERS = {
    "dod": {
        "label": "DoD / U.S. Government (USG)",
        "link": "DoD System User Access Agreement",
        "title": "U.S. Government (USG) Notice and Consent Banner",
        "paragraphs": [
            "You are accessing a U.S. Government (USG) Information System (IS) "
            "that is provided for USG-authorized use only.",
            "By using this IS (which includes any device attached to this IS), "
            "you consent to the following conditions:",
        ],
        "items": [
            "The USG routinely intercepts and monitors communications on this "
            "IS for purposes including, but not limited to, penetration "
            "testing, COMSEC monitoring, network operations and defense, "
            "personnel misconduct (PM), law enforcement (LE), and "
            "counterintelligence (CI) investigations.",
            "At any time, the USG may inspect and seize data stored on this IS.",
            "Communications using, or data stored on, this IS are not private, "
            "are subject to routine monitoring, interception, and search, and "
            "may be disclosed or used for any USG-authorized purpose.",
            "This IS includes security measures (e.g., authentication and "
            "access controls) to protect USG interests — not for your "
            "personal benefit or privacy.",
            "Notwithstanding the above, using this IS does not constitute "
            "consent to PM, LE or CI investigative searching or monitoring of "
            "the content of privileged communications, or work product, "
            "related to personal representation or services by attorneys, "
            "psychotherapists, or clergy, and their assistants. Such "
            "communications and work product are private and confidential. "
            "See User Agreement for details.",
        ],
    },
    "hipaa": {
        "label": "HIPAA Privacy Notice",
        "link": "HIPAA Notice",
        "title": "HIPAA Notice — Protected Health Information (PHI)",
        "paragraphs": [
            "This system may contain Protected Health Information (PHI) "
            "subject to the Health Insurance Portability and Accountability "
            "Act (HIPAA) and is restricted to authorized users only.",
            "By accessing this system you acknowledge and agree that:",
        ],
        "items": [
            "You will access, use, and disclose PHI only as permitted by HIPAA "
            "and your organization's policies, limited to the minimum "
            "necessary for your role.",
            "All access to PHI is logged and subject to audit; unauthorized "
            "access, use, or disclosure may result in disciplinary action and "
            "civil or criminal penalties.",
            "You will safeguard PHI from unauthorized viewing, sharing, or "
            "storage, and report any suspected breach immediately.",
            "This system is monitored to ensure compliance with the HIPAA "
            "Privacy and Security Rules.",
        ],
    },
    "nsa": {
        "label": "NSA / National Security System",
        "link": "U.S. Government User Agreement",
        "title": "U.S. Government Information System — Notice and Consent",
        "paragraphs": [
            "You are accessing a U.S. Government (USG) Information System (IS), "
            "which may be a National Security System, provided for "
            "USG-authorized use only.",
            "By using this IS, you consent to the following conditions:",
        ],
        "items": [
            "The USG routinely intercepts and monitors communications on this "
            "IS for authorized purposes, including security monitoring, "
            "network operations and defense, and investigations.",
            "At any time, the USG may inspect and seize data stored on this IS.",
            "Communications using, or data stored on, this IS are not private "
            "and may be disclosed or used for any USG-authorized purpose.",
            "This IS includes security measures to protect USG interests — "
            "not for your personal benefit or privacy.",
            "Unauthorized use may subject you to administrative action and "
            "civil or criminal penalties.",
        ],
    },
}

# --- instance settings (key/value) -----------------------------------------
_SETTINGS_DEFAULTS = {
    # "mtls" = CAC required (current/default behavior). "local" = username/
    # password auth (set by installer when mTLS isn't available).
    "auth_mode": "mtls",
    # Optional filter for self-registration: if set, only emails at this exact
    # domain may register. Empty = no domain restriction (any valid email).
    "trusted_email_domain": "",
    # "1" = new local registrations require admin approval before active.
    "require_admin_approval": "0",
    # "1" = self-registration is open (independent of the email domain filter).
    "allow_registration": "0",
    # Login consent banner: "none" or a key in LOGIN_BANNERS, or "custom".
    "login_banner": "none",
    # Custom banner content (used only when login_banner == "custom").
    "login_banner_custom_title": "Notice and Consent",
    "login_banner_custom_text": "",
}

def get_setting(key):
    try:
        with db() as conn:
            row = conn.execute(
                "SELECT value FROM app_settings WHERE key = ?", (key,)
            ).fetchone()
        if row is not None:
            return row["value"]
    except Exception:
        pass
    return _SETTINGS_DEFAULTS.get(key)

def set_setting(key, value):
    with db() as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value))

# Let the capability resolver read admin-declared env flags (cap_*).
capabilities.configure(get_setting=get_setting)
import licensing  # noqa: E402
licensing.configure(get_setting=get_setting)
sign.configure(get_setting=get_setting, set_setting=set_setting)
try:                                    # premium: absent in the Community build
    import deliver  # noqa: E402
    deliver.configure(get_setting=get_setting)
except ImportError:
    deliver = None
import keystore  # noqa: E402
keystore.configure(get_setting=get_setting)
import truststore  # noqa: E402
truststore.configure(get_setting=get_setting)
# Re-export the delivery-retry pass so the certinel-deliver timer can call
# app.run_deliveries() without its own Flask context (same pattern as
# run_auto_renew / run_expiry_warnings). Premium: stubbed in the Community build.
if deliver is not None:
    run_deliveries = deliver.run_deliveries
else:
    def run_deliveries(*_a, **_k):
        log_event("delivery", "skipped_community_build")
        return (0, 0, 0)

def auth_mode():
    # An explicit admin choice (a row in app_settings) always wins. We read it
    # RAW here rather than via get_setting(), whose _SETTINGS_DEFAULTS fallback
    # would mask "unset" as "mtls".
    with db() as conn:
        row = conn.execute(
            "SELECT value FROM app_settings WHERE key = 'auth_mode'").fetchone()
    if row and row[0]:
        return row[0]
    # No explicit setting yet: default to CAC/mTLS only on a build+license that
    # can actually do it (auth.cac entitled — a government build with a gov
    # license). Otherwise password auth, so a fresh Community or Commercial box
    # never tries to use a CAC it isn't entitled to.
    try:
        import capabilities
        return "mtls" if capabilities.is_entitled("auth.cac") else "local"
    except Exception:
        return "local"

def current_banner():
    """Resolve the configured login banner to a render-ready dict, or None.
    Public (the login page needs it pre-auth). Returns:
      {key, label, link, title, paragraphs[], items[]}  or  None ("none"/empty).
    """
    key = (get_setting("login_banner") or "none").strip().lower()
    if key == "none":
        return None
    if key == "custom":
        title = (get_setting("login_banner_custom_title") or "Notice and Consent").strip()
        text = (get_setting("login_banner_custom_text") or "").strip()
        if not text:
            return None
        # Blank-line-separated blocks become paragraphs; no items for custom.
        paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
        return {"key": "custom", "label": "Custom", "link": title or "Notice",
                "title": title or "Notice and Consent",
                "paragraphs": paras or [text], "items": []}
    b = LOGIN_BANNERS.get(key)
    if not b:
        return None
    if key in GOV_BANNERS and not capabilities.available("profiles.public_sector"):
        return None      # licensed pack: don't render without entitlement
    return {"key": key, "label": b["label"], "link": b["link"],
            "title": b["title"], "paragraphs": list(b["paragraphs"]),
            "items": list(b["items"])}

# Government/public-sector consent banners - gated by the profiles.public_sector
# license (hipaa stays available for commercial healthcare customers).
GOV_BANNERS = {"dod", "nsa"}

def banner_options():
    """Admin dropdown choices: built-in presets + none + custom. Government
    presets appear only when the public-sector pack is licensed."""
    gov_ok = capabilities.available("profiles.public_sector")
    opts = [{"key": "none", "label": "No banner"}]
    opts += [{"key": k, "label": v["label"]} for k, v in LOGIN_BANNERS.items()
             if k not in GOV_BANNERS or gov_ok]
    opts.append({"key": "custom", "label": "Custom message…"})
    return opts

# --- local sessions ---------------------------------------------------------
LOCAL_SESSION_COOKIE = "csr_session"

def create_local_session(user_dn):
    token = secrets.token_urlsafe(32)
    now = time.time()
    with db() as conn:
        conn.execute(
            "INSERT INTO local_sessions (token, user_dn, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token, user_dn, now, now + LOCAL_SESSION_TTL))
    return token

def session_user_dn(token):
    if not token:
        return None
    now = time.time()
    with db() as conn:
        row = conn.execute(
            "SELECT user_dn, expires_at FROM local_sessions WHERE token = ?",
            (token,)).fetchone()
        if not row:
            return None
        if row["expires_at"] < now:
            conn.execute("DELETE FROM local_sessions WHERE token = ?", (token,))
            return None
    return row["user_dn"]

def destroy_local_session(token):
    if not token:
        return
    with db() as conn:
        conn.execute("DELETE FROM local_sessions WHERE token = ?", (token,))

def local_identity():
    """Resolve identity from a local session cookie, if any."""
    token = request.cookies.get(LOCAL_SESSION_COOKIE, "")
    dn = session_user_dn(token)
    if dn:
        return {"dn": dn, "serial": "-", "via": "local"}
    return None

def resolve_identity():
    """Single-mode identity. A box is EITHER mtls (CAC only) or local
    (username/password only), set at install. In mtls mode only a verified
    client cert authenticates; in local mode only a local session cookie does.
    No cross-mode fallback - that's what avoids the CAC-vs-password conflict."""
    if auth_mode() == "mtls":
        dn = request.headers.get("X-Client-DN", "").strip()
        verify = request.headers.get("X-Client-Verify", "").strip()
        if verify == "SUCCESS" and dn:
            return {"dn": dn,
                    "serial": request.headers.get("X-Client-Serial", "").strip(),
                    "via": "cac"}
        return {"dn": f"ip:{request.remote_addr}", "serial": "-", "via": "none"}
    # local mode
    loc = local_identity()
    if loc:
        return loc
    return {"dn": f"ip:{request.remote_addr}", "serial": "-", "via": "none"}

def log_event(action, result, **extra):
    # Resolve actor/request context if we're inside a request; background passes
    # (the expiry + auto-renew systemd timers) call this with no request context,
    # so fall back to a 'system' actor instead of raising "working outside of
    # application context".
    if has_request_context():
        req_id = g.req_id
        src = request.remote_addr
        ident = g.identity or {}
    else:
        req_id, src, ident = "system", "-", {}
    parts = [
        f"req={req_id}", f"action={action}", f"result={result}",
        f"src={src}",
        f"user=\"{ident.get('dn','-')}\"",
        f"serial={ident.get('serial','-')}",
    ]
    for k, v in extra.items():
        parts.append(f"{k}={v}")
    audit.info(" ".join(parts))
    # Mirror into the searchable audit table. Best-effort: never let audit
    # storage break the request path.
    try:
        actor = ident.get("dn")
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
        # Strict per-mode auth: in local mode ONLY a valid local session
        # (via="local") authenticates. The ip: fallback (via="none") is NOT a
        # logged-in user - rejecting it here enforces the password gate
        # server-side and makes sign-out final (no auto-let-back-in as an
        # auto-created, active ip: user). mtls mode keeps its ip: fallback.
        if auth_mode() == "local" and g.identity.get("via") != "local":
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
        # Strict per-mode auth (see require_auth): in local mode the ip:
        # fallback is unauthenticated and must never reach an admin endpoint.
        if auth_mode() == "local" and g.identity.get("via") != "local":
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
            if request.headers.get("X-Requested-With") != "certinel":
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
            # First-admin bootstrap: if enabled AND the users table is
            # completely empty, this very first user becomes admin. The
            # emptiness check is what makes it safe(ish) and self-disabling -
            # it can only ever fire for the literal first account, never again.
            make_admin = 0
            if BOOTSTRAP_FIRST_ADMIN:
                total = conn.execute(
                    "SELECT COUNT(*) AS n FROM users"
                ).fetchone()["n"]
                if total == 0:
                    make_admin = 1
            # Auto-parse first.last from the CAC DN and assign a unified
            # username (Model A). Admin can correct names later; the username
            # then regenerates. Skip for non-CAC synthetic identities (ip:/local:).
            first, last = ("", "")
            username = None
            if not dn.startswith("ip:") and not dn.startswith("local:"):
                first, last = parse_dod_cn(dn)
                if first or last:
                    username = derive_username(first, last, conn)
            conn.execute("""
                INSERT INTO users (dn, cn, email, is_admin, is_active,
                                   first_name, last_name, username,
                                   created_at, last_seen_at)
                VALUES (?, ?, NULL, ?, 1, ?, ?, ?, ?, ?)
            """, (dn, cn, make_admin, first or None, last or None,
                  username, now, now))
            if make_admin:
                log_event("user_created", "ok", dn=dn[:128],
                          bootstrap_admin=1, username=username or "")
                log_event("admin_bootstrap", "ok", dn=dn[:128])
            else:
                log_event("user_created", "ok", dn=dn[:128],
                          username=username or "")
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
    g.identity = resolve_identity()
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

def _normalize_cert_to_pem(raw_bytes):
    """Accept a certificate in any common format a CA might hand back and return
    PEM text (str), or None if it isn't a parseable cert. Windows CAs hand out
    DER-encoded .cer files by default (binary), and sometimes PKCS#7 (.p7b)
    bundles; users/browsers also paste PEM. We convert all three to a single PEM
    leaf certificate so the rest of the upload pipeline (subject parse, pubkey
    match, expiry, storage) only ever sees PEM. openssl does the conversion (no
    new dependency); the client's only job is to deliver the bytes intact."""
    if not raw_bytes:
        return None
    # 1) Already PEM? Use as-is.
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except Exception:
        text = None
    if text and "-----BEGIN CERTIFICATE-----" in text:
        return text
    # 2) DER -> PEM (a Windows .cer).
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
            input=raw_bytes, capture_output=True, timeout=10)
        if proc.returncode == 0 and b"BEGIN CERTIFICATE" in proc.stdout:
            return proc.stdout.decode("utf-8", errors="strict")
    except Exception:
        pass
    # 3) PKCS#7 (.p7b), DER or PEM form -> first (leaf) cert -> PEM.
    for inform in ("DER", "PEM"):
        try:
            proc = subprocess.run(
                ["openssl", "pkcs7", "-inform", inform, "-print_certs",
                 "-outform", "PEM"],
                input=raw_bytes, capture_output=True, timeout=10)
            if proc.returncode == 0 and b"BEGIN CERTIFICATE" in proc.stdout:
                out = proc.stdout.decode("utf-8", errors="replace")
                start = out.find("-----BEGIN CERTIFICATE-----")
                end = out.find("-----END CERTIFICATE-----")
                if start != -1 and end != -1:
                    return out[start:end + len("-----END CERTIFICATE-----")] + "\n"
        except Exception:
            pass
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
    the system CA bundle (which includes any imported enterprise CAs), and validity
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


class CompletionError(Exception):
    """Raised by _attach_signed_cert. `.status` + `.payload` map straight to an
    HTTP JSON response so both the manual-upload and the v2 /sign callers return
    the right code (404 not-found, 409 wrong-state, 400 pubkey-mismatch)."""
    def __init__(self, status, payload):
        super().__init__(payload.get("error", "completion error"))
        self.status = status
        self.payload = payload


def _fleet_track_issued(conn, host, cert_pem, notify_email=None, job_id=None):
    """Upsert a dashboard-issued cert into fleet_certs so it is monitored for
    expiry alongside scanned certs — issuing a cert here is the same as finding
    one in the wild. Keyed on (host, path) with a synthetic 'dashboard:<job_id>'
    path so re-issues update in place and never collide with a real scanned
    filesystem path. Best-effort: never fails the issue."""
    try:
        import import_certs
        info = import_certs.parse_cert(cert_pem)
        if not info:
            return
        path = "dashboard:" + (str(job_id) if job_id
                               else (info.get("fingerprint") or "")[:16])
        now = time.time()
        conn.execute("""
            INSERT INTO fleet_certs
                (host, path, fingerprint, cn, sans_json, issuer, serial,
                 not_before, expires_at, cert_types, notify_email,
                 first_seen, last_seen, pem)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(host, path) DO UPDATE SET
                fingerprint=excluded.fingerprint, cn=excluded.cn,
                sans_json=excluded.sans_json, issuer=excluded.issuer,
                serial=excluded.serial, not_before=excluded.not_before,
                expires_at=excluded.expires_at, cert_types=excluded.cert_types,
                notify_email=excluded.notify_email, last_seen=excluded.last_seen,
                pem=excluded.pem, expiry_warned=0
        """, (host, path, info.get("fingerprint") or "", info.get("cn"),
              json.dumps(info.get("sans") or []), info.get("issuer"),
              info.get("serial"), info.get("not_before"), info.get("expires_at"),
              ",".join(info.get("cert_types") or []), notify_email,
              now, now, cert_pem))
    except Exception as e:  # noqa: BLE001 - tracking must never break issuance
        sys.stderr.write(f"fleet track failed for {host}: {e}\n")


def _attach_signed_cert(job_id, cert_pem, *, actor_dn, signed_via,
                        approver_dn=None, log_action="attach_signed_cert"):
    """Shared completion path for an issued certificate. Verifies the signed
    cert against the job's stored CSR (pubkey match), flips the job to 'issued',
    drops the cert to ISSUED_DIR, fires the job.issued webhook, and emails the
    requester. Used by the manual cert-upload route and the v2 approve-&-sign
    route, so both producers converge on identical verification + side effects.

    `signed_via` is recorded on the job ('manual' | 'openbao'); `approver_dn`
    (set only for an approval-gated sign) records who authorized it.
    Returns {"expires_at", "warnings", "target_host"}.
    Raises CompletionError(status, payload) on not-found/wrong-state/mismatch."""
    now = time.time()
    with db() as conn:
        row = conn.execute(
            "SELECT csr_pem, target_host, status, requester_email, group_id "
            "FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            raise CompletionError(404, {"error": "job not found"})
        if row["status"] != "pending":
            raise CompletionError(
                409, {"error": f"job in status '{row['status']}', cannot accept cert"})
        if not _verify_cert_matches_csr(row["csr_pem"], cert_pem):
            log_event(log_action, "deny_pubkey_mismatch", job_id=job_id,
                      target=row["target_host"], signed_via=signed_via)
            raise CompletionError(400, {"error":
                "cert public key does not match this job's CSR. "
                "Verify you uploaded the cert for the correct job."})
        expires_at = _cert_expiry(cert_pem)
        conn.execute(
            "UPDATE jobs SET status='issued', cert_pem=?, completed_at=?, "
            "completed_by_dn=?, expires_at=?, error=NULL, signed_via=?, "
            "approved_by_dn=?, approved_at=? WHERE id=?",
            (cert_pem, now, actor_dn, expires_at, signed_via, approver_dn,
             (now if approver_dn else None), job_id))
        # Auto-track the issued cert for fleet-wide expiry monitoring.
        _fleet_track_issued(conn, row["target_host"], cert_pem,
                            notify_email=row["requester_email"], job_id=job_id)

    # Filesystem drop (best-effort; never fail the issue over a fs hiccup).
    try:
        Path(ISSUED_DIR).mkdir(parents=True, exist_ok=True)
        target_path = Path(ISSUED_DIR) / f"{row['target_host']}.cer"
        target_path.write_text(cert_pem)
        os.chmod(target_path, 0o644)
        run_helper(["chown-issued", target_path.name])
    except Exception as e:
        sys.stderr.write(f"filesystem drop failed for {row['target_host']}: {e}\n")
        log_event("filesystem_drop", "error", job_id=job_id, error=str(e)[:128])

    warnings = _cert_upload_warnings(cert_pem)
    log_event(log_action, "ok", job_id=job_id, target=row["target_host"],
              uploader=actor_dn, signed_via=signed_via, warnings=len(warnings))
    fire_webhooks("job.issued", {
        "job_id": job_id, "target_host": row["target_host"],
        "requester_email": row["requester_email"],
        "completed_by_dn": actor_dn,
        "completed_by_cn": _cn_from_dn(actor_dn),
        "group_id": row["group_id"] if "group_id" in row.keys() else None,
        "expires_at": expires_at,
    })
    try:
        group_email_addr = _group_email(row["group_id"]) if "group_id" in row.keys() else None
        ok, reason = notify.send_cert_issued(
            {"id": job_id, "target_host": row["target_host"],
             "requester_email": row["requester_email"]},
            actor_dn, group_email=group_email_addr)
        log_event("email_notify", "ok" if ok else "skip", job_id=job_id,
                  event="cert_issued",
                  recipient=(row["requester_email"] or group_email_addr or "-"),
                  group_cc=(group_email_addr if (row["requester_email"] and group_email_addr) else "-"),
                  reason=reason[:96])
    except Exception as e:
        log_event("email_notify", "exception", job_id=job_id, error=str(e)[:128])

    # Certificate delivery (P1): if this job's template configures a delivery
    # backend, flag it pending and attempt an immediate ship. Best-effort and
    # fully isolated - a delivery hiccup must never fail an otherwise-good issue;
    # the certinel-deliver timer retries anything left 'pending'/'failed'.
    try:
        import deliver
        if deliver.mark_pending(job_id):
            deliver.deliver_one(job_id)
    except Exception as e:  # noqa: BLE001
        log_event("delivery", "hook_exception", job_id=job_id, error=str(e)[:128])

    return {"expires_at": expires_at, "warnings": warnings,
            "target_host": row["target_host"]}


def _cert_serial_colons(cert_pem):
    """The certificate serial as OpenBao-style colon-hex (lowercase), parsed
    from the stored PEM, e.g. '39:dd:2a:...'. None if unreadable. Used to revoke
    without storing the serial separately."""
    try:
        proc = subprocess.run(["openssl", "x509", "-noout", "-serial"],
                              input=cert_pem, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            return None
        raw = proc.stdout.strip().split("=", 1)[-1].strip().lower()
        if not raw:
            return None
        if len(raw) % 2:
            raw = "0" + raw
        return ":".join(raw[i:i + 2] for i in range(0, len(raw), 2))
    except Exception:
        return None


def _coerce_template_id(value):
    """Validate an optional template id from a request body: an int that
    references an existing template, else None (the request just won't carry a
    per-template signing policy)."""
    if value is None:
        return None
    try:
        tid = int(value)
    except (TypeError, ValueError):
        return None
    with db() as conn:
        if conn.execute("SELECT 1 FROM cert_templates WHERE id = ?", (tid,)).fetchone():
            return tid
    return None


def resolve_signing_policy(template_id=None):
    """Effective signing policy for a job: the job's template overrides the
    global default WHEN it opts into a backend. A template left at the default
    'manual' inherits the global signing-config; a template explicitly set to
    'openbao' uses its own role/ttl/auto_sign. Returns a dict the sign route
    feeds to sign.sign_csr (plus the auto_sign flag)."""
    if template_id:
        with db() as conn:
            t = conn.execute(
                "SELECT signer_backend, openbao_role, max_ttl, auto_sign "
                "FROM cert_templates WHERE id = ?", (template_id,)).fetchone()
        if t and (t["signer_backend"] or "manual") != "manual":
            return {
                "signer_backend": t["signer_backend"],
                "openbao_role": (t["openbao_role"] or "").strip()
                                or (get_setting("openbao_default_role") or "").strip() or None,
                "max_ttl": t["max_ttl"],
                "auto_sign": bool(t["auto_sign"]),
            }
    ttl = get_setting("signing_max_ttl")
    try:
        ttl = int(ttl) if ttl else None
    except (TypeError, ValueError):
        ttl = None
    return {
        "signer_backend": (get_setting("signing_default_backend") or "manual"),
        "openbao_role": (get_setting("openbao_default_role") or "").strip() or None,
        "max_ttl": ttl,
        "auto_sign": False,
    }


init_db()


def _startup_license_banner():
    """Log the license / edition / build posture once at startup.

    This is the cheap half of "tamper-evidence over tamper-proofing": a running
    instance announces, in the audit stream and on the console, exactly which
    customer it is licensed to (a watermark - a leaked license names its owner)
    and loudly flags an UNLICENSED deployment or an active dev-only override.
    Wrapped so a license problem can never stop the app from booting."""
    try:
        import build_mode
        import licensing
        info = licensing.info()
        rel = build_mode.is_release()
        boot = logging.getLogger("certinel.boot")
        if not boot.handlers:
            _bh = logging.StreamHandler()  # stderr -> journald/console
            _bh.setFormatter(logging.Formatter("certinel[%(process)d]: %(message)s"))
            boot.addHandler(_bh)
            boot.setLevel(logging.INFO)
            boot.propagate = False

        def emit(level, msg):
            boot.log(level, msg)
            try:                       # mirror to the tamper-evident audit stream
                audit.log(level, msg)
            except Exception:
                pass

        emit(logging.INFO, f"Certinel {APP_VERSION} starting - {build_mode.describe()} build")
        if info.get("valid"):
            cust = info.get("customer") or "(unnamed)"
            edition = (info.get("edition") or "commercial").capitalize()
            exp = info.get("expires")
            when = ("perpetual" if not exp
                    else time.strftime("%Y-%m-%d", time.gmtime(float(exp))))
            emit(logging.INFO, f"{edition} edition - licensed to {cust} (expires {when})")
            for w in info.get("warnings") or []:
                emit(logging.WARNING, f"LICENSE WARNING: {w}")
        else:
            import build_mode
            emit(logging.WARNING,
                 f"running UNLICENSED ({build_mode.EDITION.capitalize()} build) - "
                 f"premium features require a license [{info.get('reason')}]")
        # A release build must never honor the env backdoors; a dev build that
        # has them set is fine but should say so out loud.
        if not rel:
            for var in ("CSR_ENTITLEMENTS", "CSR_LICENSE_PUBKEY"):
                if os.environ.get(var):
                    emit(logging.WARNING,
                         f"DEV OVERRIDE ACTIVE: {var} is set and honored "
                         f"(development build) - it would be IGNORED in a release build")
    except Exception as e:  # never let licensing logging stop boot
        try:
            logging.getLogger("certinel.boot").warning(
                "license banner failed: %s", e)
        except Exception:
            pass


_startup_license_banner()

# --- Blueprints (incremental app.py split) ---
from routes_integrations import bp as integrations_bp  # noqa: E402
app.register_blueprint(integrations_bp)
from routes_feedback import bp as feedback_bp  # noqa: E402
app.register_blueprint(feedback_bp)
from routes_auth import bp as auth_bp  # noqa: E402
app.register_blueprint(auth_bp)
from routes_jobs import bp as jobs_bp  # noqa: E402
app.register_blueprint(jobs_bp)
from routes_requests import bp as requests_bp  # noqa: E402
app.register_blueprint(requests_bp)
from routes_groups import bp as groups_bp  # noqa: E402
app.register_blueprint(groups_bp)
from routes_me import bp as me_bp  # noqa: E402
app.register_blueprint(me_bp)
from routes_admin import bp as admin_bp  # noqa: E402
app.register_blueprint(admin_bp)
from routes_signing import bp as signing_bp  # noqa: E402
app.register_blueprint(signing_bp)
# Premium blueprints — present only in the Full build. The Community build omits
# the modules, so registration is best-effort; their routes simply don't exist
# (the UI grays the corresponding features out via the capability layer).
for _prem_mod, _prem_bp in (("routes_acme", "bp"), ("routes_deliver", "bp")):
    try:
        _m = __import__(_prem_mod)
        app.register_blueprint(getattr(_m, _prem_bp))
    except ImportError:
        pass
from routes_truststore import bp as truststore_bp  # noqa: E402
app.register_blueprint(truststore_bp)

# Background-pass entrypoints for the systemd timers, re-exported onto the `app`
# module so the units can call `app.run_expiry_warnings()` / `app.run_auto_renew()`.
# (run_expiry_warnings moved into routes_admin during the blueprint split; the
# timer still imports it from `app`, so this re-export keeps that unit working.)
from routes_admin import run_expiry_warnings  # noqa: E402,F401
try:                                    # premium: auto-renew is Full-build only
    from renew import run_auto_renew  # noqa: E402,F401
except ImportError:
    def run_auto_renew(*_a, **_k):
        """Stub in the Community build — automated renewal is a licensed feature.
        The systemd timer (if present) calls this and harmlessly no-ops."""
        log_event("renew", "skipped_community_build")
        return (0, 0, 0)
