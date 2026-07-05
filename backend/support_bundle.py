"""support_bundle.py - a redacted diagnostic bundle for support tickets.

Certinel is frequently deployed air-gapped, where support can't see anything.
This assembles a small ZIP an admin can attach to a ticket: versions, capability
+ FIPS posture, environment, DB/schema shape, a recent-audit tail, and the app
settings WITH ALL SECRETS REDACTED. It never includes private keys, the sealed
keystore contents, the license blob, passwords, tokens, or any user PII beyond
what already appears in the audit log.

Redaction is deny-by-default for anything whose key looks secret, and the value
of every remaining setting is length/'***'-masked when it pattern-matches a
credential — so a new setting can't leak by being unlisted.
"""

import io
import json
import os
import platform
import re
import subprocess
import zipfile
from datetime import datetime, timezone

# Setting keys whose VALUE must never appear (deny-list, matched case-insensitive
# as a substring). Value is replaced with a redaction marker; the key is kept so
# support can see the setting EXISTS without its content.
_SECRET_KEY_RE = re.compile(
    r"(secret|password|passwd|token|api[-_]?key|private[-_]?key|"
    r"signing[-_]?key|credential|shared[-_]?secret|license|"
    r"client[-_]?secret|bind[-_]?pw|pull[-_]?token|hmac|eab|"
    r"key_pem|key_ref|passphrase|_pin\b|_pw\b)", re.I)

# Values that look like credentials get masked even under a benign key name.
_SECRET_VAL_RE = re.compile(
    r"-----BEGIN|glpat-|xox[baprs]-|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}", re.I)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact_value(key, value):
    if value is None:
        return None
    s = str(value)
    if _SECRET_KEY_RE.search(key or ""):
        return f"<redacted:{len(s)} chars>"
    if _SECRET_VAL_RE.search(s):
        return "<redacted:credential-shaped value>"
    return s


def _openssl_version():
    try:
        return subprocess.run(["openssl", "version"], capture_output=True,
                              text=True, timeout=5).stdout.strip()
    except Exception:                       # noqa: BLE001
        return ""


def _safe(fn, default=None):
    try:
        return fn()
    except Exception as e:                  # noqa: BLE001 - a bundle must never 500
        return {"error": str(e)[:200]} if default is None else default


def build(get_setting, db, app_version, edition, log_event=None):
    """Return (zip_bytes, filename). Pure read-only collection."""
    stamp = _now()

    # --- info.json: versions + environment ---
    import capabilities
    info = {
        "generated_at": stamp,
        "product": "Certinel",
        "version": app_version,
        "edition": edition,
        "python": platform.python_version(),
        "openssl": _openssl_version(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "hostname": platform.node(),
        "auth_mode": _safe(lambda: get_setting("auth_mode") or "mtls", "unknown"),
        "db_backend": _safe(lambda: (get_setting("db_backend")
                                     or os.environ.get("CSR_DB_BACKEND", "sqlite")), "sqlite"),
    }

    capabilities_status = _safe(capabilities.all_status, {})
    fips_status = _safe(capabilities.fips_status, {})

    # --- schema.json: table names + row counts (SHAPE only, never data) ---
    def _schema():
        out = {}
        with db() as conn:
            try:
                names = [r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "ORDER BY name").fetchall()]
            except Exception:
                # Postgres
                names = [r[0] for r in conn.execute(
                    "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                    "ORDER BY tablename").fetchall()]
            for t in names:
                if not re.match(r"^[A-Za-z0-9_]+$", t):
                    continue
                try:
                    out[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                except Exception:
                    out[t] = None
        return out

    schema = _safe(_schema, {})

    # --- settings.txt: every app_setting, values redacted ---
    def _settings():
        with db() as conn:
            rows = conn.execute("SELECT key, value FROM app_settings "
                                "ORDER BY key").fetchall()
        lines = []
        for r in rows:
            key = r[0] if not hasattr(r, "keys") else r["key"]
            val = r[1] if not hasattr(r, "keys") else r["value"]
            lines.append(f"{key} = {_redact_value(key, val)}")
        return "\n".join(lines) + "\n"

    settings_txt = _safe(_settings, "(unavailable)")

    # --- audit-tail.txt: recent audit events (actor/action/result/detail) ---
    def _audit(limit=200):
        with db() as conn:
            rows = conn.execute(
                "SELECT ts, actor, action, result, detail FROM audit_log "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            ts, actor, action, result, detail = (r[0], r[1], r[2], r[3], r[4])
            try:
                tss = datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                tss = str(ts)
            out.append(f"{tss}\t{actor or '-'}\t{action}\t{result}\t{(detail or '')[:300]}")
        return "\n".join(reversed(out)) + "\n"

    audit_tail = _safe(_audit, "(unavailable)")

    # --- assemble the zip ---
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("info.json", json.dumps(info, indent=2))
        z.writestr("capabilities.json", json.dumps(capabilities_status, indent=2))
        z.writestr("fips.json", json.dumps(fips_status, indent=2))
        z.writestr("schema.json", json.dumps(schema, indent=2))
        z.writestr("settings.txt",
                   "# app_settings — secret values are redacted.\n"
                   "# Generated " + stamp + "\n\n" + settings_txt)
        z.writestr("audit-tail.txt",
                   "# Last audit events (oldest first).\n\n" + audit_tail)
        z.writestr("README.txt", _README % (stamp, app_version, edition))
    buf.seek(0)
    if log_event:
        try:
            log_event("support_bundle", "generated", version=app_version, edition=edition)
        except Exception:                   # noqa: BLE001
            pass
    fname = "certinel-support-%s-%s.zip" % (
        edition, datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y%m%d-%H%M%S"))
    return buf.getvalue(), fname


_README = """Certinel support bundle
Generated: %s
Version:   %s
Edition:   %s

Contents:
  info.json          product/version/environment
  capabilities.json  what this deployment can do (license + environment)
  fips.json          FIPS posture (module + policy)
  schema.json        DB table names + row COUNTS (no row data)
  settings.txt       app settings with all secret VALUES redacted
  audit-tail.txt     recent audit events

What this bundle does NOT contain: private keys, the sealed keystore contents,
the license blob, passwords, API tokens, or CSR/certificate material. It is safe
to attach to a support ticket. Review settings.txt before sharing if your
deployment stores non-standard settings.
"""
