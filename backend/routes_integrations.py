"""routes_integrations.py - admin config + callbacks for outbound integrations.

Blueprint extracted from app.py (incremental split). Holds the route handlers
for webhooks (CRUD/test), Slack interactivity (config + signed callback), and
the capabilities readout. Shared helpers (the notification/format engine,
decorators, db, settings) stay in app.py and are imported here.
"""
from flask import Blueprint, request, jsonify, g
import json
import time
import urllib.parse

import capabilities
from app import (
    db, get_setting, set_setting, require_admin, require_csrf, log_event,
    _cn_from_dn, _format_webhook, _send_webhook_sync, _webhook_pool,
    _verify_slack_signature, _slack_assign_job,
    WEBHOOK_EVENTS, WEBHOOK_TYPES, HEADER_NAME_RE,
)

bp = Blueprint("integrations", __name__)


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


@bp.get("/api/admin/webhooks")
@require_admin
def admin_list_webhooks():
    with db() as conn:
        rows = conn.execute("""
            SELECT id, name, url, events, headers, enabled, type,
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
        d["type"] = d.get("type") or "generic"
        out.append(d)
    return jsonify(webhooks=out, available_events=list(WEBHOOK_EVENTS),
                   available_types=list(WEBHOOK_TYPES))


@bp.post("/api/admin/webhooks")
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

    wtype = (payload.get("type") or "generic").strip().lower()
    if wtype not in WEBHOOK_TYPES:
        return jsonify(error="invalid integration type"), 400

    enabled = bool(payload.get("enabled", True))

    with db() as conn:
        cur = conn.execute("""
            INSERT INTO webhooks (name, url, events, headers, enabled,
                                  created_at, created_by_dn, type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            name, url, json.dumps(events), json.dumps(headers) if headers else None,
            1 if enabled else 0, time.time(), g.identity["dn"], wtype,
        ))
        wid = cur.lastrowid

    log_event("admin_webhook_create", "ok", webhook_id=wid, name=name,
              events=",".join(events))
    return jsonify(ok=True, id=wid)


@bp.put("/api/admin/webhooks/<int:webhook_id>")
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

    if "type" in payload:
        wtype = (payload["type"] or "generic").strip().lower()
        if wtype not in WEBHOOK_TYPES:
            return jsonify(error="invalid integration type"), 400
        fields.append("type = ?"); params.append(wtype)

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


@bp.delete("/api/admin/webhooks/<int:webhook_id>")
@require_admin
@require_csrf
def admin_delete_webhook(webhook_id):
    with db() as conn:
        cur = conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        if cur.rowcount == 0:
            return jsonify(error="webhook not found"), 404
    log_event("admin_webhook_delete", "ok", webhook_id=webhook_id)
    return jsonify(ok=True)


@bp.post("/api/admin/webhooks/<int:webhook_id>/test")
@require_admin
@require_csrf
def admin_test_webhook(webhook_id):
    """Send a synchronous test payload and return the result inline."""
    with db() as conn:
        row = conn.execute(
            "SELECT name, url, headers, type FROM webhooks WHERE id = ?", (webhook_id,)
        ).fetchone()
    if not row:
        return jsonify(error="webhook not found"), 404

    try:
        headers = json.loads(row["headers"] or "{}") if row["headers"] else {}
    except (ValueError, TypeError):
        headers = {}

    wtype = (row["type"] if "type" in row.keys() else "generic") or "generic"
    payload = _format_webhook(wtype, "test", {
        "message": "This is a test from the Certinel admin panel.",
        "triggered_by": _cn_from_dn(g.identity["dn"]),
        "target_host": "example.test",
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
# Slack interactivity (assign jobs from a Slack message)
# ============================================================
@bp.get("/api/admin/slack-config")
@require_admin
def admin_get_slack_config():
    return jsonify(
        enabled=(get_setting("slack_interactive") == "1"),
        mode=get_setting("slack_interactive_mode") or "http",
        signing_secret_set=bool(get_setting("slack_signing_secret")),
        app_token_set=bool(get_setting("slack_app_token")),
        bot_token_set=bool(get_setting("slack_bot_token")),
        request_path="/csr/api/slack/interact",
    )


@bp.put("/api/admin/slack-config")
@require_admin
@require_csrf
def admin_put_slack_config():
    payload = request.get_json(silent=True) or {}
    if "enabled" in payload:
        set_setting("slack_interactive", "1" if payload["enabled"] else "0")
    if "mode" in payload:
        m = (payload["mode"] or "http").strip().lower()
        if m not in ("http", "socket"):
            return jsonify(error="mode must be 'http' or 'socket'"), 400
        set_setting("slack_interactive_mode", m)
    # secrets: blank or the mask placeholder keeps the stored value
    for key, setting in (("signing_secret", "slack_signing_secret"),
                         ("app_token", "slack_app_token"),
                         ("bot_token", "slack_bot_token")):
        if key in payload:
            s = (payload[key] or "").strip()
            if s and s != "********":
                set_setting(setting, s)
    log_event("admin_slack_config", "ok",
              mode=get_setting("slack_interactive_mode") or "http")
    return jsonify(ok=True)


@bp.get("/api/admin/capabilities")
@require_admin
def admin_capabilities():
    """What this deployment can do: per-capability availability + reason, plus
    the detected/declared environment. Drives the admin UI's show/disable/why."""
    return jsonify(capabilities=capabilities.all_status(),
                   environment=capabilities.env_caps())


@bp.post("/api/slack/interact")
def slack_interact():
    """Slack interactivity callback. Authenticated by the Slack request
    signature (NOT a user session), so it carries no auth/csrf decorators."""
    secret = get_setting("slack_signing_secret") or ""
    if get_setting("slack_interactive") != "1" \
            or (get_setting("slack_interactive_mode") or "http") != "http" \
            or not secret:
        return ("", 404)
    body = request.get_data(cache=True) or b""
    ts = request.headers.get("X-Slack-Request-Timestamp", "")
    sig = request.headers.get("X-Slack-Signature", "")
    if not _verify_slack_signature(body, ts, sig, secret):
        log_event("slack_interact", "deny_bad_signature")
        return ("invalid signature", 401)

    form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
    try:
        p = json.loads((form.get("payload") or [""])[0])
    except (ValueError, TypeError):
        return ("", 400)
    if p.get("type") != "block_actions":
        return ("", 200)

    actions = p.get("actions") or []
    act = actions[0] if actions else {}
    block_id = act.get("block_id", "") or ""
    job_id = block_id[4:] if block_id.startswith("job_") else None
    group_id = (act.get("selected_option") or {}).get("value")
    slack_user = ((p.get("user") or {}).get("username")
                  or (p.get("user") or {}).get("name") or "slack-user")
    response_url = p.get("response_url")

    if act.get("action_id") == "assign_group" and job_id and group_id:
        ok, msg = _slack_assign_job(job_id, group_id, slack_user)
        if response_url:
            # Confirm back in the channel (async; never block the 200 ack).
            try:
                _webhook_pool.submit(_send_webhook_sync, response_url,
                                     {"replace_original": False, "text": msg}, {})
            except RuntimeError:
                pass
    return ("", 200)


