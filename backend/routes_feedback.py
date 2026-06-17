"""routes_feedback.py - user feedback submit + admin triage.

Blueprint extracted from app.py (incremental split).
"""
from flask import Blueprint, request, jsonify, g
import time

import notify
from app import (
    db, require_auth, require_admin, require_csrf, log_event,
    _cn_from_dn, fire_webhooks,
)

bp = Blueprint("feedback", __name__)


# ============================================================
# Feedback
# ============================================================
FEEDBACK_CATEGORIES = ("bug", "feature", "general")


@bp.post("/api/feedback")
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


@bp.get("/api/admin/feedback")
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


@bp.put("/api/admin/feedback/<int:feedback_id>")
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


@bp.delete("/api/admin/feedback/<int:feedback_id>")
@require_admin
@require_csrf
def admin_delete_feedback(feedback_id):
    with db() as conn:
        cur = conn.execute("DELETE FROM feedback WHERE id = ?", (feedback_id,))
        if cur.rowcount == 0:
            return jsonify(error="feedback not found"), 404
    log_event("admin_feedback_delete", "ok", feedback_id=feedback_id)
    return jsonify(ok=True)
