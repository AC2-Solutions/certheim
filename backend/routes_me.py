"""routes_me blueprint - extracted from app.py (paths unchanged)."""
from flask import Blueprint, g, jsonify, request
from app import (  # noqa: E402
    APP_VERSION, _is_signer, _validate_email, db, log_event, require_auth, require_csrf)
bp = Blueprint("me", __name__)

# ============================================================
# Current-user profile (any authenticated user)
# ============================================================
@bp.get("/api/me")
@require_auth
def get_me():
    return jsonify({
        "dn":           g.user["dn"],
        "cn":           g.user["cn"],
        "username":     g.user["username"] if "username" in g.user.keys() else None,
        "email":        g.user["email"],
        "is_admin":     bool(g.user["is_admin"]),
        "is_active":    bool(g.user["is_active"]),
        "is_signer":    _is_signer(g.user["dn"]),
        "tutorial_dismissed": bool(g.user["tutorial_dismissed"]),
        "created_at":   g.user["created_at"],
        "last_seen_at": g.user["last_seen_at"],
        # how this request authenticated: "cac" | "local" | "none"
        "via":          (g.identity or {}).get("via", "none"),
        "version": APP_VERSION,
    })

@bp.put("/api/me/prefs")
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
