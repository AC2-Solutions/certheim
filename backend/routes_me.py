"""routes_me blueprint - extracted from app.py (paths unchanged)."""
import json
from flask import Blueprint, g, jsonify, request
import licensing
from app import (  # noqa: E402
    APP_VERSION, _is_signer, _validate_email, db, get_setting, log_event,
    require_auth, require_csrf)
bp = Blueprint("me", __name__)

# ============================================================
# Current-user profile (any authenticated user)
# ============================================================
@bp.get("/api/me")
@require_auth
def get_me():
    is_admin = bool(g.user["is_admin"])
    # License-renewal reminder. Admins are warned earlier (60 days) so they can
    # act; regular users only inside 30 days. The UI further confines the 60-day
    # window to the Admin view (the main dashboard shows it only inside 30 days).
    notice = licensing.expiry_notice(60 if is_admin else 30)
    li = licensing.info()
    return jsonify({
        "dn":           g.user["dn"],
        "cn":           g.user["cn"],
        "username":     g.user["username"] if "username" in g.user.keys() else None,
        "email":        g.user["email"],
        "is_admin":     is_admin,
        "is_active":    bool(g.user["is_active"]),
        "is_signer":    _is_signer(g.user["dn"]),
        "tutorial_dismissed": bool(g.user["tutorial_dismissed"]),
        "created_at":   g.user["created_at"],
        "last_seen_at": g.user["last_seen_at"],
        # how this request authenticated: "cac" | "local" | "none"
        "via":          (g.identity or {}).get("via", "none"),
        "license_notice": notice,
        # Persistent edition watermark for the UI chrome. licensed_to is null on
        # the free Community baseline; a named customer means a valid license.
        "edition": li.get("edition") or "community",
        # What this ARTIFACT can actually run (the ceiling), vs. `edition` above
        # which is what the license grants. When a valid license outranks the
        # build, edition_mismatch carries the actionable upgrade message.
        "build_edition": li.get("build_edition") or "community",
        "edition_mismatch": li.get("edition_mismatch"),
        "licensed_to": li.get("customer") if li.get("valid") else None,
        "license_warnings": li.get("warnings") or [],
        "version": APP_VERSION,
        # Configured CSR subject domain, so the request form's help text + input
        # placeholders show the REAL suffix (e.g. myserver.ac2.lan) instead of a
        # hardcoded example.com. Empty until an admin configures the subject.
        "domain_suffix": get_setting("subject_domain_suffix") or "",
        # Selectable suffixes for the request form (primary + admin alternates).
        "domain_suffixes": _selectable_domain_suffixes(),
        # Named subject profiles the requester can choose between.
        "subject_profiles": _subject_profiles_public(),
    })


def _subject_profiles_public():
    try:
        profs = json.loads(get_setting("subject_profiles") or "[]")
    except (TypeError, ValueError):
        profs = []
    if not isinstance(profs, list):
        profs = []
    if not profs and get_setting("subject_configured") == "1":
        profs = [{"slug": "default", "name": "Default", "is_default": True}]
    return [{"slug": p.get("slug"), "name": p.get("name"),
             "is_default": bool(p.get("is_default"))}
            for p in profs if p.get("slug")]


def _selectable_domain_suffixes():
    primary = get_setting("subject_domain_suffix") or ""
    try:
        alts = json.loads(get_setting("subject_domain_suffixes") or "[]")
    except (TypeError, ValueError):
        alts = []
    out, seen = [], set()
    for d in [primary] + (alts if isinstance(alts, list) else []):
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out

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
