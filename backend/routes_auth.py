"""routes_auth blueprint - extracted from app.py (paths unchanged)."""
import db as dbx
from flask import Blueprint, g, jsonify, request, session
import sqlite3, string, time
import capabilities

# CAC / client-cert mTLS is a licensed capability (Government edition, or a
# Commercial add-on entitlement). Enabling it - the app's mtls auth mode or the
# nginx client-cert verification - requires that entitlement.
_CAC_LICENSED_ERR = ("CAC / mTLS is a licensed feature - it requires a "
                     "Government license or the CAC add-on. Apply a license "
                     "in Admin -> License, then enable it here.")
from app import (  # noqa: E402
    APP_VERSION, BOOTSTRAP_FIRST_ADMIN, DOMAIN_RE, EMAIL_RE, LOCAL_SESSION_COOKIE, LOCAL_SESSION_TTL, LOCKOUT_SECONDS, LOCKOUT_THRESHOLD, LOGIN_BANNERS, NAME_RE, _get_or_create_session, _normalize_name_part, _sessions, _sessions_lock, _set_session_cookie, _upsert_user, auth_mode, banner_options, create_local_session, current_banner, db, derive_username, destroy_local_session, get_setting, hash_password, log_event, parse_trusted_domains, password_policy_errors, require_admin, require_auth, require_csrf, set_setting, verify_password)
bp = Blueprint("auth", __name__)

# ============================================================
# Misc
# ============================================================
@bp.get("/api/health")
def health():
    return jsonify(ok=True, version=APP_VERSION)

# ---------------------------------------------------------------------------
# Local authentication endpoints (only meaningful when auth_mode == "local";
# they remain available as a CAC fallback even after mtls is enabled).
# ---------------------------------------------------------------------------
@bp.get("/api/auth/info")
def auth_info():
    """Unauthenticated: tells the UI which auth mode is active and whether
    self-registration is open, so it can show the right login/register UI."""
    mode = auth_mode()
    domains = parse_trusted_domains(get_setting("trusted_email_domain"))
    banner = current_banner()
    return jsonify(
        auth_mode=mode,
        local_enabled=(mode == "local"),
        # Self-registration is its own toggle now, independent of the (optional)
        # email-domain filter - a domain is "not always going to be a thing".
        registration_open=(mode == "local"
                           and get_setting("allow_registration") == "1"),
        # `trusted_email_domain` (joined string) kept for backward compat;
        # `trusted_email_domains` is the canonical list the UI should use.
        trusted_email_domain=", ".join(domains),
        trusted_email_domains=domains,
        require_admin_approval=(get_setting("require_admin_approval") == "1"),
        banner=banner,
        require_agreement=bool(banner),
    )

@bp.post("/api/auth/login")
def auth_login():
    """Local username/password login. Always available as a fallback, but the
    UI only surfaces it in local mode. Applies failed-attempt lockout."""
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    if auth_mode() == "mtls":
        return jsonify(error="this host uses CAC authentication"), 403
    if not username or not password:
        return jsonify(error="username and password required"), 400

    now = time.time()
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    # Uniform failure response (don't reveal whether the username exists).
    generic = (jsonify(error="invalid credentials"), 401)
    if not row or not row["password_hash"]:
        log_event("login", "deny_unknown_user", username=username[:64])
        return generic

    user = dict(row)
    if user.get("locked_until", 0) > now:
        log_event("login", "deny_locked", username=username[:64])
        return jsonify(error="account temporarily locked - try again later"), 429
    if user.get("auth_status") == "pending":
        return jsonify(error="account awaiting administrator approval"), 403
    if not user.get("is_active"):
        return jsonify(error="account disabled"), 403

    if not verify_password(password, user["password_hash"]):
        attempts = int(user.get("failed_attempts", 0)) + 1
        lock_until = now + LOCKOUT_SECONDS if attempts >= LOCKOUT_THRESHOLD else 0
        with db() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE dn = ?",
                (attempts, lock_until, user["dn"]))
        log_event("login", "deny_badpass", username=username[:64],
                  attempts=attempts, locked=int(bool(lock_until)))
        return generic

    # success - reset counters, issue session
    with db() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0, last_seen_at = ? "
            "WHERE dn = ?", (now, user["dn"]))
    token = create_local_session(user["dn"])
    log_event("login", "ok", username=username[:64])
    resp = jsonify(ok=True)
    resp.set_cookie(LOCAL_SESSION_COOKIE, token, httponly=True, secure=True,
                    samesite="Strict", max_age=LOCAL_SESSION_TTL)
    return resp

@bp.post("/api/auth/logout")
def auth_logout():
    token = request.cookies.get(LOCAL_SESSION_COOKIE, "")
    destroy_local_session(token)
    resp = jsonify(ok=True)
    resp.delete_cookie(LOCAL_SESSION_COOKIE)
    return resp

@bp.post("/api/auth/register")
def auth_register():
    """Self-registration in local mode, gated by trusted email domain and
    (optionally) admin approval. Disabled entirely in mtls mode.

    Usernames are NOT user-chosen: they are derived as first.last and
    auto-suffixed on collision (john.smith, john.smith2, ...). The assigned
    username is returned to the caller for display."""
    if auth_mode() != "local":
        return jsonify(error="registration not available"), 403
    if get_setting("allow_registration") != "1":
        return jsonify(error="self-registration is disabled"), 403
    # Optional email-domain filter (empty = any valid email may register;
    # one OR MORE trusted domains may be configured).
    domains = parse_trusted_domains(get_setting("trusted_email_domain"))

    payload = request.get_json(silent=True) or {}
    first = (payload.get("first_name") or "").strip()
    last = (payload.get("last_name") or "").strip()
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""

    if not NAME_RE.match(first) or not NAME_RE.match(last):
        return jsonify(error="enter a valid first and last name"), 400
    # must reduce to something usable
    if not _normalize_name_part(first) or not _normalize_name_part(last):
        return jsonify(error="name must contain letters"), 400
    if not EMAIL_RE.match(email):
        return jsonify(error="valid email required"), 400
    # Trusted-domain enforcement (case-insensitive, exact domain match) - only
    # when an admin configured domain(s); otherwise any valid email is allowed.
    if domains and email.rsplit("@", 1)[-1] not in domains:
        log_event("register", "deny_domain", email=email[:128])
        allowed = ", ".join("@" + d for d in domains)
        return jsonify(error=f"email must be at one of: {allowed}"), 403
    pol = password_policy_errors(password)
    if pol:
        return jsonify(error="password needs " + ", ".join(pol)), 400

    now = time.time()
    approval = get_setting("require_admin_approval") == "1"
    display = f"{first} {last}".strip()[:128]

    # Derive username + insert atomically, retrying on the (rare) race where
    # two registrations pick the same suffix between derive and insert. The
    # UNIQUE index on username is the hard guard; we retry a few times.
    pwhash = hash_password(password)
    last_err = None
    for _ in range(5):
        with db() as conn:
            # First-admin bootstrap (local mode): when enabled and this is the
            # very first account on an empty database, the registrant becomes an
            # active admin - so a fresh password-only box has an administrator
            # without a manual certinel-bootstrap-admin step. Self-disabling (fires
            # only while users is empty); mirrors the CAC path in _upsert_user.
            if BOOTSTRAP_FIRST_ADMIN and conn.execute(
                    "SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0:
                is_admin, active, status = 1, 1, "active"
            else:
                is_admin = 0
                active = 0 if approval else 1
                status = "pending" if approval else "active"
            username = derive_username(first, last, conn)
            dn = f"local:{username}"
            try:
                # Persist first/last (Model A): the username is derived from
                # them, and the admin edit modal shows/edits them - so store
                # them, not just the combined display cn.
                conn.execute("""
                    INSERT INTO users (dn, cn, email, username, password_hash,
                                       first_name, last_name,
                                       is_admin, is_active, auth_status,
                                       created_at, last_seen_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (dn, display, email, username, pwhash,
                      first or None, last or None,
                      is_admin, active, status, now, now))
                break
            except dbx.IntegrityError as e:
                last_err = e
                continue  # collision between derive and insert; retry
    else:
        log_event("register", "error_collision", email=email[:128])
        return jsonify(error="could not assign a username, please retry"), 503

    log_event("register", "ok", username=username[:64], status=status)
    if status == "pending":
        return jsonify(ok=True, status="pending", username=username,
                       message=f"Account created as '{username}' - "
                               f"awaiting administrator approval.")
    token = create_local_session(dn)
    resp = jsonify(ok=True, status="active", username=username,
                   message=f"Your username is '{username}'.")
    resp.set_cookie(LOCAL_SESSION_COOKIE, token, httponly=True, secure=True,
                    samesite="Strict", max_age=LOCAL_SESSION_TTL)
    return resp

# --- admin: auth settings ---------------------------------------------------
@bp.get("/api/admin/auth-settings")
@require_admin
def admin_get_auth_settings():
    domains = parse_trusted_domains(get_setting("trusted_email_domain"))
    return jsonify(
        auth_mode=auth_mode(),
        trusted_email_domain=", ".join(domains),   # back-compat display string
        trusted_email_domains=domains,             # canonical list
        require_admin_approval=(get_setting("require_admin_approval") == "1"),
        allow_registration=(get_setting("allow_registration") == "1"),
        login_banner=get_setting("login_banner") or "none",
        login_banner_custom_title=get_setting("login_banner_custom_title") or "",
        login_banner_custom_text=get_setting("login_banner_custom_text") or "",
        banner_options=banner_options(),
        # nginx client-cert (mTLS) verification - app-managed via the helper.
        mtls_mode=get_setting("mtls_mode") or "off",
        mtls_ca_bundle_path=get_setting("mtls_ca_bundle_path") or "",
        mtls_modes=["off", "optional", "enforce"],
    )

@bp.put("/api/admin/auth-settings")
@require_admin
@require_csrf
def admin_set_auth_settings():
    payload = request.get_json(silent=True) or {}
    changed = {}
    if "auth_mode" in payload:
        mode = payload["auth_mode"]
        if mode not in ("mtls", "local"):
            return jsonify(error="auth_mode must be 'mtls' or 'local'"), 400
        # Guard: don't switch to mtls unless at least one CAC-capable admin
        # exists, or the operator could lock everyone out. We can't verify a
        # cert here, so require explicit confirm flag for the mtls switch.
        if mode == "mtls" and not capabilities.available("auth.cac"):
            return jsonify(error=_CAC_LICENSED_ERR), 403
        if mode == "mtls" and not payload.get("confirm_mtls"):
            return jsonify(error="enabling mTLS requires confirm_mtls=true; "
                                 "ensure CAC access works first"), 400
        set_setting("auth_mode", mode); changed["auth_mode"] = mode
    if "mtls_mode" in payload:
        # App-managed nginx client-cert verification. Store the choice and apply
        # it to nginx via the helper (best-effort: the setting is the source of
        # truth; a failed apply is reported, not fatal, so the save still lands).
        mmode = (payload.get("mtls_mode") or "off").strip()
        if mmode not in ("off", "optional", "enforce"):
            return jsonify(error="mtls_mode must be off|optional|enforce"), 400
        if not capabilities.available("auth.cac"):
            # Unlicensed: mTLS can't be enabled. Only reject an ACTIVE enable
            # (a real change to optional/enforce); a save that merely echoes a
            # stale value - e.g. editing trusted domains - is coerced to off so
            # it still lands instead of 403ing. Also self-heals boxes seeded
            # with mtls_mode=optional by older installers.
            cur = get_setting("mtls_mode") or "off"
            if mmode in ("optional", "enforce") and mmode != cur:
                return jsonify(error=_CAC_LICENSED_ERR), 403
            mmode = "off"
        mpath = (payload.get("mtls_ca_bundle_path") or "").strip()
        if mmode == "enforce":
            ok_path = (mpath.startswith("/") and
                       all(c.isalnum() or c in "._/-" for c in mpath))
            if not ok_path:
                return jsonify(error="enforce mode needs a valid absolute "
                                     "client-CA bundle path"), 400
        set_setting("mtls_mode", mmode)
        set_setting("mtls_ca_bundle_path", mpath)
        changed["mtls_mode"] = mmode
        from app import run_helper, CONTAINER_MODE
        if CONTAINER_MODE:
            # In a container, TLS + client-cert verification is terminated at the
            # ingress (which passes X-Client-* headers the app already reads).
            # There's no in-pod nginx to rewrite, so the setting is recorded for
            # the UI but the operator configures mTLS on the ingress.
            changed["mtls_applied"] = True
            changed["mtls_managed_by"] = "ingress"
        else:
            try:
                rc, out, err = run_helper(["apply-mtls", mmode, mpath])
            except Exception as e:  # helper/sudo absent (e.g. CI) - never 500
                rc, out, err = 1, "", str(e)
            changed["mtls_applied"] = (rc == 0)
            if rc != 0:
                changed["mtls_apply_error"] = (err or out or "").strip()[:240]
    if "trusted_email_domains" in payload or "trusted_email_domain" in payload:
        # Accept either a list (canonical) or a string that may itself hold
        # several domains (comma/space/semicolon separated). Validate each;
        # store comma-joined in the single back-compat setting key.
        raw = payload.get("trusted_email_domains")
        raw = ",".join(str(x) for x in raw) if isinstance(raw, list) \
            else (payload.get("trusted_email_domain") or "")
        domains = parse_trusted_domains(raw)
        bad = [d for d in domains if not DOMAIN_RE.match(d)]
        if bad:
            return jsonify(error="invalid domain(s): " + ", ".join(bad)), 400
        joined = ",".join(domains)
        set_setting("trusted_email_domain", joined)
        changed["trusted_email_domain"] = joined
    if "require_admin_approval" in payload:
        val = "1" if payload["require_admin_approval"] else "0"
        set_setting("require_admin_approval", val)
        changed["require_admin_approval"] = val
    if "allow_registration" in payload:
        val = "1" if payload["allow_registration"] else "0"
        set_setting("allow_registration", val)
        changed["allow_registration"] = val
    if "login_banner" in payload:
        b = (payload["login_banner"] or "none").strip().lower()
        if b not in ("none", "custom") and b not in LOGIN_BANNERS:
            return jsonify(error="invalid login_banner"), 400
        set_setting("login_banner", b)
        changed["login_banner"] = b
    if "login_banner_custom_title" in payload:
        t = (payload["login_banner_custom_title"] or "").strip()[:120]
        set_setting("login_banner_custom_title", t)
        changed["login_banner_custom_title"] = t
    if "login_banner_custom_text" in payload:
        txt = payload["login_banner_custom_text"]
        if txt is not None and not isinstance(txt, str):
            return jsonify(error="login_banner_custom_text must be string"), 400
        txt = (txt or "")[:8000]
        set_setting("login_banner_custom_text", txt)
        changed["login_banner_custom_text"] = "set" if txt else "(empty)"
    log_event("admin_auth_settings", "ok", **{k: str(v)[:64] for k, v in changed.items()})
    return jsonify(ok=True, **changed)

@bp.post("/api/admin/users/<path:user_dn>/approve")
@require_admin
@require_csrf
def admin_approve_user(user_dn):
    """Approve a pending local registration."""
    with db() as conn:
        row = conn.execute(
            "SELECT auth_status FROM users WHERE dn = ?", (user_dn,)).fetchone()
        if not row:
            return jsonify(error="user not found"), 404
        conn.execute(
            "UPDATE users SET auth_status = 'active', is_active = 1 WHERE dn = ?",
            (user_dn,))
    log_event("admin_user_approve", "ok", target_dn=user_dn[:128])
    return jsonify(ok=True)

@bp.get("/api/whoami")
@require_auth
def whoami():
    log_event("whoami", "ok")
    return jsonify(dn=g.identity["dn"])

@bp.get("/api/session")
@require_auth
def session_info():
    sid, is_new = _get_or_create_session()
    log_event("session", "created" if is_new else "renewed")
    return _set_session_cookie(jsonify(ok=True), sid)

@bp.post("/api/session/end")
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

