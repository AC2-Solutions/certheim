"""routes_admin blueprint - extracted from app.py (paths unchanged)."""
from flask import Blueprint, abort, g, jsonify, request, session
import json, re, string, time, uuid
import capabilities
import notify
from app import (  # noqa: E402
    DB_PATH, EMAIL_RE, GROUP_NAME_RE, ISSUED_DIR, JOB_ID_RE, KEY_NAME_RE, _cn_from_dn, _group_by_id, _group_email, _group_owner_emails, _group_role, _normalize_cert_types, _normalize_name_part, _parse_helper_listing, _signer_recipients, _user_group_ids, _user_groups, _validate_email, audit, db, derive_username, fire_webhooks, hash_password, log_event, password_policy_errors, require_admin, require_auth, require_csrf, run_helper)
bp = Blueprint("admin", __name__)

# ============================================================
# Admin: users
# ============================================================
@bp.get("/api/admin/users")
@require_admin
def admin_list_users():
    with db() as conn:
        rows = conn.execute("""
            SELECT dn, cn, email, is_admin, is_active, username, auth_status,
                   first_name, last_name,
                   created_at, last_seen_at, notes
              FROM users
             ORDER BY last_seen_at DESC
        """).fetchall()
    log_event("admin_list_users", "ok", count=len(rows))
    return jsonify(users=[{
        "dn": r["dn"], "cn": r["cn"], "email": r["email"],
        "is_admin": bool(r["is_admin"]), "is_active": bool(r["is_active"]),
        "username": r["username"], "auth_status": r["auth_status"],
        "first_name": r["first_name"], "last_name": r["last_name"],
        "created_at": r["created_at"], "last_seen_at": r["last_seen_at"],
        "notes": r["notes"],
    } for r in rows])

@bp.put("/api/admin/users")
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

    # First/last name edits regenerate the unified username (first.last). This
    # is the admin correction path - e.g. fixing an auto-parsed CAC name, or
    # backfilling names for an existing user so they get a proper username.
    regen_username = False
    new_first = new_last = None
    if "first_name" in payload:
        new_first = (payload["first_name"] or "").strip()[:64]
        fields["first_name"] = new_first or None
        regen_username = True
    if "last_name" in payload:
        new_last = (payload["last_name"] or "").strip()[:64]
        fields["last_name"] = new_last or None
        regen_username = True

    if not fields:
        return jsonify(error="no fields to update"), 400

    with db() as conn:
        # If names changed, compute the new username inside this transaction so
        # the collision check + update are atomic.
        if regen_username:
            row = conn.execute(
                "SELECT first_name, last_name, username FROM users WHERE dn = ?",
                (target_dn,)).fetchone()
            if not row:
                return jsonify(error="user not found"), 404
            eff_first = new_first if new_first is not None else (row["first_name"] or "")
            eff_last = new_last if new_last is not None else (row["last_name"] or "")
            if _normalize_name_part(eff_first) or _normalize_name_part(eff_last):
                cur_username = row["username"]
                # If the names still reduce to the user's existing base, keep
                # their current username (don't bump the suffix on re-save).
                base = ".".join(p for p in (_normalize_name_part(eff_first),
                                            _normalize_name_part(eff_last)) if p)
                if cur_username and (cur_username == base or
                        re.match(r"^" + re.escape(base) + r"\d*$", cur_username or "")):
                    pass  # already a valid first.last[N] for these names; keep it
                else:
                    candidate = derive_username(eff_first, eff_last, conn)
                    fields["username"] = candidate

        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [target_dn]
        cur = conn.execute(
            f"UPDATE users SET {set_clause} WHERE dn = ?", values
        )
        if cur.rowcount == 0:
            return jsonify(error="user not found"), 404

    log_event("admin_user_update", "ok",
              target_dn=target_dn[:128],
              fields=",".join(fields.keys()))
    return jsonify(ok=True, username=fields.get("username"))

@bp.post("/api/admin/users/set-password")
@require_admin
@require_csrf
def admin_set_password():
    """Admin sets or resets a user's password. Works for any user (CAC or
    local); giving a CAC user a password enables the password fallback for
    them. The user needs a username - if they don't have one yet, the admin
    should set first/last names first so a username is generated."""
    payload = request.get_json(silent=True) or {}
    target_dn = (payload.get("dn") or "").strip()
    password = payload.get("password") or ""
    if not target_dn:
        return jsonify(error="dn required"), 400
    pol = password_policy_errors(password)
    if pol:
        return jsonify(error="password needs " + ", ".join(pol)), 400
    with db() as conn:
        row = conn.execute(
            "SELECT username FROM users WHERE dn = ?", (target_dn,)).fetchone()
        if not row:
            return jsonify(error="user not found"), 404
        if not row["username"]:
            return jsonify(error="set the user's first/last name first so a "
                                 "username exists"), 400
        conn.execute(
            "UPDATE users SET password_hash = ?, failed_attempts = 0, "
            "locked_until = 0 WHERE dn = ?",
            (hash_password(password), target_dn))
    log_event("admin_set_password", "ok", target_dn=target_dn[:128])
    return jsonify(ok=True)

@bp.post("/api/admin/users")
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

@bp.delete("/api/admin/users")
@require_admin
@require_csrf
def admin_delete_user():
    """Delete a user. DN is in the request body (it contains URL-awkward
    characters). Removes the user's group memberships too. Their jobs and
    templates are historical records and are left intact (the requester_dn /
    owner_dn columns remain as an audit trail), unless ?purge=1 is given to
    also detach owned templates back to no-owner. Jobs are never deleted here -
    use job cleanup for that."""
    payload = request.get_json(silent=True) or {}
    target_dn = (payload.get("dn") or "").strip()
    if not target_dn or len(target_dn) > 512:
        return jsonify(error="invalid dn"), 400

    # You cannot delete yourself - prevents an admin locking themselves out
    # mid-session and orphaning the instance if they're the only admin.
    if target_dn == g.user["dn"]:
        return jsonify(error="cannot delete your own account"), 400

    with db() as conn:
        existing = conn.execute(
            "SELECT dn, is_admin FROM users WHERE dn = ?", (target_dn,)
        ).fetchone()
        if not existing:
            return jsonify(error="user not found"), 404

        # Don't allow deleting the last remaining admin - that would leave the
        # instance with no one who can administer it.
        if existing["is_admin"]:
            admin_count = conn.execute(
                "SELECT COUNT(*) AS n FROM users WHERE is_admin = 1"
            ).fetchone()["n"]
            if admin_count <= 1:
                return jsonify(error="cannot delete the last admin"), 400

        # Count what references this user, for the response summary.
        job_count = conn.execute(
            "SELECT COUNT(*) AS n FROM jobs WHERE requester_dn = ?", (target_dn,)
        ).fetchone()["n"]
        tmpl_count = conn.execute(
            "SELECT COUNT(*) AS n FROM cert_templates WHERE owner_dn = ?", (target_dn,)
        ).fetchone()["n"]

        # Remove group memberships (these are the user's own associations and
        # are safe to drop).
        conn.execute("DELETE FROM user_groups WHERE user_dn = ?", (target_dn,))

        # Optionally detach owned templates so they survive as instance/global
        # rather than pointing at a deleted owner.
        if payload.get("purge"):
            conn.execute(
                "UPDATE cert_templates SET owner_dn = NULL WHERE owner_dn = ?",
                (target_dn,),
            )

        conn.execute("DELETE FROM users WHERE dn = ?", (target_dn,))

    log_event("admin_user_delete", "ok",
              target_dn=target_dn[:128],
              jobs_retained=job_count, templates=tmpl_count)
    return jsonify(ok=True, jobs_retained=job_count, templates=tmpl_count)

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

@bp.delete("/api/admin/jobs/<job_id>")
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

@bp.post("/api/admin/jobs/bulk-delete")
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
@bp.get("/api/admin/orphans/keys")
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

@bp.delete("/api/admin/orphans/keys/<name>")
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

@bp.get("/api/admin/orphans/certs")
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

@bp.delete("/api/admin/orphans/certs/<name>")
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
@bp.get("/api/admin/stats")
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
@bp.get("/api/me/groups")
@require_auth
def get_my_groups():
    groups = _user_groups(g.identity["dn"])
    return jsonify(groups=groups)

# ============================================================
# Cert-type templates (personal + group scoped)
# ============================================================
@bp.get("/api/templates")
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


@bp.post("/api/templates")
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


@bp.put("/api/admin/templates/<int:template_id>/signing")
@require_admin
@require_csrf
def admin_set_template_signing(template_id):
    """Set a template's signing policy (admin only - it controls CA issuance).
    signer_backend 'manual' inherits the global signing default; 'openbao' uses
    this template's role/ttl and optional auto_sign (issue on request, no human
    approval)."""
    payload = request.get_json(silent=True) or {}
    backend = (payload.get("signer_backend") or "manual").strip()
    if backend not in ("manual", "openbao"):
        return jsonify(error="signer_backend must be 'manual' or 'openbao'"), 400
    role = (payload.get("openbao_role") or "").strip() or None
    ttl = payload.get("max_ttl")
    if ttl in (None, ""):
        ttl = None
    else:
        try:
            ttl = int(ttl)
            if ttl <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify(error="max_ttl must be a positive integer (seconds)"), 400
    auto_sign = 1 if payload.get("auto_sign") else 0
    with db() as conn:
        if not conn.execute("SELECT 1 FROM cert_templates WHERE id = ?",
                            (template_id,)).fetchone():
            return jsonify(error="template not found"), 404
        conn.execute(
            "UPDATE cert_templates SET signer_backend = ?, openbao_role = ?, "
            "max_ttl = ?, auto_sign = ? WHERE id = ?",
            (backend, role, ttl, auto_sign, template_id))
    log_event("template_signing", "update", template_id=template_id,
              backend=backend, auto_sign=auto_sign, actor=g.identity["dn"][:128])
    return jsonify(ok=True, template_id=template_id, signer_backend=backend,
                   openbao_role=role, max_ttl=ttl, auto_sign=bool(auto_sign))


@bp.delete("/api/templates/<int:template_id>")
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


@bp.delete("/api/admin/templates/<int:template_id>")
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


@bp.post("/api/admin/run-expiry-warnings")
@require_admin
@require_csrf
def admin_run_expiry_warnings():
    sent, errors = run_expiry_warnings()
    log_event("expiry_warnings", "ok", sent=sent, errors=errors)
    return jsonify(ok=True, sent=sent, errors=errors)


# ============================================================
# Admin: audit log viewer
# ============================================================
@bp.get("/api/admin/audit")
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
@bp.get("/api/fleet-certs")
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


@bp.delete("/api/fleet-certs/<int:cert_id>")
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
@bp.get("/api/admin/email-config")
@require_admin
def admin_get_email_config():
    return jsonify(notify.get_settings())


@bp.put("/api/admin/email-config")
@require_admin
@require_csrf
def admin_put_email_config():
    payload = request.get_json(silent=True) or {}

    method = (payload.get("method") or "smg").strip().lower()
    if method != "none" and method not in notify.EMAIL_METHODS:
        return jsonify(error="unknown email method"), 400
    fields = payload.get("fields") or {}
    if not isinstance(fields, dict):
        return jsonify(error="fields must be an object"), 400
    from_address = (payload.get("from_address") or "").strip()
    dashboard_url = (payload.get("dashboard_url") or "").strip()
    cc = (payload.get("cc") or "").strip()

    # "none" disables email entirely - skip the delivery-field validation.
    if method == "none":
        ok, reason = notify.save_settings({
            "method": "none", "fields": {},
            "from_address": from_address, "cc": cc, "dashboard_url": dashboard_url,
        })
        if not ok:
            return jsonify(error=reason), 500
        log_event("admin_email_config", "ok", method="none")
        return jsonify(ok=True, reason=reason, **notify.get_settings())

    # Common validation.
    if from_address:
        ok_e, from_address, err_e = _validate_email(from_address)
        if not ok_e or not from_address:
            return jsonify(error=f"invalid from address: {err_e or 'required'}"), 400
    else:
        return jsonify(error="from address is required"), 400
    if cc:
        for addr in [a.strip() for a in cc.split(",") if a.strip()]:
            if not EMAIL_RE.match(addr):
                return jsonify(error=f"invalid cc address: {addr}"), 400
    if dashboard_url and not dashboard_url.startswith("https://"):
        return jsonify(error="dashboard_url must start with https://"), 400

    # Method-specific shape checks (notify reports "disabled" if a required
    # connection field is missing, but catch the obvious ones here).
    for k in ("port", "timeout"):
        v = fields.get(k)
        if v not in (None, ""):
            try:
                iv = int(v)
            except (TypeError, ValueError):
                return jsonify(error=f"{k} must be an integer"), 400
            if k == "port" and not (1 <= iv <= 65535):
                return jsonify(error="port out of range"), 400
            if k == "timeout" and not (1 <= iv <= 120):
                return jsonify(error="timeout out of range (1-120s)"), 400
    if method in ("mailgun", "sendgrid") \
            and not capabilities.available("notify.email.api"):
        return jsonify(error="HTTP email providers (Mailgun/SendGrid) are not "
                             "available in this deployment (no outbound "
                             "internet). Use an SMTP/SMG relay instead."), 400
    if method in ("smg", "smtp"):
        host = (fields.get("host") or "").strip()
        if not host or not re.match(r"^[A-Za-z0-9._-]+$", host):
            return jsonify(error="host is required (hostname or IP)"), 400
    if method == "mailgun":
        dom = (fields.get("domain") or "").strip()
        if not dom or not re.match(r"^[A-Za-z0-9.-]+$", dom):
            return jsonify(error="mailgun sending domain is required"), 400

    ok, reason = notify.save_settings({
        "method": method, "fields": fields,
        "from_address": from_address, "cc": cc, "dashboard_url": dashboard_url,
    })
    if not ok:
        log_event("admin_email_config", "error", reason=reason[:128])
        return jsonify(error=reason), 500

    log_event("admin_email_config", "ok", method=method)
    return jsonify(ok=True, reason=reason, **notify.get_settings())


# ============================================================
# Admin: groups CRUD
# ============================================================
@bp.get("/api/admin/groups")
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

@bp.post("/api/admin/groups")
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

@bp.put("/api/admin/groups/<int:group_id>")
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

@bp.delete("/api/admin/groups/<int:group_id>")
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

@bp.get("/api/admin/groups/<int:group_id>/members")
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

@bp.post("/api/admin/groups/<int:group_id>/members")
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

@bp.delete("/api/admin/groups/<int:group_id>/members")
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

@bp.post("/api/admin/test-email")
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
