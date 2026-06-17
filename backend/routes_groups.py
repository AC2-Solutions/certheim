"""routes_groups blueprint - extracted from app.py (paths unchanged)."""
from flask import Blueprint, g, jsonify, request
import time
from app import (  # noqa: E402
    EMAIL_RE, _cn_from_dn, _group_by_id, _group_role, _is_group_owner_or_admin, db, log_event, require_admin, require_auth, require_csrf)
bp = Blueprint("groups", __name__)

@bp.put("/api/admin/groups/<int:group_id>/members/role")
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

@bp.get("/api/my-groups")
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

@bp.post("/api/groups/<int:group_id>/members")
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

@bp.delete("/api/groups/<int:group_id>/members")
@require_auth
@require_csrf
def group_owner_remove_member(group_id):
    """Removal rules:
      - Anyone can remove THEMSELVES (leave the group) - except the last owner,
        who must hand off ownership first so the group isn't left ownerless.
      - Owners (and admins) can remove OTHER members, but not other owners
        (an admin demotes/removes an owner).
      - Plain members cannot remove anyone but themselves."""
    me = g.identity["dn"]
    if not _group_by_id(group_id):
        return jsonify(error="group not found"), 404
    payload = request.get_json(silent=True) or {}
    dn = (payload.get("dn") or "").strip()
    if not dn:
        return jsonify(error="dn required"), 400

    is_admin = bool(g.user and g.user.get("is_admin"))
    is_self = (dn == me)
    my_role = _group_role(me, group_id)
    target_role = _group_role(dn, group_id)
    if target_role is None:
        return jsonify(error="not a member"), 404

    if is_self:
        # Leaving the group yourself. The last owner can't leave (would orphan
        # the group) - promote someone else to owner first.
        if target_role == "owner" and not is_admin:
            with db() as conn:
                owner_count = conn.execute(
                    "SELECT COUNT(*) AS n FROM user_groups "
                    "WHERE group_id = ? AND role = 'owner'", (group_id,)
                ).fetchone()["n"]
            if owner_count <= 1:
                return jsonify(error="you are the only owner - make another "
                                     "member an owner before leaving"), 400
    else:
        # Removing someone else requires owner or admin.
        if not (is_admin or my_role == "owner"):
            return jsonify(error="only the group owner or an admin can remove "
                                 "other members"), 403
        # Owners can't remove other owners; that's an admin action.
        if target_role == "owner" and not is_admin:
            return jsonify(error="only an admin can remove a group owner"), 403

    with db() as conn:
        conn.execute("DELETE FROM user_groups WHERE user_dn = ? AND group_id = ?",
                     (dn, group_id))
    log_event("group_remove_member", "ok", group_id=group_id,
              member=_cn_from_dn(dn) or dn, self=int(is_self))
    return jsonify(ok=True)

@bp.put("/api/groups/<int:group_id>/members/role")
@require_auth
@require_csrf
def group_owner_set_member_role(group_id):
    """Group owners (or admins) promote a member to owner, or demote an owner
    back to member - so a group can be self-managed without an admin. Safeguard:
    a group must always keep at least one owner, so the last owner cannot be
    demoted (by an owner; an admin still goes through the admin endpoint)."""
    me = g.identity["dn"]
    if not _group_by_id(group_id):
        return jsonify(error="group not found"), 404
    if not _is_group_owner_or_admin(me, group_id):
        log_event("group_set_role", "deny_not_owner", group_id=group_id)
        return jsonify(error="only the group owner or an admin can change roles"), 403
    payload = request.get_json(silent=True) or {}
    dn = (payload.get("dn") or "").strip()
    role = (payload.get("role") or "").strip()
    if role not in ("member", "owner"):
        return jsonify(error="role must be 'member' or 'owner'"), 400
    if not dn:
        return jsonify(error="dn required"), 400

    target_role = _group_role(dn, group_id)
    if target_role is None:
        return jsonify(error="not a member of that group"), 404
    if target_role == role:
        return jsonify(ok=True)  # no change

    # Don't allow demoting the last owner - the group would be left ownerless.
    if target_role == "owner" and role == "member":
        with db() as conn:
            owner_count = conn.execute(
                "SELECT COUNT(*) AS n FROM user_groups "
                "WHERE group_id = ? AND role = 'owner'", (group_id,)
            ).fetchone()["n"]
        if owner_count <= 1:
            return jsonify(error="a group must have at least one owner"), 400

    with db() as conn:
        conn.execute(
            "UPDATE user_groups SET role = ? WHERE group_id = ? AND user_dn = ?",
            (role, group_id, dn))
    log_event("group_set_role", "ok", group_id=group_id,
              member=_cn_from_dn(dn) or dn, role=role, by="owner")
    return jsonify(ok=True)
