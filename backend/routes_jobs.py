"""routes_jobs blueprint - extracted from app.py (paths unchanged)."""
from flask import Blueprint, Response, abort, g, jsonify, request, session
import csv, io, json, os, re, subprocess, time, uuid, zipfile
import notify
import capabilities
from app import (  # noqa: E402
    app, ISSUED_DIR, JOB_ID_RE, KEY_ALGOS_ALLOWED, KEY_NAME_RE, MAX_CERT_BYTES, CompletionError, _add_session_keys, _attach_signed_cert, _cert_expiry, _cert_upload_warnings, _cn_from_dn, _get_or_create_session, _get_session_keys, _group_by_id, _group_email, _is_signer, _parse_csr_subject, _parse_helper_listing, _signer_recipients, _user_group_ids, _verify_cert_matches_csr, db, fire_webhooks, get_setting, log_event, require_auth, require_csrf, resolve_signing_policy, run_helper)
bp = Blueprint("jobs", __name__)

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

@bp.get("/api/jobs")
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

@bp.get("/api/jobs/<job_id>")
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
    # Approve-&-sign is offered only when this user may sign (signer or admin),
    # the job is pending, AND this job's template (or the global default)
    # resolves to an automated backend that's usable here. Authoritative
    # server-side gate (the /sign route enforces the same).
    _tid = row["template_id"] if "template_id" in row.keys() else None
    out["can_sign"] = bool(
        row["status"] == "pending"
        and (user_is_signer or user_is_admin)
        and resolve_signing_policy(_tid)["signer_backend"] != "manual"
        and capabilities.available("ca.signing.openbao")
    )
    log_event("get_job", "ok", job_id=job_id)
    return jsonify(out)

@bp.get("/api/jobs/<job_id>/csr")
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

@bp.get("/api/jobs/<job_id>/cert")
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

@bp.put("/api/jobs/<job_id>/group")
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

@bp.get("/api/jobs/<job_id>/key")
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
@bp.post("/api/jobs/<job_id>/upload-cert")
@require_auth
@require_csrf
def upload_cert(job_id):
    if not JOB_ID_RE.match(job_id):
        abort(400)
    payload = request.get_json(silent=True) or {}
    cert_pem = payload.get("cert_pem", "")

    if not cert_pem or not isinstance(cert_pem, str) or not (50 < len(cert_pem) <= MAX_CERT_BYTES):
        return jsonify(error="invalid cert_pem"), 400

    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-subject"],
            input=cert_pem, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            log_event("upload_cert", "deny_invalid_cert", job_id=job_id)
            return jsonify(error="not a valid X.509 certificate"), 400
    except Exception:
        return jsonify(error="cert validation error"), 400

    # Manual return path: feed the verified cert to the shared completion helper
    # (same verify + 'issued' transition + filesystem drop + webhook + email
    # used by the v2 approve-&-sign route). signed_via='manual', no approver.
    try:
        result = _attach_signed_cert(
            job_id, cert_pem, actor_dn=g.identity["dn"],
            signed_via="manual", log_action="upload_cert")
    except CompletionError as e:
        return jsonify(**e.payload), e.status

    return jsonify(ok=True, status="issued", target_host=result["target_host"],
                   expires_at=result["expires_at"], warnings=result["warnings"])

# ============================================================
# Cancel / mark failed
# ============================================================
@bp.post("/api/jobs/<job_id>/cancel")
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

@bp.post("/api/jobs/<job_id>/renew")
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
    try:
        recipients = _signer_recipients()
        if recipients:
            notify.send_csrs_created([cn or target], cert_type,
                                     _cn_from_dn(me), requester_email, recipients)
    except Exception:
        pass
    return jsonify(ok=True, new_job_id=new_id)

@bp.get("/api/jobs/export.csv")
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

@bp.get("/api/signing-queue/csrs.zip")
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

@bp.post("/api/jobs/bulk-cancel")
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

@bp.post("/api/jobs/<job_id>/mark-failed")
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
@bp.get("/api/jobs/<job_id>/csr-info")
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

@bp.get("/api/jobs/<job_id>/cert-info")
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
