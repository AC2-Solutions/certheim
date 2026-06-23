"""routes_requests blueprint - extracted from app.py (paths unchanged)."""
from flask import Blueprint, Response, abort, g, jsonify, request, session
import csv, json, string, subprocess, time, uuid
import notify
import capabilities
import csr_subject
import sign
from app import (  # noqa: E402
    CERTLIST_LINE_RE, HOSTNAME_RE, KEY_ALGOS_ALLOWED, KEY_NAME_RE, MAX_CERTLIST_BYTES, MAX_CSR_BYTES, _add_session_keys, _attach_signed_cert, _cn_from_dn, _coerce_template_id, _get_or_create_session, _get_session_keys, _group_by_id, _normalize_cert_types, _parse_csr_subject, _parse_helper_listing, _set_session_cookie, _signer_recipients, _user_group_ids, _validate_email, db, fire_webhooks, log_event, require_auth, require_csrf, resolve_signing_policy, run_helper)
bp = Blueprint("requests", __name__)


def _auto_sign_jobs(job_ids, template_id):
    """If the request's template opts into an automated backend with auto_sign,
    issue each created job immediately (no human approval). Best-effort per job;
    on any failure the job stays pending for normal manual approval."""
    if not job_ids:
        return
    policy = resolve_signing_policy(template_id)
    if not (policy.get("auto_sign") and policy["signer_backend"] != "manual"
            and capabilities.available("ca.signing.openbao")):
        return
    for jid in job_ids:
        try:
            with db() as conn:
                jr = conn.execute("SELECT csr_pem FROM jobs WHERE id=?", (jid,)).fetchone()
            res = sign.sign_csr(jr["csr_pem"], policy,
                                actor="auto-sign:" + g.identity["dn"])
            _attach_signed_cert(jid, res.cert_pem, actor_dn=g.identity["dn"],
                                signed_via=policy["signer_backend"],
                                approver_dn=None, log_action="auto_sign")
            log_event("auto_sign", "issued", job_id=jid, backend=policy["signer_backend"])
        except Exception as e:  # noqa: BLE001 - never fail the request over auto-sign
            log_event("auto_sign", "error", job_id=jid, error=str(e)[:160])

# ============================================================
# Linux certlist
# ============================================================
def _certlist_get(subcmd, action_name):
    rc, out, err = run_helper([subcmd])
    if rc != 0:
        log_event(action_name, "error", rc=rc)
        return jsonify(error="read failed"), 500
    log_event(action_name, "ok", bytes=len(out))
    return jsonify(content=out)

def _certlist_put(subcmd, action_name):
    payload = request.get_json(silent=True) or {}
    content = payload.get("content", "")
    if not isinstance(content, str):
        return jsonify(error="content must be string"), 400
    if len(content.encode("utf-8")) > MAX_CERTLIST_BYTES:
        log_event(action_name, "deny_size")
        return jsonify(error="payload too large"), 413
    for n, line in enumerate(content.splitlines(), 1):
        if not CERTLIST_LINE_RE.match(line):
            log_event(action_name, "deny_invalid", line=n)
            return jsonify(error=f"invalid characters on line {n}"), 400
    rc, out, err = run_helper([subcmd], stdin=content)
    if rc != 0:
        log_event(action_name, "error", rc=rc)
        return jsonify(error="write failed"), 400
    log_event(action_name, "ok", bytes=len(content))
    return jsonify(ok=True)

@bp.get("/api/rhel/certlist")
@require_auth
def get_certlist_rhel():
    return _certlist_get("read-certlist-rhel", "read_certlist_rhel")

@bp.post("/api/rhel/certlist")
@require_auth
@require_csrf
def put_certlist_rhel():
    return _certlist_put("write-certlist-rhel", "write_certlist_rhel")

# ============================================================
# Linux generate -> ingest CSRs as jobs
# ============================================================
@bp.post("/api/rhel/generate")
@require_auth
@require_csrf
def generate_rhel():
    payload = request.get_json(silent=True) or {}
    submitted_email = payload.get("requester_email")
    # If empty/missing, fall back to user's saved default
    if submitted_email is None or (isinstance(submitted_email, str) and not submitted_email.strip()):
        submitted_email = (g.user or {}).get("email")
    ok, requester_email, err = _validate_email(submitted_email)
    if not ok:
        log_event("generate_rhel", "deny_invalid_email")
        return jsonify(error=err), 400
    if not requester_email:
        log_event("generate_rhel", "deny_no_email")
        return jsonify(error="No notification email on file. Set your email "
                             "in Settings before creating requests."), 400

    # Cert type(s). String or array; defaults to "web" to preserve the
    # existing user experience. Stored canonically (sorted csv).
    ok_ct, cert_type, err_ct = _normalize_cert_types(payload.get("cert_type"))
    if not ok_ct:
        return jsonify(error=err_ct), 400
    if cert_type is None:
        cert_type = "web"

    # Optional group assignment. Users can only assign to groups they belong to.
    # Admins can assign to any existing group.
    group_id = payload.get("group_id")
    if group_id is not None:
        try:
            group_id = int(group_id)
        except (TypeError, ValueError):
            return jsonify(error="invalid group_id"), 400
        if not _group_by_id(group_id):
            return jsonify(error="group does not exist"), 400
        if not g.user.get("is_admin") and group_id not in _user_group_ids(g.identity["dn"]):
            return jsonify(error="you are not a member of that group"), 403

    key_algo = (payload.get("key_algo") or "rsa2048").strip().lower()
    if key_algo not in KEY_ALGOS_ALLOWED:
        return jsonify(error=f"invalid key_algo (allowed: {', '.join(KEY_ALGOS_ALLOWED)})"), 400

    # Optional template the request is made under: drives per-template signing
    # policy (and auto-sign). Stored only if it references an existing template.
    template_id = _coerce_template_id(payload.get("template_id"))

    log_event("generate_rhel", "start",
              email=("set" if requester_email else "none"),
              group_id=(group_id if group_id else "-"),
              cert_type=cert_type, key_algo=key_algo)
    sid, _ = _get_or_create_session()
    start_time = time.time() - 2

    # Optional per-batch domain-suffix choice (one of the admin-configured
    # selectable suffixes). Sanitized here; the helper re-validates it against
    # the allow-list and ignores anything not configured.
    domain_choice = csr_subject.sanitize(payload.get("domain_suffix") or "", domain=True)
    # Optional named subject profile (slug); the helper loads subjects/<slug>.conf
    # and validates the slug, ignoring anything unknown.
    profile = csr_subject.slugify(payload.get("subject_profile") or "") if payload.get("subject_profile") else ""
    rc, out, err = run_helper(
        ["generate-typed", cert_type, key_algo, domain_choice, profile], timeout=600)
    if rc != 0:
        log_event("generate_rhel", "error", rc=rc, cert_type=cert_type)
        return jsonify(returncode=rc, output=out + err, jobs=[]), 500

    rc_l, out_l, _ = run_helper(["list-csrs"])
    new_csrs = [r["name"] for r in _parse_helper_listing(out_l)
                if r.get("mtime_epoch", 0) >= start_time] if rc_l == 0 else []

    rc_k, out_k, _ = run_helper(["list-keys"])
    new_keys = [r["name"] for r in _parse_helper_listing(out_k)
                if r.get("mtime_epoch", 0) >= start_time] if rc_k == 0 else []
    if sid and new_keys:
        _add_session_keys(sid, new_keys)

    job_ids = []
    created_targets = []
    for csr_name in new_csrs:
        rc_g, csr_pem, _ = run_helper(["get-csr", csr_name])
        if rc_g != 0:
            continue
        cn, sans = _parse_csr_subject(csr_pem)
        target = cn or csr_name[:-4]
        local_key = csr_name[:-4] + ".key"
        has_key = local_key in new_keys

        job_id = uuid.uuid4().hex
        with db() as conn:
            conn.execute("""
                INSERT INTO jobs (id, created_at, requester_dn, requester_serial,
                                  requester_ip, requester_email, target_host, sans_json,
                                  csr_pem, status, has_local_key, local_key_name, source,
                                  group_id, cert_type, key_algo, template_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, 'rhel', ?, ?, ?, ?)
            """, (
                job_id, time.time(),
                g.identity["dn"], g.identity.get("serial", "-"), request.remote_addr,
                requester_email,
                target, json.dumps(sans), csr_pem,
                1 if has_key else 0, local_key if has_key else None,
                group_id, cert_type, key_algo, template_id,
            ))
        # Apply the key-storage policy (vault by default: move the key off the
        # host into OpenBao + shred the local copy). No-op for external CSRs.
        if has_key:
            import keystore
            keystore.secure_after_generate(job_id, local_key, template_id)
        job_ids.append(job_id)
        created_targets.append(target)
        run_helper(["delete-csr", csr_name])
        log_event("job_created", "ok", job_id=job_id, target=target,
                  has_key=int(has_key), source="rhel",
                  email=("set" if requester_email else "none"),
                  group_id=(group_id if group_id else "-"),
                  cert_type=cert_type)
        fire_webhooks("job.created", {
            "job_id": job_id, "target_host": target, "source": "rhel",
            "requester_dn": g.identity["dn"], "requester_email": requester_email,
            "group_id": group_id, "cert_type": cert_type,
            "has_local_key": bool(has_key),
        })

    log_event("generate_rhel", "ok", jobs=len(job_ids), keys=len(new_keys),
              cert_type=cert_type)

    _auto_sign_jobs(job_ids, template_id)

    # Notify signer groups (one aggregated email per batch). Best-effort.
    if job_ids:
        try:
            recipients = _signer_recipients()
            if recipients:
                ok_n, reason_n = notify.send_csrs_created(
                    created_targets, cert_type,
                    _cn_from_dn(g.identity["dn"]),
                    (g.user or {}).get("email"),
                    recipients,
                )
                log_event("email_notify", "ok" if ok_n else "skip",
                          event="csrs_created", count=len(created_targets),
                          recipients=len(recipients), reason=reason_n[:96])
        except Exception as e:
            log_event("email_notify", "exception", event="csrs_created",
                      error=str(e)[:128])

    # Clear the on-disk certlist after a successful run so the next page load
    # shows an empty editor. Best-effort: log a warning but don't fail the
    # response if the clear write fails.
    rc_clear, _, _ = run_helper(["write-certlist-rhel"], stdin="")
    if rc_clear != 0:
        log_event("certlist_clear", "warn_failed", rc=rc_clear)
    else:
        log_event("certlist_clear", "ok")

    resp = jsonify(returncode=rc, output=out + err, jobs=job_ids, new_keys=new_keys)
    return _set_session_cookie(resp, sid)

# ============================================================
# External CSR upload
# ============================================================
@bp.post("/api/external/submit")
@require_auth
@require_csrf
def submit_external():
    payload = request.get_json(silent=True) or {}
    csr_pem = payload.get("csr_pem", "")
    target_host = payload.get("target_host", "").strip()

    if not isinstance(csr_pem, str) or not (50 < len(csr_pem) <= MAX_CSR_BYTES):
        return jsonify(error="invalid csr_pem"), 400
    if not target_host or not HOSTNAME_RE.match(target_host):
        return jsonify(error="invalid target_host"), 400

    ok, requester_email, err = _validate_email(payload.get("requester_email"))
    if not ok:
        return jsonify(error=err), 400
    if requester_email is None:
        requester_email = (g.user or {}).get("email")
    if not requester_email:
        log_event("submit_external", "deny_no_email")
        return jsonify(error="No notification email on file. Set your email "
                             "in Settings before creating requests."), 400

    group_id = payload.get("group_id")
    if group_id is not None:
        try:
            group_id = int(group_id)
        except (TypeError, ValueError):
            return jsonify(error="invalid group_id"), 400
        if not _group_by_id(group_id):
            return jsonify(error="group does not exist"), 400
        if not g.user.get("is_admin") and group_id not in _user_group_ids(g.identity["dn"]):
            return jsonify(error="you are not a member of that group"), 403

    # Cert type(s) are informational for external CSRs (we don't generate
    # them). Optional; string or array.
    ok_ct, cert_type_in, err_ct = _normalize_cert_types(payload.get("cert_type"))
    if not ok_ct:
        return jsonify(error=err_ct), 400

    try:
        proc = subprocess.run(
            ["openssl", "req", "-noout", "-verify"],
            input=csr_pem, capture_output=True, text=True, timeout=10,
        )
        verified = "verify OK" in (proc.stdout + proc.stderr) or proc.returncode == 0
        if not verified:
            log_event("submit_external", "deny_invalid_csr")
            return jsonify(error="CSR signature failed validation"), 400
    except Exception:
        log_event("submit_external", "error_validation")
        return jsonify(error="CSR validation error"), 400

    template_id = _coerce_template_id(payload.get("template_id"))
    cn, sans = _parse_csr_subject(csr_pem)
    job_id = uuid.uuid4().hex
    with db() as conn:
        conn.execute("""
            INSERT INTO jobs (id, created_at, requester_dn, requester_serial,
                              requester_ip, requester_email, target_host, sans_json,
                              csr_pem, status, has_local_key, source, group_id,
                              cert_type, template_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, 'external', ?, ?, ?)
        """, (
            job_id, time.time(),
            g.identity["dn"], g.identity.get("serial", "-"), request.remote_addr,
            requester_email,
            target_host, json.dumps(sans), csr_pem,
            group_id, cert_type_in, template_id,
        ))
    log_event("submit_external", "ok", job_id=job_id, target=target_host,
              cn=cn or "-", email=("set" if requester_email else "none"),
              group_id=(group_id if group_id else "-"),
              cert_type=(cert_type_in or "-"))
    fire_webhooks("job.created", {
        "job_id": job_id, "target_host": target_host, "source": "external",
        "requester_dn": g.identity["dn"], "requester_email": requester_email,
        "group_id": group_id, "cert_type": cert_type_in,
        "has_local_key": False, "cn": cn,
    })

    # Notify signer groups about the new external CSR. Best-effort.
    try:
        recipients = _signer_recipients()
        if recipients:
            ok_n, reason_n = notify.send_csrs_created(
                [target_host], cert_type_in or "unspecified",
                _cn_from_dn(g.identity["dn"]),
                (g.user or {}).get("email"),
                recipients,
            )
            log_event("email_notify", "ok" if ok_n else "skip",
                      event="csrs_created", count=1,
                      recipients=len(recipients), reason=reason_n[:96])
    except Exception as e:
        log_event("email_notify", "exception", event="csrs_created",
                  error=str(e)[:128])

    _auto_sign_jobs([job_id], template_id)

    # Re-read status: auto-sign may have flipped it to 'issued'.
    with db() as conn:
        st = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
    return jsonify(job_id=job_id, status=(st["status"] if st else "pending"),
                   cn=cn, sans=sans)

# ============================================================
# Linux key downloads (kept; session-scoped)
# ============================================================
@bp.get("/api/rhel/keys")
@require_auth
def list_session_keys():
    claimed = _get_session_keys()
    if not claimed:
        return jsonify(keys=[])
    rc, out, err = run_helper(["list-keys"])
    if rc != 0:
        log_event("list_keys", "error", rc=rc)
        return jsonify(keys=[])
    rows = [{"name": r["name"], "size": r["size"], "mtime": r["mtime"]}
            for r in _parse_helper_listing(out) if r["name"] in claimed]
    log_event("list_keys", "ok", count=len(rows))
    return jsonify(keys=rows)

@bp.get("/api/rhel/keys/<name>")
@require_auth
def fetch_key(name):
    if not KEY_NAME_RE.match(name):
        log_event("fetch_key", "deny_invalid", name=name[:64])
        abort(400)
    if name not in _get_session_keys():
        log_event("fetch_key", "deny_not_in_session", name=name)
        abort(403)
    import keystore
    out = keystore.fetch_by_name(name)   # vault when the key moved there, else host
    if not (out or "").strip():
        log_event("fetch_key", "not_found", name=name)
        return jsonify(error="not found"), 404
    log_event("fetch_key", "ok", name=name, bytes=len(out))
    return Response(out, mimetype="application/x-pem-file",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})
