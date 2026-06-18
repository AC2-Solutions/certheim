"""routes_signing blueprint - v2 in-UI certificate signing.

Approval-gated: a signer (or admin) triggers the sign; an automated backend
(OpenBao PKI) produces the cert, which feeds the SAME shared completion path
(_attach_signed_cert) as the manual upload - so verification, the 'issued'
transition, the filesystem drop, the webhook, and the email are identical no
matter who/what produced the cert.

P1 scope: signing is driven by a GLOBAL admin signing-config (default backend +
OpenBao role + max TTL). Jobs don't yet carry a template_id, so per-template
policy (design §4.3) is a P2 refinement - sign_csr already takes a template
dict, so that drops in without touching this flow.
"""
from flask import Blueprint, request, jsonify, g
import time
import capabilities
import sign
from app import (  # noqa: E402
    db, get_setting, set_setting, require_auth, require_admin, require_csrf,
    log_event, _is_signer, _attach_signed_cert, CompletionError, JOB_ID_RE,
    resolve_signing_policy, _cert_serial_colons, fire_webhooks)

bp = Blueprint("signing", __name__)

# Capability key gating the OpenBao backend (env_supports openbao + entitled).
CAP_OPENBAO = "ca.signing.openbao"


def _config_view():
    """Non-secret signing config: the selected provider, the full provider
    registry (with current field values + credential presence) so the admin UI
    can render any provider's connection fields, plus capability + CRL/OCSP."""
    return {
        "default_backend": (get_setting("signing_default_backend") or "manual"),
        "max_ttl": get_setting("signing_max_ttl") or "",
        "providers": sign.provider_meta(),
        "backends": list(sign.BACKENDS),
        # OpenBao capability (env_supports openbao + entitled) for the UI hint.
        "capability": capabilities.status(CAP_OPENBAO),
        "crl_ocsp": sign.crl_ocsp_urls(),
        # Automated-renewal master switch + default window (per-template windows
        # can override). Only effective for templates that opt in + an automated
        # backend; see renew.run_auto_renew.
        "auto_renew_enabled": (get_setting("auto_renew_enabled") or "0") in ("1", "true", "yes", "on"),
        "auto_renew_before_days": int(get_setting("auto_renew_before_days") or 30),
    }


@bp.post("/api/jobs/<job_id>/sign")
@require_auth
@require_csrf
def sign_job(job_id):
    """Approve-&-sign a pending job's CSR via the configured CA backend."""
    if not JOB_ID_RE.match(job_id):
        return jsonify(error="invalid job id"), 400

    # Approval gate: only a signer-group member or an admin may sign.
    actor_dn = g.identity["dn"]
    if not (g.user.get("is_admin") or _is_signer(actor_dn)):
        log_event("sign", "deny_not_signer", job_id=job_id, dn=actor_dn[:128])
        return jsonify(error="not authorized to sign (signer or admin only)"), 403

    with db() as conn:
        row = conn.execute(
            "SELECT status, csr_pem, template_id FROM jobs WHERE id = ?",
            (job_id,)).fetchone()
    if not row:
        return jsonify(error="job not found"), 404
    if row["status"] != "pending":
        return jsonify(error=f"job in status '{row['status']}', cannot sign"), 409

    # Resolve THIS job's template policy (falls back to the global default).
    template = resolve_signing_policy(row["template_id"])
    backend = template["signer_backend"]
    if backend == "manual":
        return jsonify(error="no automated signing backend is configured; "
                             "use the manual cert-upload path"), 409
    # Capability gate for the selected backend (offline boxes shouldn't try).
    _cap = "ca.signing." + backend
    if not capabilities.available(_cap):
        return jsonify(error=f"{backend} signing is not available in this "
                             "deployment", capability=capabilities.status(_cap)), 409

    try:
        result = sign.sign_csr(row["csr_pem"], template)
    except sign.BackendUnavailable as e:
        return jsonify(error=str(e)), 409
    except sign.SignError as e:
        log_event("sign", "backend_error", job_id=job_id, backend=backend,
                  error=str(e)[:200])
        return jsonify(error=f"signing failed: {e}"), 502

    # Feed the signed cert through the shared completion path (verifies the
    # cert's pubkey against the job CSR before flipping to 'issued').
    try:
        completed = _attach_signed_cert(
            job_id, result.cert_pem, actor_dn=actor_dn,
            signed_via=backend, approver_dn=actor_dn, log_action="sign")
    except CompletionError as e:
        return jsonify(**e.payload), e.status

    log_event("sign", "issued", job_id=job_id, backend=backend,
              role=template.get("openbao_role") or "-", approver=actor_dn[:128])
    return jsonify(ok=True, status="issued", signed_via=backend,
                   target_host=completed["target_host"],
                   expires_at=completed["expires_at"],
                   warnings=completed["warnings"],
                   chain_pem=result.chain_pem)


@bp.post("/api/jobs/<job_id>/revoke")
@require_auth
@require_csrf
def revoke_job(job_id):
    """Revoke an issued cert via the CA backend that produced it. Signer/admin
    only. Only certs from an automated (OpenBao) backend are revocable in-UI;
    others must be revoked at the CA."""
    if not JOB_ID_RE.match(job_id):
        return jsonify(error="invalid job id"), 400
    actor_dn = g.identity["dn"]
    if not (g.user.get("is_admin") or _is_signer(actor_dn)):
        log_event("revoke", "deny_not_signer", job_id=job_id, dn=actor_dn[:128])
        return jsonify(error="not authorized to revoke (signer or admin only)"), 403

    with db() as conn:
        row = conn.execute(
            "SELECT status, cert_pem, template_id, target_host "
            "FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        return jsonify(error="job not found"), 404
    if row["status"] != "issued":
        return jsonify(error=f"job in status '{row['status']}', only issued "
                             "certificates can be revoked"), 409

    backend = resolve_signing_policy(row["template_id"])["signer_backend"]
    if backend not in ("openbao", "windows_ca"):
        return jsonify(error="this certificate's backend does not support in-UI "
                             "revocation; revoke it at your CA"), 409
    if not capabilities.available("ca.signing." + backend):
        return jsonify(error=f"{backend} is not available in this deployment"), 409

    serial = _cert_serial_colons(row["cert_pem"] or "")
    if not serial:
        return jsonify(error="could not read the certificate serial"), 500
    try:
        rev_time = sign.revoke_cert(serial, backend=backend)
    except sign.SignError as e:
        log_event("revoke", "backend_error", job_id=job_id, error=str(e)[:200])
        return jsonify(error=f"revoke failed: {e}"), 502

    now = time.time()
    with db() as conn:
        conn.execute("UPDATE jobs SET status='revoked', revoked_at=?, "
                     "revoked_by_dn=? WHERE id=?", (now, actor_dn, job_id))
    log_event("revoke", "ok", job_id=job_id, serial=serial, actor=actor_dn[:128])
    fire_webhooks("job.revoked", {
        "job_id": job_id, "target_host": row["target_host"],
        "revoked_by_dn": actor_dn, "revoked_by_cn": None, "serial": serial,
    })
    return jsonify(ok=True, status="revoked", serial=serial,
                   revocation_time=rev_time)


@bp.get("/api/admin/signing-config")
@require_admin
def get_signing_config():
    return jsonify(**_config_view())


@bp.put("/api/admin/signing-config")
@require_admin
@require_csrf
def put_signing_config():
    payload = request.get_json(silent=True) or {}
    backend = (payload.get("default_backend") or "manual").strip()
    if backend not in sign.BACKENDS:
        return jsonify(error=f"default_backend must be one of {list(sign.BACKENDS)}"), 400

    ttl = payload.get("max_ttl")
    if ttl not in (None, ""):
        try:
            ttl = int(ttl)
            if ttl <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify(error="max_ttl must be a positive integer (seconds)"), 400

    set_setting("signing_default_backend", backend)
    set_setting("signing_max_ttl", str(ttl) if ttl not in (None, "") else "")
    # Automated-renewal master switch + default window (optional in the payload).
    if "auto_renew_enabled" in payload:
        set_setting("auto_renew_enabled",
                    "1" if payload.get("auto_renew_enabled") else "0")
    if "auto_renew_before_days" in payload:
        rd = payload.get("auto_renew_before_days")
        try:
            rd = max(1, min(int(rd), 365))
        except (TypeError, ValueError):
            return jsonify(error="auto_renew_before_days must be 1-365"), 400
        set_setting("auto_renew_before_days", str(rd))
    # Persist the selected provider's connection fields generically. The UI
    # sends {fields: {<field_key>: <value>}} for the chosen provider; each maps
    # to its app_settings key via the provider registry.
    fields = payload.get("fields") or {}
    if isinstance(fields, dict):
        for fkey, fval in fields.items():
            skey = sign.field_setting(backend, fkey)
            if skey:
                set_setting(skey, ("" if fval is None else str(fval)).strip())
    log_event("signing_config", "update", backend=backend,
              actor=g.identity["dn"][:128])
    return jsonify(ok=True, **_config_view())


@bp.post("/api/admin/signing-config/test")
@require_admin
@require_csrf
def test_signing_config():
    """Test the selected provider's connection without signing anything."""
    payload = request.get_json(silent=True) or {}
    backend = (payload.get("backend")
               or get_setting("signing_default_backend") or "openbao").strip()
    try:
        info = sign.test_connection(backend)
    except sign.SignError as e:
        log_event("signing_config", "test_fail", backend=backend, error=str(e)[:200])
        return jsonify(ok=False, error=str(e)), 502
    log_event("signing_config", "test_ok", backend=backend, addr=info.get("addr", "-"))
    # info already carries ok=True (+ addr/mount); don't pass ok= again or
    # jsonify raises "multiple values for keyword argument 'ok'" (500).
    return jsonify(**info)
