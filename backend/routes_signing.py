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

# Issuance-time validity (TTL) bounds for the Approve-&-sign control. The floor
# supports genuinely short-lived certificates (e.g. 30-minute client certs); the
# ceiling falls back to the template/global cap, else one year.
MIN_SIGN_TTL = 1800                 # 30 minutes, in seconds
DEFAULT_MAX_SIGN_TTL = 365 * 86400  # 1 year, when no template/global cap is set
# How a server-generated private key is stored (admin-selectable). See
# docs/key-handling-design.md. Default vault: never persist on the host.
#   vault       - write the key to the credential manager; shred the host copy
#   return_once - hand to the requester once; never persisted server-side
#   host        - legacy on-disk keystore (air-gapped / no-vault deployments)
KEY_STORAGE_MODES = ("vault", "return_once", "host")
DEFAULT_KEY_STORAGE = "vault"
# Backends that honor an arbitrary per-issuance TTL (others issue at the CA's /
# template's own validity and ignore a requested value).
TTL_BACKENDS = {"openbao"}


def _ttl_bounds(template):
    """(min, max, default) issuance TTL in seconds for a job's template. max =
    the template's max_ttl cap, else the global signing cap, else one year;
    default = the template cap when set, else the max (current behavior)."""
    cap = template.get("max_ttl")
    if not cap:
        g = get_setting("signing_max_ttl")
        cap = int(g) if (g or "").strip().isdigit() else DEFAULT_MAX_SIGN_TTL
    cap = max(int(cap), MIN_SIGN_TTL)
    default = int(template.get("max_ttl") or cap)
    return MIN_SIGN_TTL, cap, max(MIN_SIGN_TTL, min(default, cap))


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
        # ACME server (Phase 4): expose an RFC 8555 directory for external
        # clients. Off by default + gated by the ca.server.acme capability.
        "acme_server_enabled": (get_setting("acme_server_enabled") or "0") in ("1", "true", "yes", "on"),
        "acme_server_base_url": get_setting("acme_server_base_url") or "",
        "acme_server_capability": capabilities.status("ca.server.acme"),
        # Private-key storage policy for server-generated keys (admin-selectable;
        # see docs/key-handling-design.md). Enforcement lands in a later phase.
        "key_storage": (get_setting("key_storage") or DEFAULT_KEY_STORAGE),
        "key_storage_options": list(KEY_STORAGE_MODES),
        # Phase 3 short-lived auto-rule: templates capped at <= this many seconds
        # don't retain keys (return_once); 0 disables. Per-template override wins.
        "key_return_once_max_ttl": int(get_setting("key_return_once_max_ttl") or 0),
        # FIPS 140-3 posture: live self-check + the admin "require FIPS" policy.
        "fips": capabilities.fips_status(),
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

    # Optional issuance-time validity override (short-lived certs). Only honored
    # for backends that accept an arbitrary TTL; clamped to the template's cap
    # and never below the 30-minute floor.
    payload = request.get_json(silent=True) or {}
    chosen_ttl = None
    req_ttl = payload.get("ttl")
    if req_ttl not in (None, "") and backend in TTL_BACKENDS:
        try:
            req_ttl = int(req_ttl)
        except (TypeError, ValueError):
            return jsonify(error="ttl must be an integer number of seconds"), 400
        lo, hi, _ = _ttl_bounds(template)
        if req_ttl < lo:
            return jsonify(error=f"ttl must be at least {lo} seconds "
                                 f"({lo // 60} minutes)"), 400
        chosen_ttl = min(req_ttl, hi)        # clamp down to the template/global cap
        template = {**template, "max_ttl": chosen_ttl}

    try:
        result = sign.sign_csr(row["csr_pem"], template, actor=actor_dn)
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
            signed_via=backend, approver_dn=actor_dn, log_action="sign",
            chain_pem=result.chain_pem)
    except CompletionError as e:
        return jsonify(**e.payload), e.status

    log_event("sign", "issued", job_id=job_id, backend=backend,
              role=template.get("openbao_role") or "-", approver=actor_dn[:128],
              ttl=chosen_ttl if chosen_ttl is not None else "-")
    return jsonify(ok=True, status="issued", signed_via=backend,
                   target_host=completed["target_host"],
                   expires_at=completed["expires_at"],
                   validity_seconds=chosen_ttl,
                   warnings=completed["warnings"],
                   chain_pem=result.chain_pem)


@bp.get("/api/jobs/<job_id>/sign-options")
@require_auth
def sign_options(job_id):
    """Validity bounds for the Approve-&-sign control: whether this job's backend
    honors a per-issuance TTL, and the min / max / default (seconds)."""
    if not JOB_ID_RE.match(job_id):
        return jsonify(error="invalid job id"), 400
    actor_dn = g.identity["dn"]
    if not (g.user.get("is_admin") or _is_signer(actor_dn)):
        return jsonify(error="not authorized"), 403
    with db() as conn:
        row = conn.execute(
            "SELECT template_id FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        return jsonify(error="job not found"), 404
    template = resolve_signing_policy(row["template_id"])
    backend = template["signer_backend"]
    lo, hi, default = _ttl_bounds(template)
    return jsonify(backend=backend, supports_ttl=(backend in TTL_BACKENDS),
                   ttl_min=lo, ttl_max=hi, ttl_default=default)


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
    if "key_storage" in payload:
        ks = (payload.get("key_storage") or DEFAULT_KEY_STORAGE).strip()
        if ks not in KEY_STORAGE_MODES:
            return jsonify(error=f"key_storage must be one of {list(KEY_STORAGE_MODES)}"), 400
        set_setting("key_storage", ks)
    if "key_return_once_max_ttl" in payload:
        try:
            v = max(0, int(payload.get("key_return_once_max_ttl") or 0))
        except (TypeError, ValueError):
            return jsonify(error="key_return_once_max_ttl must be a non-negative integer"), 400
        set_setting("key_return_once_max_ttl", str(v))
    if "fips_required" in payload:
        set_setting("fips_required", "1" if payload.get("fips_required") else "0")
    if "acme_server_enabled" in payload:
        set_setting("acme_server_enabled", "1" if payload.get("acme_server_enabled") else "0")
    if "acme_server_base_url" in payload:
        set_setting("acme_server_base_url", (payload.get("acme_server_base_url") or "").strip())
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
