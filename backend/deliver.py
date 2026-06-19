"""deliver.py - ship issued certificates to their destinations (P1).

Provider seam mirroring sign.py / notify.py / ca_providers.py: one dispatch over
a registry of delivery backends, configured per `cert_templates` row. Delivery
runs best-effort inline right after issuance and is retried by the `csr-deliver`
systemd timer (`run_deliveries`), so a short-lived cert that fails to ship keeps
retrying instead of lapsing silently.

Delivered material:
- the leaf **certificate** (always; from `jobs.cert_pem`), and
- the **private key** when the template's `key_mode` ships it AND the job has a
  server-side key (Generate jobs; retrieved via the helper `get-key`). External-
  submit jobs have no server-side key -> certificate only.

P1 provider: `openbao` (write the bundle to OpenBao/Vault KV v2). The `ssh`
host-push provider lands in P1-B. Connection secrets come from the environment /
sign.py's OpenBao login; this module stores no secrets.
"""
import sign

_get_setting = None


def configure(get_setting=None):
    global _get_setting
    if get_setting is not None:
        _get_setting = get_setting


def _get(key, default=""):
    return ((_get_setting(key) if _get_setting else None) or default)


class DeliveryError(Exception):
    """A delivery attempt failed (retryable)."""


# Key-handling modes (admin-selectable per template). `destination` ships only
# the cert (the endpoint holds its own key); `ship`/`vault` also ship the key.
KEY_MODES = ("destination", "ship", "vault")


def _job_bundle(job):
    """{certificate, private_key?, target_host} for an issued job row (dict)."""
    bundle = {
        "certificate": job["cert_pem"],
        "target_host": job["target_host"],
    }
    ships_key = (job.get("key_mode") or "destination") in ("ship", "vault")
    if ships_key and job.get("has_local_key") and job.get("local_key_name"):
        from app import run_helper  # lazy: avoid an import cycle at module load
        rc, out, err = run_helper(["get-key", job["local_key_name"]])
        if rc != 0 or not (out or "").strip():
            raise DeliveryError(f"could not retrieve private key: {(err or '')[:120]}")
        bundle["private_key"] = out
    return bundle


# --------------------------------------------------------------------------- #
# Providers                                                                    #
# --------------------------------------------------------------------------- #
def _deliver_openbao(job):
    """Write the bundle to OpenBao KV v2 at <kv_mount>/<base>/<target_host>."""
    addr, _pki = sign._openbao_addr_mount()
    if not addr:
        raise DeliveryError("OpenBao address is not configured")
    kv_mount = (_get("delivery_openbao_kv_mount", "secret")).strip("/")
    base = ((job.get("delivery_target") or "").strip("/")
            or _get("delivery_openbao_base", "csr-certs").strip("/"))
    host = job["target_host"]
    bundle = _job_bundle(job)
    token = sign._openbao_login(addr)
    # KV v2 secret write: POST <addr>/v1/<mount>/data/<base>/<host>  {data: {...}}
    url = f"{addr}/v1/{kv_mount}/data/{base}/{host}"
    sign._http(url, {"data": bundle}, token=token)
    return f"openbao:{kv_mount}/{base}/{host}"


PROVIDERS = {
    "openbao": _deliver_openbao,
}


def deliver_job(job):
    """Deliver one issued job (a row dict carrying its template's delivery cfg).
    Returns a detail string on success; raises DeliveryError on failure. A
    backend of none/'' is a no-op (returns None)."""
    backend = (job.get("delivery_backend") or "none").strip()
    if backend in ("", "none"):
        return None
    import capabilities
    if not capabilities.available("delivery." + backend):
        raise DeliveryError(f"{backend} delivery is not available in this deployment")
    fn = PROVIDERS.get(backend)
    if not fn:
        raise DeliveryError(f"unknown delivery backend '{backend}'")
    if not job.get("cert_pem"):
        raise DeliveryError("job has no certificate to deliver")
    return fn(job)


# --------------------------------------------------------------------------- #
# Job loading + status bookkeeping (no Flask context required)                 #
# --------------------------------------------------------------------------- #
_JOB_SELECT = (
    "SELECT j.id, j.target_host, j.cert_pem, j.has_local_key, j.local_key_name, "
    "       t.delivery_backend, t.key_mode, t.delivery_target, t.delivery_reload "
    "FROM jobs j LEFT JOIN cert_templates t ON j.template_id = t.id "
)


def _load_job(conn, job_id):
    r = conn.execute(_JOB_SELECT + "WHERE j.id = ?", (job_id,)).fetchone()
    return dict(r) if r else None


def _mark(conn, job_id, status, detail=None, bump_attempt=False):
    import time
    if bump_attempt:
        conn.execute(
            "UPDATE jobs SET delivery_status=?, delivery_detail=?, "
            "delivery_attempts = COALESCE(delivery_attempts,0)+1 WHERE id=?",
            (status, (detail or "")[:300], job_id))
    else:
        conn.execute(
            "UPDATE jobs SET delivery_status=?, delivery_detail=?, "
            "delivered_at=?, delivery_attempts = COALESCE(delivery_attempts,0)+1 "
            "WHERE id=?",
            (status, (detail or "")[:300], time.time() if status == "delivered" else None,
             job_id))


def deliver_one(job_id):
    """Best-effort delivery of a single issued job (called inline after issue).
    Never raises; records the outcome on the job. Returns the status string."""
    from app import db, log_event
    with db() as conn:
        job = _load_job(conn, job_id)
        if not job or (job.get("delivery_backend") or "none") in ("", "none"):
            return "n/a"
    try:
        detail = deliver_job(job)
        with db() as conn:
            _mark(conn, job_id, "delivered", detail)
        log_event("delivery", "ok", job_id=job_id,
                  backend=job.get("delivery_backend"), detail=str(detail)[:120])
        return "delivered"
    except Exception as e:  # noqa: BLE001 - delivery must never break issuance
        with db() as conn:
            _mark(conn, job_id, "failed", str(e), bump_attempt=True)
        log_event("delivery", "fail", job_id=job_id,
                  backend=job.get("delivery_backend"), error=str(e)[:160])
        return "failed"


def mark_pending(job_id):
    """Flag an issued job for delivery if its template configures one. Called by
    the completion path before the inline attempt."""
    from app import db
    with db() as conn:
        job = _load_job(conn, job_id)
        if not job or (job.get("delivery_backend") or "none") in ("", "none"):
            return False
        conn.execute("UPDATE jobs SET delivery_status='pending' WHERE id=?", (job_id,))
        return True


def run_deliveries(limit=100):
    """Retry pending/failed deliveries (the csr-deliver timer entrypoint). No
    Flask context. Returns {delivered, failed, scanned}."""
    from app import db
    with db() as conn:
        rows = conn.execute(
            _JOB_SELECT +
            "WHERE j.status='issued' AND j.delivery_status IN ('pending','failed') "
            "AND COALESCE(t.delivery_backend,'none') NOT IN ('','none') LIMIT ?",
            (limit,)).fetchall()
        jobs = [dict(r) for r in rows]
    delivered = failed = 0
    for job in jobs:
        if deliver_one(job["id"]) == "delivered":
            delivered += 1
        else:
            failed += 1
    return {"delivered": delivered, "failed": failed, "scanned": len(jobs)}
