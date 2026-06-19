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
import os
import re
import subprocess
import tempfile

import sign

_get_setting = None
# A destination hostname must be a plain host/FQDN - it's interpolated into the
# remote scp path, so reject anything with shell-significant characters.
_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


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


def _openbao_kv_read(path):
    """Read a KV v2 secret's data dict at <kv_mount>/<path>; {} if empty."""
    addr, _pki = sign._openbao_addr_mount()
    if not addr:
        raise DeliveryError("OpenBao address is not configured")
    mount = (_get("delivery_openbao_kv_mount", "secret")).strip("/")
    token = sign._openbao_login(addr)
    try:
        d = sign._http(f"{addr}/v1/{mount}/data/{path}", token=token)
    except sign.SignError as e:
        raise DeliveryError(f"Vault read of {mount}/{path} failed: {e}")
    return ((d.get("data") or {}).get("data")) or {}


def _deliver_ssh(job):
    """Copy the cert (and key, per key_mode) to the destination host over SSH,
    using a per-destination credential fetched from Vault
    (secret/csr-delivery-ssh/<host>: username, private_key, optional port), then
    run the template's optional reload command."""
    host = (job.get("target_host") or "").strip()
    if not _HOST_RE.match(host):
        raise DeliveryError(f"invalid destination host: {host!r}")
    cred = _openbao_kv_read("csr-delivery-ssh/" + host)
    key = cred.get("private_key")
    if not key:
        raise DeliveryError(f"no SSH credential at secret/csr-delivery-ssh/{host}")
    user = (cred.get("username") or "root").strip()
    port = str(cred.get("port") or "22").strip()
    remote_dir = (job.get("delivery_target") or "/etc/ssl/delivered").rstrip("/")
    bundle = _job_bundle(job)

    kf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".key")
    try:
        kf.write(key if key.endswith("\n") else key + "\n")
        kf.close()
        os.chmod(kf.name, 0o600)
        ssh = ["ssh", "-i", kf.name, "-p", port,
               "-o", "StrictHostKeyChecking=accept-new",
               "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
               f"{user}@{host}"]

        def _put(content, name, mode):
            dest = f"{remote_dir}/{name}"
            p = subprocess.run(
                ssh + [f"umask 077; cat > '{dest}' && chmod {mode} '{dest}'"],
                input=content, capture_output=True, text=True, timeout=30)
            if p.returncode != 0:
                raise DeliveryError(f"write {name} failed: {(p.stderr or p.stdout)[:160]}")

        _put(bundle["certificate"], host + ".crt", "0644")
        shipped = "cert"
        if bundle.get("private_key"):
            _put(bundle["private_key"], host + ".key", "0600")
            shipped = "cert+key"
        reload_cmd = (job.get("delivery_reload") or "").strip()
        if reload_cmd:
            p = subprocess.run(ssh + [reload_cmd], capture_output=True,
                               text=True, timeout=60)
            if p.returncode != 0:
                raise DeliveryError(f"reload failed: {(p.stderr or p.stdout)[:160]}")
        return f"ssh:{user}@{host}:{remote_dir} ({shipped})"
    finally:
        try:
            os.remove(kf.name)
        except OSError:
            pass


PROVIDERS = {
    "openbao": _deliver_openbao,
    "ssh": _deliver_ssh,
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
