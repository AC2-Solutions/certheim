"""keystore.py - server-generated private-key storage policy (key-handling Phase 2).

The admin picks `key_storage` (Admin -> Signing/CA) for how a key Certinel
generates is kept:

  vault        (default) - write the key to OpenBao immediately after generation
                           and shred the host copy; nothing at rest on the host.
  return_once            - same, but the vault copy is destroyed on first fetch
                           (one-time retrieval).
  host                   - legacy on-disk keystore (the helper's KEYDIR), for
                           air-gapped / no-vault deployments.

Keys are stored per job at <kv>/certinel-keys/<job_id>. Retrieval is unified
(fetch_for_job / fetch_by_name): vault when `key_vault_path` is set, else the
host helper. Connection + AppRole login are reused from sign.py; this module
stores no secrets of its own. Every operation fails safe: any vault error during
generation leaves the key on the host (never lost), and is logged.

See docs/key-handling-design.md.
"""
import os
import urllib.error
import urllib.request

import sign

DEFAULT_KEY_STORAGE = "vault"
KEY_STORAGE_MODES = ("vault", "return_once", "host")

_get_setting = None


def configure(get_setting=None):
    global _get_setting
    if get_setting is not None:
        _get_setting = get_setting


def _get(key, default=""):
    return ((_get_setting(key) if _get_setting else None) or default)


def policy():
    p = _get("key_storage", DEFAULT_KEY_STORAGE)
    return p if p in KEY_STORAGE_MODES else DEFAULT_KEY_STORAGE


def vault_available():
    """Vault storage needs OpenBao configured (AppRole creds in the env)."""
    return bool(os.environ.get("CSR_OPENBAO_ROLE_ID", "").strip()
                and os.environ.get("CSR_OPENBAO_SECRET_ID", "").strip())


# --------------------------------------------------------------------------- #
# OpenBao KV v2 ops at <kv_mount>/certinel-keys/<job_id>                        #
# --------------------------------------------------------------------------- #
def _kv_mount():
    return (_get("delivery_openbao_kv_mount", "secret")).strip("/")


def _url(job_id, kind="data"):
    addr, _pki = sign._openbao_addr_mount()
    return f"{addr}/v1/{_kv_mount()}/{kind}/certinel-keys/{job_id}"


def _token(addr):
    return sign._openbao_login(addr)


def _put(job_id, pem):
    addr, _ = sign._openbao_addr_mount()
    sign._http(_url(job_id, "data"), {"data": {"key": pem}}, token=_token(addr))


def _read(job_id):
    addr, _ = sign._openbao_addr_mount()
    try:
        d = sign._http(_url(job_id, "data"), token=_token(addr))   # payload=None -> GET
    except sign.SignError as e:
        if "404" in str(e):           # no such (or destroyed) key -> not found
            return None
        raise
    return ((d.get("data") or {}).get("data") or {}).get("key")


def _destroy(job_id):
    """DELETE the KV metadata - removes all versions + metadata (a true shred)."""
    addr, _ = sign._openbao_addr_mount()
    req = urllib.request.Request(
        _url(job_id, "metadata"),
        headers={"X-Vault-Token": _token(addr)}, method="DELETE")
    try:
        urllib.request.urlopen(req, timeout=15, context=sign._ssl_context())
    except urllib.error.HTTPError as e:
        if e.code not in (200, 204, 404):
            raise


def _set_job(job_id, **cols):
    from app import db
    if not cols:
        return
    sets = ", ".join(f"{k}=?" for k in cols)
    with db() as conn:
        conn.execute(f"UPDATE jobs SET {sets} WHERE id=?", (*cols.values(), job_id))


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #
def secure_after_generate(job_id, key_name):
    """Apply the key-storage policy to a freshly generated server key (called
    right after the job is created). Returns the location: 'host' | 'vault' |
    'returned'. Never raises - any vault failure leaves the key on the host."""
    from app import run_helper, log_event
    mode = policy()
    if mode == "host" or not key_name:
        _set_job(job_id, key_storage="host")
        return "host"
    if not vault_available():
        log_event("keystore", "vault_unavailable", job_id=job_id, fallback="host")
        _set_job(job_id, key_storage="host")
        return "host"
    rc, pem, _err = run_helper(["get-key", key_name])
    if rc != 0 or not (pem or "").strip():
        log_event("keystore", "read_fail", job_id=job_id)
        _set_job(job_id, key_storage="host")
        return "host"
    try:
        _put(job_id, pem)
    except Exception as e:  # noqa: BLE001 - storage must never break issuance
        log_event("keystore", "vault_put_fail", job_id=job_id, error=str(e)[:160])
        _set_job(job_id, key_storage="host")          # keep the host copy
        return "host"
    run_helper(["delete-key", key_name])              # shred the host copy
    _set_job(job_id, key_storage=mode,
             key_vault_path="certinel-keys/" + job_id)  # local_key_name kept as a label
    log_event("keystore", "stored_vault", job_id=job_id, mode=mode)
    return "returned" if mode == "return_once" else "vault"


def fetch_for_job(job):
    """Return the private-key PEM for a job, from vault or the host helper, or
    None. For 'return_once' the vault copy is destroyed after this read."""
    from app import run_helper
    vpath = job.get("key_vault_path")
    if vpath:
        job_id = vpath.rsplit("/", 1)[-1]
        try:
            pem = _read(job_id)
        except sign.SignError:
            return None
        if pem and job.get("key_storage") == "return_once":
            try:
                _destroy(job_id)
            except Exception:  # noqa: BLE001
                pass
            _set_job(job["id"], key_vault_path=None, has_local_key=0,
                     key_storage="returned")
        return pem
    name = job.get("local_key_name")
    if job.get("has_local_key") and name:
        rc, pem, _ = run_helper(["get-key", name])
        return pem if rc == 0 else None
    return None


def fetch_by_name(name):
    """Download by key name (legacy session-key path). Resolve to its job - which
    may have moved the key to vault - else fall back to the host helper."""
    from app import db, run_helper
    with db() as conn:
        r = conn.execute("SELECT id, has_local_key, local_key_name, key_vault_path, "
                         "key_storage FROM jobs WHERE local_key_name=? LIMIT 1",
                         (name,)).fetchone()
    if r:
        return fetch_for_job(dict(r))
    rc, pem, _ = run_helper(["get-key", name])
    return pem if rc == 0 else None


def purge_for_job(job):
    """Remove a job's key from wherever it lives (vault + host). Best-effort."""
    from app import run_helper
    vpath = job.get("key_vault_path")
    if vpath:
        try:
            _destroy(vpath.rsplit("/", 1)[-1])
        except Exception:  # noqa: BLE001
            pass
    name = job.get("local_key_name")
    if name:
        run_helper(["delete-key", name])
