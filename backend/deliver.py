"""deliver.py - ship issued certificates to their destinations (P1).

Provider seam mirroring sign.py / notify.py / ca_providers.py: one dispatch over
a registry of delivery backends, configured per `cert_templates` row. Delivery
runs best-effort inline right after issuance and is retried by the `certinel-deliver`
systemd timer (`run_deliveries`), so a short-lived cert that fails to ship keeps
retrying instead of lapsing silently.

Delivered material:
- the leaf **certificate** (always; from `jobs.cert_pem`), and
- the **private key** when the template's `key_mode` ships it AND the job has a
  server-side key (Generate jobs; retrieved via the helper `get-key`). External-
  submit jobs have no server-side key -> certificate only.

Providers:
- P1 `openbao` — write the bundle to OpenBao/Vault KV v2.
- P1-B `ssh` — scp the cert/key to a host (per-destination cred from Vault).
- P2 `pull` — store the bundle behind a scoped, single-use token; the
  destination fetches it at GET /deliver/pull/<token> (no push path needed,
  works through a one-way firewall toward the dashboard).
- P2 `k8s` — server-side-apply a kubernetes.io/tls Secret into a cluster
  namespace (cluster API + token from Vault secret/csr-delivery-k8s/<cluster>).

Connection secrets come from the environment / sign.py's OpenBao login or from
Vault KV; this module stores no long-lived secrets of its own.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import sign

_get_setting = None
# A destination hostname must be a plain host/FQDN - it's interpolated into the
# remote scp path, so reject anything with shell-significant characters.
_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
# A Kubernetes namespace / secret name / cluster label (DNS-1123 subdomain-ish).
_K8S_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


def _https(method, url, body=None, headers=None, ca_pem=None, timeout=15,
           client_cert_pem=None, client_key_pem=None):
    """Arbitrary-method HTTPS to a non-OpenBao endpoint (Kubernetes API, a
    webhook receiver, CyberArk), verifying TLS against an optional CA bundle and
    optionally presenting a client certificate (mTLS). Returns (status, text)."""
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    ctx = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
    cf = None
    if client_cert_pem:
        # load_cert_chain wants files; write the cert(+key) to a 0600 temp PEM.
        cf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem")
        cf.write(client_cert_pem if client_cert_pem.endswith("\n") else client_cert_pem + "\n")
        if client_key_pem:
            cf.write(client_key_pem if client_key_pem.endswith("\n") else client_key_pem + "\n")
        cf.close()
        os.chmod(cf.name, 0o600)
        ctx.load_cert_chain(cf.name)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        raise DeliveryError(f"HTTP {e.code} from {url.split('?')[0]}: {detail}")
    except urllib.error.URLError as e:
        raise DeliveryError(f"unreachable {url.split('?')[0]}: {e.reason}")
    finally:
        if cf:
            try:
                os.remove(cf.name)
            except OSError:
                pass


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
    if ships_key and (job.get("has_local_key") or job.get("key_vault_path")):
        import keystore  # lazy: avoid an import cycle at module load
        pem = keystore.fetch_for_job(job)   # vault when stored there, else host
        if not (pem or "").strip():
            raise DeliveryError("could not retrieve private key for this job")
        bundle["private_key"] = pem
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
        # UserKnownHostsFile=/dev/null: certinel-api runs ProtectHome=true, so the
        # service user's ~/.ssh is masked and ssh can't persist known_hosts;
        # accept-new takes the host key on first use.
        ssh = ["ssh", "-i", kf.name, "-p", port,
               "-o", "StrictHostKeyChecking=accept-new",
               "-o", "UserKnownHostsFile=/dev/null",
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


# --------------------------------------------------------------------------- #
# P2: pull (token-bundle) provider                                             #
# --------------------------------------------------------------------------- #
def _public_base():
    """Externally reachable base URL of the dashboard, for handing pull links to
    a destination. Set via the `public_base_url` admin setting (the certinel-deliver
    timer has no request context to infer it). '' -> a relative path is used."""
    return (_get("public_base_url", "")).rstrip("/")


def _deliver_pull(job):
    """Stash the issued bundle behind a scoped, single-use token; the destination
    pulls it from GET /deliver/pull/<token>. The token is the credential, so it's
    random, short-lived (delivery_pull_ttl, default 1h) and consumed on fetch
    (delivery_pull_max_uses, default 1)."""
    from app import db  # lazy: avoid an import cycle at module load
    bundle = _job_bundle(job)
    try:
        ttl = max(60, int(_get("delivery_pull_ttl", "3600") or 3600))
    except ValueError:
        ttl = 3600
    try:
        max_uses = max(1, int(_get("delivery_pull_max_uses", "1") or 1))
    except ValueError:
        max_uses = 1
    token = secrets.token_urlsafe(32)
    now = time.time()
    with db() as conn:
        conn.execute(
            "INSERT INTO delivery_pulls (token, job_id, target_host, certificate, "
            "private_key, created_at, expires_at, max_uses, uses) "
            "VALUES (?,?,?,?,?,?,?,?,0)",
            (token, job.get("id"), job.get("target_host"), bundle["certificate"],
             bundle.get("private_key"), now, now + ttl, max_uses))
    base = _public_base()
    path = "/api/deliver/pull/" + token
    url = (base + path) if base else path
    return f"pull:{url} (1 of {max_uses}, ttl {ttl}s)"


def consume_pull(token, ip=None, peek=False):
    """Fetch + consume a pull bundle. Returns the bundle dict or None if the
    token is unknown/expired/exhausted (callers must not distinguish, to avoid
    an oracle). Deletes the row once uses reach max_uses."""
    from app import db
    now = time.time()
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM delivery_pulls WHERE token = ?", (token,)).fetchone()
        if not row:
            return None
        row = dict(row)
        if now >= row["expires_at"] or row["uses"] >= row["max_uses"]:
            conn.execute("DELETE FROM delivery_pulls WHERE token = ?", (token,))
            return None
        if not peek:
            uses = row["uses"] + 1
            if uses >= row["max_uses"]:
                conn.execute("DELETE FROM delivery_pulls WHERE token = ?", (token,))
            else:
                conn.execute(
                    "UPDATE delivery_pulls SET uses=?, last_pull_at=?, last_pull_ip=? "
                    "WHERE token=?", (uses, now, (ip or "")[:64], token))
    return {"certificate": row["certificate"],
            "private_key": row.get("private_key"),
            "target_host": row.get("target_host")}


def purge_expired_pulls():
    """Delete expired pull rows (called by the certinel-deliver timer). Returns count."""
    from app import db
    with db() as conn:
        cur = conn.execute("DELETE FROM delivery_pulls WHERE expires_at < ?",
                           (time.time(),))
        return cur.rowcount or 0


# --------------------------------------------------------------------------- #
# P2: k8s (TLS Secret) provider                                                #
# --------------------------------------------------------------------------- #
def _deliver_k8s(job):
    """Server-side-apply a kubernetes.io/tls Secret into a cluster namespace.
    delivery_target is `[<cluster>/]<namespace>/<secret-name>`; the cluster API
    address + bearer token (+ optional CA) come from Vault KV at
    secret/csr-delivery-k8s/<cluster> {api_server, token, ca_cert?}."""
    target = (job.get("delivery_target") or "").strip().strip("/")
    parts = target.split("/")
    if len(parts) == 2:
        cluster = _get("delivery_k8s_cluster", "default")
        namespace, name = parts
    elif len(parts) == 3:
        cluster, namespace, name = parts
    else:
        raise DeliveryError(
            "k8s delivery_target must be '<namespace>/<secret>' "
            "or '<cluster>/<namespace>/<secret>'")
    for label, val in (("cluster", cluster), ("namespace", namespace), ("secret", name)):
        if not _K8S_NAME_RE.match(val):
            raise DeliveryError(f"invalid k8s {label} name: {val!r}")

    bundle = _job_bundle(job)
    if not bundle.get("private_key"):
        raise DeliveryError(
            "k8s delivery needs the private key (set the template's key mode to "
            "'ship'); a kubernetes.io/tls Secret requires tls.key")

    cred = _openbao_kv_read("csr-delivery-k8s/" + cluster)
    api = (cred.get("api_server") or "").rstrip("/")
    tok = cred.get("token")
    if not (api and tok):
        raise DeliveryError(
            f"no k8s credential at secret/csr-delivery-k8s/{cluster} "
            "(need api_server + token)")
    ca_pem = cred.get("ca_cert") or None

    body = json.dumps({
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
        "type": "kubernetes.io/tls",
        "data": {
            "tls.crt": base64.b64encode(bundle["certificate"].encode()).decode(),
            "tls.key": base64.b64encode(bundle["private_key"].encode()).decode(),
        },
    })
    # Server-side apply is idempotent (create or update) and needs no
    # resourceVersion; force=true claims fields from any prior manager.
    url = (f"{api}/api/v1/namespaces/{namespace}/secrets/{name}"
           "?fieldManager=csr-dashboard&force=true")
    status, _ = _https(
        "PATCH", url, body=body, ca_pem=ca_pem,
        headers={"Authorization": "Bearer " + tok,
                 "Content-Type": "application/apply-patch+yaml",
                 "Accept": "application/json"})
    return f"k8s:{cluster}/{namespace}/{name} (status {status})"


# --------------------------------------------------------------------------- #
# P3: webhook (POST to a receiver) provider                                    #
# --------------------------------------------------------------------------- #
def _deliver_webhook(job):
    """POST the bundle as JSON to a receiver URL (delivery_target). Optionally
    signs the body (HMAC-SHA256) and/or presents a client cert (mTLS); both come
    from Vault at secret/csr-delivery-webhook/<host> when present
    {secret, ca_cert?, client_cert?, client_key?} — the provider also works with
    no Vault cred (a plain POST, for receivers gated by network/mTLS alone)."""
    url = (job.get("delivery_target") or "").strip()
    if not url.lower().startswith("https://"):
        raise DeliveryError("webhook delivery_target must be an https:// URL")
    host = (job.get("target_host") or "").strip()
    cred = {}
    try:
        if host:
            cred = _openbao_kv_read("csr-delivery-webhook/" + host)
    except DeliveryError:
        cred = {}            # no Vault / no cred -> unsigned POST

    bundle = _job_bundle(job)
    body = json.dumps({
        "event": "cert.delivered",
        "target_host": host,
        "certificate": bundle["certificate"],
        **({"private_key": bundle["private_key"]} if bundle.get("private_key") else {}),
    })
    headers = {"Content-Type": "application/json", "User-Agent": "csr-dashboard"}
    secret = cred.get("secret")
    if secret:
        sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers["X-CSR-Signature"] = "sha256=" + sig
    status, _ = _https("POST", url, body=body, headers=headers,
                       ca_pem=cred.get("ca_cert") or None,
                       client_cert_pem=cred.get("client_cert") or None,
                       client_key_pem=cred.get("client_key") or None)
    return f"webhook:{url} (status {status}{', signed' if secret else ''})"


# --------------------------------------------------------------------------- #
# P3: cyberark (CyberArk Conjur set-secret) provider                           #
# --------------------------------------------------------------------------- #
def _cyberark_cfg():
    return {
        "url": (_get("delivery_cyberark_url", "") or os.environ.get("CSR_CYBERARK_URL", "")).rstrip("/"),
        "account": _get("delivery_cyberark_account", "") or os.environ.get("CSR_CYBERARK_ACCOUNT", ""),
        "login": _get("delivery_cyberark_login", "") or os.environ.get("CSR_CYBERARK_LOGIN", ""),
        "api_key": os.environ.get("CSR_CYBERARK_API_KEY", ""),
        "ca_cert": os.environ.get("CSR_CYBERARK_CA_CERT", ""),
    }


def _deliver_cyberark(job):
    """Write the bundle into CyberArk Conjur as secret variable(s). The cert goes
    to the variable named by delivery_target; the key (per key_mode) to
    `<target>/key`. Connection config is admin-set; the API key is env-only."""
    c = _cyberark_cfg()
    missing = [k for k in ("url", "account", "login", "api_key") if not c[k]]
    if missing:
        raise DeliveryError("CyberArk not configured (missing " + ", ".join(missing) + ")")
    var_id = (job.get("delivery_target") or "").strip().strip("/")
    if not var_id:
        raise DeliveryError("cyberark delivery_target must be a Conjur variable id")
    ca = c["ca_cert"] or None
    bundle = _job_bundle(job)

    # 1) Authenticate: POST the API key, get a short-lived access token.
    login = urllib.parse.quote(c["login"], safe="")
    status, tok = _https(
        "POST", f"{c['url']}/authn/{c['account']}/{login}/authenticate",
        body=c["api_key"], ca_pem=ca,
        headers={"Content-Type": "text/plain", "Accept-Encoding": "base64"})
    auth = 'Token token="' + tok.strip() + '"'

    # 2) Set the cert variable (and the key variable when shipped).
    def _set(vid, value):
        path = "/".join(urllib.parse.quote(p, safe="") for p in vid.split("/"))
        _https("POST", f"{c['url']}/secrets/{c['account']}/variable/{path}",
               body=value, ca_pem=ca,
               headers={"Authorization": auth, "Content-Type": "text/plain"})

    _set(var_id, bundle["certificate"])
    shipped = "cert"
    if bundle.get("private_key"):
        _set(var_id + "/key", bundle["private_key"])
        shipped = "cert+key"
    return f"cyberark:{c['account']}:{var_id} ({shipped})"


PROVIDERS = {
    "openbao": _deliver_openbao,
    "ssh": _deliver_ssh,
    "pull": _deliver_pull,
    "k8s": _deliver_k8s,
    "webhook": _deliver_webhook,
    "cyberark": _deliver_cyberark,
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
    "       j.delivery_attempts, j.key_vault_path, j.key_storage, "
    "       t.delivery_backend, t.key_mode, t.delivery_target, t.delivery_reload "
    "FROM jobs j LEFT JOIN cert_templates t ON j.template_id = t.id "
)


def _load_job(conn, job_id):
    r = conn.execute(_JOB_SELECT + "WHERE j.id = ?", (job_id,)).fetchone()
    return dict(r) if r else None


# Retry policy for the certinel-deliver timer: exponential backoff between attempts,
# capped, then give up (status 'abandoned') and alert — a short-lived cert must
# never lapse silently.
MAX_DELIVERY_ATTEMPTS = 8
_BACKOFF_BASE = 120      # seconds (doubles each attempt)
_BACKOFF_CAP = 3600      # seconds


def _backoff(attempts):
    return min(_BACKOFF_CAP, _BACKOFF_BASE * (2 ** max(0, attempts - 1)))


def _max_attempts():
    try:
        return max(1, int(_get("delivery_max_attempts", str(MAX_DELIVERY_ATTEMPTS))
                          or MAX_DELIVERY_ATTEMPTS))
    except ValueError:
        return MAX_DELIVERY_ATTEMPTS


def _mark(conn, job_id, status, detail=None, next_attempt=None):
    """Record a delivery outcome. Always bumps the attempt counter; sets
    delivered_at on success and delivery_next_attempt (backoff gate) on retryable
    failure (None clears it)."""
    conn.execute(
        "UPDATE jobs SET delivery_status=?, delivery_detail=?, delivered_at=?, "
        "delivery_next_attempt=?, delivery_attempts = COALESCE(delivery_attempts,0)+1 "
        "WHERE id=?",
        (status, (detail or "")[:300], time.time() if status == "delivered" else None,
         next_attempt, job_id))


def deliver_one(job_id):
    """Best-effort delivery of a single issued job (called inline after issue and
    by the retry timer). Never raises; records the outcome on the job. On success
    fires job.delivered; after MAX attempts gives up (status 'abandoned') and
    fires job.delivery_failed so the failure can't pass silently. Returns the
    status string (delivered / failed / abandoned / n/a)."""
    from app import db, log_event, fire_webhooks
    with db() as conn:
        job = _load_job(conn, job_id)
        if not job or (job.get("delivery_backend") or "none") in ("", "none"):
            return "n/a"
    backend = job.get("delivery_backend")
    try:
        detail = deliver_job(job)
        with db() as conn:
            _mark(conn, job_id, "delivered", detail)
        log_event("delivery", "ok", job_id=job_id, backend=backend,
                  detail=str(detail)[:120])
        try:
            fire_webhooks("job.delivered", {
                "job_id": job_id, "target_host": job.get("target_host"),
                "backend": backend, "detail": str(detail)[:200]})
        except Exception:  # noqa: BLE001 - notification must not undo a delivery
            pass
        return "delivered"
    except Exception as e:  # noqa: BLE001 - delivery must never break issuance
        attempts = (job.get("delivery_attempts") or 0) + 1
        final = attempts >= _max_attempts()
        status = "abandoned" if final else "failed"
        nxt = None if final else (time.time() + _backoff(attempts))
        with db() as conn:
            _mark(conn, job_id, status, str(e), next_attempt=nxt)
        log_event("delivery", "giveup" if final else "fail", job_id=job_id,
                  backend=backend, attempts=attempts, error=str(e)[:160])
        if final:
            try:
                fire_webhooks("job.delivery_failed", {
                    "job_id": job_id, "target_host": job.get("target_host"),
                    "backend": backend, "attempts": attempts, "error": str(e)[:200]})
            except Exception:  # noqa: BLE001
                pass
        return status


def mark_pending(job_id):
    """Flag an issued job for delivery if its template configures one. Called by
    the completion path before the inline attempt; also resets the backoff gate
    so a manual re-queue retries immediately."""
    from app import db
    with db() as conn:
        job = _load_job(conn, job_id)
        if not job or (job.get("delivery_backend") or "none") in ("", "none"):
            return False
        conn.execute("UPDATE jobs SET delivery_status='pending', "
                     "delivery_next_attempt=NULL WHERE id=?", (job_id,))
        return True


def run_deliveries(limit=100):
    """Retry due pending/failed deliveries (the certinel-deliver timer entrypoint).
    Respects the per-job backoff gate and skips 'abandoned' jobs. No Flask
    context. Returns {delivered, failed, abandoned, scanned, purged}."""
    from app import db
    purged = purge_expired_pulls()
    try:
        import truststore
        purged += truststore.purge_expired_pulls()
    except Exception:
        pass  # trust-store pull cleanup is best-effort
    now = time.time()
    with db() as conn:
        rows = conn.execute(
            _JOB_SELECT +
            "WHERE j.status='issued' AND j.delivery_status IN ('pending','failed') "
            "AND (j.delivery_next_attempt IS NULL OR j.delivery_next_attempt <= ?) "
            "AND COALESCE(t.delivery_backend,'none') NOT IN ('','none') LIMIT ?",
            (now, limit)).fetchall()
        jobs = [dict(r) for r in rows]
    delivered = failed = abandoned = 0
    for job in jobs:
        outcome = deliver_one(job["id"])
        if outcome == "delivered":
            delivered += 1
        elif outcome == "abandoned":
            abandoned += 1
        else:
            failed += 1
    return {"delivered": delivered, "failed": failed, "abandoned": abandoned,
            "scanned": len(jobs), "purged": purged}
