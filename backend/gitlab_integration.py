"""GitLab integration for the Certheim.

Bidirectional, issue-driven signing loop:

  1. OUTBOUND  (dashboard -> GitLab API): when a CSR job is created the
     dashboard opens an issue in a signing project, pastes the CSR, assigns
     the signers, and labels it for the dashboard group. The issue iid is
     stored back on the job (jobs.gitlab_issue_iid).

  2. INBOUND   (GitLab -> dashboard, via webhook): a signer pastes/attaches
     the signed certificate in the issue (Note Hook) -> the dashboard pulls
     the PEM and attaches it to the matching job. Closing the issue
     (Issue Hook, action=close) confirms completion.

Config lives in /etc/certinel/integrations.conf (INI), managed from the
admin UI and writable by the service account. Secrets (api_token,
webhook_secret) are never returned to the UI in clear. All public functions
return (ok, ...) tuples and never raise into the request path.
"""
import base64
import configparser
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONFIG_PATH = Path("/var/opt/certinel/integrations.conf")
API_TIMEOUT = 15

# A PEM cert block pasted directly into an issue comment.
_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
    re.DOTALL,
)
# A GitLab markdown upload link to a cert file: [foo](/uploads/<hash>/foo.crt)
_UPLOAD_RE = re.compile(r"\((/uploads/[0-9a-f]{32}/[^)]+\.(?:crt|cer|pem|txt|key))\)", re.I)

_cfg = None


def _load():
    global _cfg
    cfg = configparser.ConfigParser()
    if CONFIG_PATH.exists():
        try:
            cfg.read(CONFIG_PATH)
        except configparser.Error:
            pass
    _cfg = cfg


_load()


def _get(key, fallback=""):
    return _cfg.get("gitlab", key, fallback=fallback).strip()


def is_enabled():
    return _cfg.get("gitlab", "enabled", fallback="false").strip().lower() in ("1", "true", "yes", "on")


def _project_enc():
    """URL-encoded project id-or-path for the API path."""
    return urllib.parse.quote(_get("project"), safe="")


def _api(method, path, fields=None, token=None, full_url=None):
    """Call the GitLab API. `path` is appended to {base}/api/v4 unless
    `full_url` is given. Returns (status, body_bytes, err)."""
    base = _get("base_url").rstrip("/")
    tok = token or _get("api_token")
    url = full_url or f"{base}/api/v4{path}"
    data = urllib.parse.urlencode(fields, doseq=True).encode() if fields else None
    headers = {"PRIVATE-TOKEN": tok, "User-Agent": "certinel/2.3"}
    if data:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            return resp.status, resp.read(), None
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(500)
        except Exception:
            pass
        return e.code, body, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return 0, b"", f"unreachable: {e.reason}"
    except Exception as e:  # noqa: BLE001 - never raise into the request path
        return 0, b"", f"{type(e).__name__}: {str(e)[:160]}"


def verify_webhook_token(token):
    """Constant-ish comparison of the X-Gitlab-Token against the configured
    secret. Returns False when no secret is configured (fail closed)."""
    secret = _get("webhook_secret")
    if not secret:
        return False
    a = (token or "").encode()
    b = secret.encode()
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def test_connection():
    """Verify base_url + token + project resolve. Returns (ok, reason)."""
    if not _get("base_url") or not _get("api_token") or not _get("project"):
        return False, "base_url, api_token and project are all required"
    status, body, err = _api("GET", f"/projects/{_project_enc()}")
    if err:
        return False, err
    try:
        p = json.loads(body)
        return True, f"connected to project {p.get('path_with_namespace', _get('project'))} (id {p.get('id')})"
    except Exception:
        return False, "unexpected response from GitLab"


def create_issue(job):
    """Open a signing issue for a CSR job. `job` needs id, target_host,
    sans (list), csr_pem, requester_cn/requester_email, group_name.
    Returns (ok, iid, web_url, reason)."""
    if not is_enabled():
        return False, None, None, "gitlab integration disabled"
    if not _get("project") or not _get("api_token"):
        return False, None, None, "project/api_token not configured"

    sans = job.get("sans") or []
    san_lines = "\n".join(f"- `{s}`" for s in sans) or "_none_"
    group = job.get("group_name") or "—"
    title = f"CSR signing: {job.get('target_host')} ({job.get('id')})"
    description = (
        "A certificate signing request awaits signing from the Certheim.\n\n"
        f"- **Target host:** `{job.get('target_host')}`\n"
        f"- **Job ID:** `{job.get('id')}`\n"
        f"- **Requested by:** {job.get('requester_cn') or '—'}"
        f" {('<' + job['requester_email'] + '>') if job.get('requester_email') else ''}\n"
        f"- **Dashboard group:** {group}\n\n"
        f"**SANs:**\n{san_lines}\n\n"
        "**CSR (PEM):**\n\n```\n"
        f"{(job.get('csr_pem') or '').strip()}\n"
        "```\n\n"
        "---\n"
        "**Signers:** sign this CSR, then paste the signed certificate PEM in a "
        "comment **or** attach the `.crt`/`.pem` file. The dashboard will attach "
        "it to the job automatically. Close this issue when done.\n"
    )
    fields = [
        ("title", title),
        ("description", description),
    ]
    labels = _get("labels")
    if labels:
        fields.append(("labels", labels))
    assignees = [a.strip() for a in _get("assignee_ids").split(",") if a.strip()]
    for a in assignees:
        fields.append(("assignee_ids[]", a))

    status, body, err = _api("POST", f"/projects/{_project_enc()}/issues", fields=fields)
    if err:
        return False, None, None, err
    try:
        d = json.loads(body)
        return True, d.get("iid"), d.get("web_url"), "issue created"
    except Exception:
        return False, None, None, "unexpected response creating issue"


def comment_issue(iid, body_text):
    """Post a note on an issue. Best-effort; returns (ok, reason)."""
    if not is_enabled() or not iid:
        return False, "disabled or no iid"
    status, body, err = _api(
        "POST", f"/projects/{_project_enc()}/issues/{int(iid)}/notes",
        fields=[("body", body_text)],
    )
    return (err is None), (err or "commented")


def close_issue(iid):
    status, body, err = _api(
        "PUT", f"/projects/{_project_enc()}/issues/{int(iid)}",
        fields=[("state_event", "close")],
    )
    return (err is None), (err or "closed")


def extract_cert_from_note(note_body, project_web_url):
    """Find a signed cert in an issue comment. Tries an inline PEM block
    first, then a GitLab /uploads/ attachment link (downloaded via the web
    path with the API token). Returns (cert_pem|None, reason)."""
    if not note_body:
        return None, "empty note"
    m = _PEM_RE.search(note_body)
    if m:
        return m.group(0).strip() + "\n", "inline PEM"
    u = _UPLOAD_RE.search(note_body)
    if u and project_web_url:
        upload_path = u.group(1)
        url = project_web_url.rstrip("/") + upload_path
        status, body, err = _api("GET", "", full_url=url)
        if err:
            return None, f"attachment download failed: {err}"
        text = body.decode("utf-8", "replace")
        m2 = _PEM_RE.search(text)
        if m2:
            return m2.group(0).strip() + "\n", "attached file"
        return None, "attachment had no PEM certificate"
    return None, "no certificate found in comment"


# ---------- settings round-trip for the admin UI ----------

def get_settings():
    return {
        "enabled": is_enabled(),
        "base_url": _get("base_url") or "https://gitlab.com",
        "project": _get("project"),
        "assignee_ids": _get("assignee_ids"),
        "labels": _get("labels"),
        "api_token_set": bool(_get("api_token")),
        "webhook_secret_set": bool(_get("webhook_secret")),
        "config_path": str(CONFIG_PATH),
    }


def save_settings(d):
    existing = configparser.ConfigParser()
    if CONFIG_PATH.exists():
        try:
            existing.read(CONFIG_PATH)
        except configparser.Error:
            pass

    def keep(key, incoming):
        v = (incoming or "").strip()
        return v if v else existing.get("gitlab", key, fallback="")

    cfg = configparser.ConfigParser()
    cfg["gitlab"] = {
        "enabled": "true" if d.get("enabled") else "false",
        "base_url": (d.get("base_url") or "").strip().rstrip("/"),
        "project": (d.get("project") or "").strip(),
        "assignee_ids": (d.get("assignee_ids") or "").strip(),
        "labels": (d.get("labels") or "").strip(),
        "api_token": keep("api_token", d.get("api_token")),
        "webhook_secret": keep("webhook_secret", d.get("webhook_secret")),
    }
    try:
        with open(CONFIG_PATH, "w") as f:
            f.write("# /etc/certinel/integrations.conf - managed via the admin UI\n")
            cfg.write(f)
    except OSError as e:
        return False, f"could not write {CONFIG_PATH}: {e}"
    _load()
    return True, "saved"
