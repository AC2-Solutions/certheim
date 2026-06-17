"""Endpoint smoke tests for the CSR Dashboard.

Purpose: a fast, dependency-light safety net that exercises every route GROUP
(auth, jobs, admin, integrations, capabilities) so a refactor - especially the
planned blueprint split of app.py - can't silently drop or break a route. It
asserts registration + auth + basic response shape, NOT deep business logic.

Runs against the app in-process via Flask's test client with a throwaway temp
DB; never touches a live deployment. CAC headers + first-admin bootstrap give an
authenticated admin without a real cert or session.

    pip install -r requirements.txt pytest
    pytest tests/test_smoke.py -q
"""
import os
import pathlib
import sys
import tempfile

import pytest

CAC = {  # mTLS identity headers; with bootstrap, the first user becomes admin
    "X-Client-Verify": "SUCCESS",
    "X-Client-DN": "CN=TEST.ADMIN.0000000001,OU=PKI,OU=DoD,O=U.S. Government,C=US",
    "X-Client-Serial": "AA11",
}
CSRF = {"X-Requested-With": "csr-dashboard"}
WRITE = {**CAC, **CSRF, "Content-Type": "application/json"}

# Route groups every refactor must keep intact (method, path).
CRITICAL_ROUTES = [
    ("GET", "/api/health"),
    ("GET", "/api/auth/info"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/register"),
    ("POST", "/api/auth/logout"),
    ("GET", "/api/me"),
    ("GET", "/api/whoami"),
    ("GET", "/api/jobs"),
    ("GET", "/api/admin/users"),
    ("GET", "/api/admin/groups"),
    ("GET", "/api/admin/auth-settings"),
    ("GET", "/api/admin/email-config"),
    ("GET", "/api/admin/webhooks"),
    ("GET", "/api/admin/capabilities"),
    ("GET", "/api/admin/slack-config"),
    ("GET", "/api/admin/audit"),
    ("GET", "/api/fleet-certs"),
    ("GET", "/api/admin/feedback"),
    ("GET", "/api/templates"),
    ("POST", "/api/feedback"),
    ("POST", "/api/slack/interact"),
    ("POST", "/api/jobs/<job_id>/sign"),
    ("GET", "/api/admin/signing-config"),
    ("PUT", "/api/admin/signing-config"),
    ("POST", "/api/admin/signing-config/test"),
    ("PUT", "/api/admin/templates/<int:template_id>/signing"),
    ("POST", "/api/jobs/<job_id>/revoke"),
]


@pytest.fixture(scope="session")
def client():
    tmp = tempfile.mkdtemp(prefix="csr-smoke-")
    os.environ["CSR_DB_PATH"] = os.path.join(tmp, "jobs.db")
    os.environ["CSR_DASHBOARD_ENV"] = os.path.join(tmp, "absent.env")
    os.environ["CSR_BOOTSTRAP_FIRST_ADMIN"] = "1"
    os.environ["CSR_CAP_EGRESS_INTERNET"] = "1"
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))
    import app as appmod
    appmod.app.config.update(TESTING=True)
    c = appmod.app.test_client()
    c.get("/api/me", headers=CAC)          # bootstrap the first CAC user as admin
    c._appmod = appmod
    return c


# --- registration / wiring -------------------------------------------------
def test_all_critical_routes_registered(client):
    rules = {(m, r.rule) for r in client._appmod.app.url_map.iter_rules()
             for m in r.methods}
    missing = [(m, p) for (m, p) in CRITICAL_ROUTES if (m, p) not in rules]
    assert not missing, f"routes missing after refactor: {missing}"


# --- unauthenticated surface ----------------------------------------------
def test_health_open(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.get_json().get("ok") is True


def test_auth_info_open(client):
    assert client.get("/api/auth/info").status_code == 200


def test_admin_requires_auth(client):
    assert client.get("/api/admin/users").status_code == 403


# --- authenticated admin (bootstrapped CAC user) --------------------------
def test_me_is_admin(client):
    r = client.get("/api/me", headers=CAC)
    assert r.status_code == 200
    assert r.get_json().get("is_admin") is True


@pytest.mark.parametrize("path", [
    "/api/jobs",
    "/api/admin/users",
    "/api/admin/groups",
    "/api/admin/auth-settings",
    "/api/admin/email-config",
    "/api/admin/webhooks",
    "/api/admin/capabilities",
    "/api/admin/slack-config",
    "/api/admin/audit",
    "/api/fleet-certs",
    "/api/admin/feedback",
    "/api/templates",
    "/api/admin/signing-config",
])
def test_admin_reads_ok(client, path):
    assert client.get(path, headers=CAC).status_code == 200


def test_job_detail_404(client):
    # a well-formed but nonexistent job id -> 404 (not 500/400)
    assert client.get("/api/jobs/" + "a" * 32, headers=CAC).status_code == 404


# --- negative-auth / CSRF / input validation -------------------------------
def test_write_requires_csrf(client):
    # authed admin but missing the X-Requested-With CSRF header -> 403
    import json
    r = client.post("/api/admin/groups", headers={**CAC, "Content-Type": "application/json"},
                    data=json.dumps({"name": "nocsrf"}))
    assert r.status_code == 403


def test_write_requires_auth(client):
    import json
    r = client.post("/api/admin/groups", headers=CSRF, data=json.dumps({"name": "noauth"}))
    assert r.status_code == 403


def test_bad_group_name_rejected(client):
    import json
    r = client.post("/api/admin/groups", headers=WRITE,
                    data=json.dumps({"name": "bad name!! @"}))
    assert r.status_code == 400


def test_capabilities_shape(client):
    body = client.get("/api/admin/capabilities", headers=CAC).get_json()
    assert "capabilities" in body and "environment" in body
    assert "integrations.chat" in body["capabilities"]


# --- a write cycle through CSRF + admin ------------------------------------
def test_group_crud(client):
    import json
    r = client.post("/api/admin/groups", headers=WRITE,
                    data=json.dumps({"name": "smoke-grp"}))
    assert r.status_code == 200, r.get_data(as_text=True)
    gid = r.get_json()["id"]
    assert any(g["id"] == gid for g in
               client.get("/api/admin/groups", headers=CAC).get_json()["groups"])
    assert client.delete(f"/api/admin/groups/{gid}", headers=WRITE).status_code == 200


# --- a signature-protected callback rejects forgery ------------------------
def test_slack_interact_unconfigured_or_unsigned(client):
    # interactivity disabled by default -> 404; if enabled, a bad signature -> 401
    assert client.post("/api/slack/interact", data="payload=%7B%7D").status_code \
        in (401, 404)


# --- v2 in-UI signing ------------------------------------------------------
def test_signing_config_shape(client):
    body = client.get("/api/admin/signing-config", headers=CAC).get_json()
    assert body.get("default_backend") == "manual"          # safe default
    assert "openbao" in body.get("backends", [])
    assert "capability" in body and "approle_configured" in body


def test_signing_config_put_bad_backend(client):
    import json
    r = client.put("/api/admin/signing-config", headers=WRITE,
                   data=json.dumps({"default_backend": "bogus"}))
    assert r.status_code == 400


def test_sign_requires_auth(client):
    # CSRF header present but no CAC identity -> 403
    assert client.post("/api/jobs/" + "a" * 32 + "/sign", headers=CSRF).status_code == 403


def test_sign_requires_csrf(client):
    # authed admin (a signer) but missing the CSRF header -> 403
    assert client.post("/api/jobs/" + "a" * 32 + "/sign", headers=CAC).status_code == 403


def test_sign_nonexistent_job_404(client):
    # admin passes the signer gate; the missing job then 404s (not 500)
    r = client.post("/api/jobs/" + "a" * 32 + "/sign", headers=WRITE)
    assert r.status_code == 404


def test_template_signing_policy(client):
    import json
    # a built-in template exists after first-run seeding
    tpls = client.get("/api/templates", headers=CAC).get_json()["templates"]
    assert tpls, "expected seeded built-in templates"
    tid = tpls[0]["id"]
    # bad backend rejected
    bad = client.put(f"/api/admin/templates/{tid}/signing", headers=WRITE,
                     data=json.dumps({"signer_backend": "nope"}))
    assert bad.status_code == 400
    # valid policy accepted + round-trips through the templates list
    ok = client.put(f"/api/admin/templates/{tid}/signing", headers=WRITE,
                    data=json.dumps({"signer_backend": "openbao",
                                     "openbao_role": "csr-dashboard",
                                     "max_ttl": 3600, "auto_sign": True}))
    assert ok.status_code == 200, ok.get_data(as_text=True)
    again = client.get("/api/templates", headers=CAC).get_json()["templates"]
    row = next(t for t in again if t["id"] == tid)
    assert row["signer_backend"] == "openbao" and row["auto_sign"] == 1
    # nonexistent template -> 404
    assert client.put("/api/admin/templates/999999/signing", headers=WRITE,
                      data=json.dumps({"signer_backend": "manual"})).status_code == 404


def test_revoke_negatives(client):
    rid = "/api/jobs/" + "a" * 32 + "/revoke"
    assert client.post(rid, headers=CSRF).status_code == 403   # no identity
    assert client.post(rid, headers=CAC).status_code == 403    # no CSRF header
    # admin passes the signer gate; missing job -> 404 (not 500)
    assert client.post(rid, headers=WRITE).status_code == 404
