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
    ("POST", "/api/slack/interact"),
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
])
def test_admin_reads_ok(client, path):
    assert client.get(path, headers=CAC).status_code == 200


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
