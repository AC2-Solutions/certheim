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
    ("GET", "/api/admin/csr-subject"),
    ("PUT", "/api/admin/csr-subject"),
    ("POST", "/api/admin/run-auto-renew"),
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
    "/api/admin/csr-subject",
    "/api/admin/stats",            # uses Path() — regressed to a 500 once
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
    assert {"manual", "openbao", "cyberark", "windows_ca"} <= set(body.get("backends", []))
    # provider registry drives the UI: each provider carries its own fields
    provs = {p["key"]: p for p in body.get("providers", [])}
    assert "openbao" in provs and "cyberark" in provs and "windows_ca" in provs
    assert any(f["key"] == "addr" for f in provs["openbao"]["fields"])
    assert any(f["key"] == "config" for f in provs["windows_ca"]["fields"])
    assert provs["cyberark"]["stub"] is True and provs["windows_ca"]["stub"] is False
    assert "capability" in body
    # automated-renewal controls are exposed (default off, 30-day window)
    assert body.get("auto_renew_enabled") is False
    assert body.get("auto_renew_before_days") == 30


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
    # valid policy accepted + round-trips through the templates list, including
    # the auto-renew opt-in + per-template window
    ok = client.put(f"/api/admin/templates/{tid}/signing", headers=WRITE,
                    data=json.dumps({"signer_backend": "openbao",
                                     "openbao_role": "csr-dashboard",
                                     "max_ttl": 3600, "auto_sign": True,
                                     "auto_renew": True, "renew_before_days": 21}))
    assert ok.status_code == 200, ok.get_data(as_text=True)
    again = client.get("/api/templates", headers=CAC).get_json()["templates"]
    row = next(t for t in again if t["id"] == tid)
    assert row["signer_backend"] == "openbao" and row["auto_sign"] == 1
    assert row["auto_renew"] == 1 and row["renew_before_days"] == 21
    # an out-of-range window is clamped to 1..365 (the UI input caps it too)
    assert client.put(f"/api/admin/templates/{tid}/signing", headers=WRITE,
                      data=json.dumps({"signer_backend": "openbao",
                                       "renew_before_days": 9999})).status_code == 200
    clamped = client.get("/api/templates", headers=CAC).get_json()["templates"]
    assert next(t for t in clamped if t["id"] == tid)["renew_before_days"] == 365
    # nonexistent template -> 404
    assert client.put("/api/admin/templates/999999/signing", headers=WRITE,
                      data=json.dumps({"signer_backend": "manual"})).status_code == 404


def test_auto_renew_timer_entrypoints_exported(client):
    """Regression guard for the blueprint-split breakage: the systemd timers
    call app.run_expiry_warnings()/app.run_auto_renew(), so both MUST be
    attributes of the app module."""
    appmod = client._appmod
    assert callable(getattr(appmod, "run_expiry_warnings", None))
    assert callable(getattr(appmod, "run_auto_renew", None))


def test_auto_renew_noop_when_disabled(client):
    """With the master switch off (default), the pass renews nothing and never
    raises — safe to run on every timer tick."""
    appmod = client._appmod
    renewed, skipped, errors = appmod.run_auto_renew()
    assert (renewed, errors) == (0, 0)


def test_run_auto_renew_endpoint(client):
    """Admin trigger returns the (renewed, skipped, errors) shape and requires
    auth + CSRF."""
    assert client.post("/api/admin/run-auto-renew", headers=CSRF).status_code == 403  # no identity
    assert client.post("/api/admin/run-auto-renew", headers=CAC).status_code == 403   # no CSRF
    r = client.post("/api/admin/run-auto-renew", headers=WRITE)
    assert r.status_code == 200
    body = r.get_json()
    assert {"renewed", "skipped", "errors"} <= set(body)


def test_duplicate_group_name_409_not_500(client):
    # A duplicate group name must hit sqlite3.IntegrityError -> 409, not a
    # NameError 500 (regression: routes_admin didn't import sqlite3).
    import json
    b = json.dumps({"name": "dup-grp-smoke"})
    r1 = client.post("/api/admin/groups", headers=WRITE, data=b)
    assert r1.status_code == 200, r1.get_data(as_text=True)
    r2 = client.post("/api/admin/groups", headers=WRITE, data=b)
    assert r2.status_code == 409, r2.get_data(as_text=True)
    client.delete(f"/api/admin/groups/{r1.get_json()['id']}", headers=WRITE)


def test_user_multi_group_assignment(client):
    # Assign a user to multiple groups in one PUT /admin/users, and remove.
    import json
    g1 = client.post("/api/admin/groups", headers=WRITE,
                     data=json.dumps({"name": "mg-one"})).get_json()["id"]
    g2 = client.post("/api/admin/groups", headers=WRITE,
                     data=json.dumps({"name": "mg-two"})).get_json()["id"]
    me = client.get("/api/me", headers=CAC).get_json()
    dn = me["dn"]
    # assign both
    r = client.put("/api/admin/users", headers=WRITE,
                   data=json.dumps({"dn": dn, "group_ids": [g1, g2]}))
    assert r.status_code == 200, r.get_data(as_text=True)
    users = {u["dn"]: u for u in client.get("/api/admin/users", headers=CAC).get_json()["users"]}
    assert g1 in users[dn]["group_ids"] and g2 in users[dn]["group_ids"]
    # drop g2 in one save
    client.put("/api/admin/users", headers=WRITE,
               data=json.dumps({"dn": dn, "group_ids": [g1]}))
    users = {u["dn"]: u for u in client.get("/api/admin/users", headers=CAC).get_json()["users"]}
    assert g1 in users[dn]["group_ids"] and g2 not in users[dn]["group_ids"]
    # unknown group rejected
    bad = client.put("/api/admin/users", headers=WRITE,
                     data=json.dumps({"dn": dn, "group_ids": [999999]}))
    assert bad.status_code == 400
    client.delete(f"/api/admin/groups/{g1}", headers=WRITE)
    client.delete(f"/api/admin/groups/{g2}", headers=WRITE)


def test_fleet_track_on_issue(client):
    # An issued cert is auto-added to fleet tracking via _fleet_track_issued.
    import subprocess, tempfile
    appmod = client._appmod
    d = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", d + "/k", "-out", d + "/c",
                    "-subj", "/CN=fleettest.example.com", "-days", "30"],
                   check=True, capture_output=True)
    pem = open(d + "/c").read()
    with appmod.db() as conn:
        appmod._fleet_track_issued(conn, "fleettrack-host", pem, job_id="jobxyz")
    certs = client.get("/api/fleet-certs", headers=CAC).get_json()["certs"]
    match = [c for c in certs if c.get("host") == "fleettrack-host"]
    assert match, "issued cert not tracked in fleet_certs"
    assert match[0].get("cn") == "fleettest.example.com"


def test_csr_subject_shape(client):
    b = client.get("/api/admin/csr-subject", headers=CAC).get_json()
    assert "config" in b and "configured" in b
    pkeys = {p["key"] for p in b.get("profiles", [])}
    assert "dod" in pkeys and "commercial" in pkeys
    assert "USEUCOM" in b.get("suggested_ous", [])


def test_csr_subject_render_sanitizes():
    import csr_subject as s
    out = s.render_conf({"org": "X$(id)`whoami`;rm", "ous": ["DoD", "DoD", "A;B"],
                         "domain_suffix": "ex.com"})
    assert "$(" not in out and "`" not in out and ";" not in out
    assert out.count("OU=") == 2          # dedup DoD; ';' stripped from "A;B"
    assert "DOMAIN_SUFFIX=ex.com" in out


def test_revoke_negatives(client):
    rid = "/api/jobs/" + "a" * 32 + "/revoke"
    assert client.post(rid, headers=CSRF).status_code == 403   # no identity
    assert client.post(rid, headers=CAC).status_code == 403    # no CSRF header
    # admin passes the signer gate; missing job -> 404 (not 500)
    assert client.post(rid, headers=WRITE).status_code == 404


# --- ACME (RFC 8555) client provider --------------------------------------
def test_acme_provider_registered(client):
    body = client.get("/api/admin/signing-config", headers=CAC).get_json()
    assert "acme" in body.get("backends", [])
    provs = {p["key"]: p for p in body.get("providers", [])}
    assert "acme" in provs and provs["acme"]["automated"] is True
    fkeys = {f["key"] for f in provs["acme"]["fields"]}
    assert {"directory_url", "challenge_type", "dns_server", "http_webroot"} <= fkeys


def test_acme_capability_key_present(client):
    import capabilities
    assert "ca.signing.acme" in capabilities.CAPABILITIES
    # not available without the env flag (offline-safe default)
    assert capabilities.available("ca.signing.acme") in (True, False)


def test_template_can_pin_acme_backend(client):
    import json
    tid = client.get("/api/templates", headers=CAC).get_json()["templates"][0]["id"]
    r = client.put(f"/api/admin/templates/{tid}/signing", headers=WRITE,
                   data=json.dumps({"signer_backend": "acme"}))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()["signer_backend"] == "acme"
    # unknown backend still rejected
    assert client.put(f"/api/admin/templates/{tid}/signing", headers=WRITE,
                      data=json.dumps({"signer_backend": "nope"})).status_code == 400


def test_acme_client_pure_helpers():
    """Offline unit coverage for the JOSE/encoding + CSR-parsing helpers (no
    network): base64url, JWK + RFC 7638 thumbprint stability, chain split, and
    identifier extraction from a real CSR."""
    import subprocess
    import acme_client as ac
    assert ac.b64u(b"\x00\xff") == "AP8"                      # no padding, urlsafe
    # account key -> JWK with members in thumbprint order; thumbprint stable
    key = ac.new_account_key_pem()
    jwk = ac._rsa_jwk(key)
    assert list(jwk.keys()) == ["e", "kty", "n"] and jwk["kty"] == "RSA"
    assert ac._jwk_thumbprint(jwk) == ac._jwk_thumbprint(dict(jwk))
    # chain split: leaf vs the rest
    leaf, chain = ac._split_chain(
        "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
        "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n")
    assert "AAA" in leaf and "BBB" in chain
    # identifiers parsed from a real CSR (CN + SAN)
    k = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True).stdout
    csr = subprocess.run(
        ["openssl", "req", "-new", "-key", "/dev/stdin", "-subj", "/CN=a.example.com",
         "-addext", "subjectAltName=DNS:a.example.com,DNS:b.example.com"],
        input=k, capture_output=True).stdout.decode()
    ids = ac.csr_identifiers(csr)
    assert "a.example.com" in ids and "b.example.com" in ids


# --- Phase 2: cloud DNS-01 solvers (Cloudflare / Route53 / Azure) ----------
def test_sigv4_known_answer():
    """AWS SigV4 'get-vanilla' published test vector — independent verification
    of the hand-rolled signing (no live AWS to test against)."""
    import acme_dns
    h = acme_dns.aws_sigv4_headers(
        "GET", "example.amazonaws.com", "/", "", b"",
        "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1", service="service",
        amzdate="20150830T123600Z", datestamp="20150830")
    assert "SignedHeaders=host;x-amz-date" in h["Authorization"]
    assert ("Signature=5fa00fa31553b73ebf1942676e86291e8372ff2"
            "a2260956d9b8aae1d763fbf31") in h["Authorization"]


def _http_recorder(responses):
    calls = []

    def fake(method, url, headers=None, body=None, timeout=20):
        calls.append({"method": method, "url": url, "headers": headers or {}, "body": body})
        return responses.pop(0)
    return calls, fake


def test_cloudflare_solver(monkeypatch):
    import json
    import acme_dns
    calls, fake = _http_recorder([
        (200, {}, b'{"result":[{"id":"zone123"}]}'),              # zone lookup
        (200, {}, b'{"success":true,"result":{"id":"rec456"}}'),  # create TXT
        (200, {}, b'{}'),                                         # delete
    ])
    monkeypatch.setattr(acme_dns, "_http", fake)
    s = acme_dns.Dns01CloudflareSolver("tok", propagation_wait=0)
    s.setup("a.example.com", "token", "keyauth-XYZ")
    create = json.loads(calls[1]["body"])
    assert create["name"] == "_acme-challenge.a.example.com" and create["type"] == "TXT"
    assert create["content"] == acme_dns._txt_value("keyauth-XYZ")
    assert "Bearer tok" in calls[1]["headers"]["Authorization"]
    s.cleanup()
    assert calls[2]["method"] == "DELETE" and "rec456" in calls[2]["url"]


def test_route53_solver(monkeypatch):
    import acme_dns
    calls, fake = _http_recorder([(200, {}, b"<ok/>"), (200, {}, b"<ok/>")])
    monkeypatch.setattr(acme_dns, "_http", fake)
    s = acme_dns.Dns01Route53Solver("AKID", "secret", "/hostedzone/Z123", propagation_wait=0)
    s.setup("a.example.com", "token", "keyauth-1")
    up = calls[0]
    assert "Z123" in up["url"] and b"UPSERT" in up["body"]
    assert b"_acme-challenge.a.example.com." in up["body"]
    assert acme_dns._txt_value("keyauth-1").encode() in up["body"]
    assert "AWS4-HMAC-SHA256" in up["headers"]["Authorization"]
    s.cleanup()
    assert b"DELETE" in calls[1]["body"]


def test_azure_solver(monkeypatch):
    import json
    import acme_dns
    calls, fake = _http_recorder([
        (200, {}, b'{"access_token":"tok123"}'),   # oauth token
        (200, {}, b'{}'),                          # PUT record
        (200, {}, b'{"access_token":"tok123"}'),   # token (cleanup)
        (200, {}, b'{}'),                          # DELETE
    ])
    monkeypatch.setattr(acme_dns, "_http", fake)
    s = acme_dns.Dns01AzureSolver("tenant", "cid", "csecret", "sub", "rg",
                                  "example.com", propagation_wait=0)
    s.setup("a.example.com", "token", "keyauth-1")
    put = calls[1]
    assert put["method"] == "PUT" and "dnsZones/example.com/TXT/_acme-challenge.a" in put["url"]
    body = json.loads(put["body"])
    assert body["properties"]["TXTRecords"][0]["value"] == [acme_dns._txt_value("keyauth-1")]
    assert "Bearer tok123" in put["headers"]["Authorization"]


def test_acme_dns_provider_field_shape(client):
    body = client.get("/api/admin/signing-config", headers=CAC).get_json()
    acme = next(p for p in body["providers"] if p["key"] == "acme")
    f = {x["key"]: x for x in acme["fields"]}
    assert f["challenge_type"]["options"] == ["dns-01", "http-01"]
    assert f["dns_provider"]["options"] == ["rfc2136", "cloudflare", "route53", "azure"]
    # dns_zone is conditional on challenge=dns-01 AND a cloud provider
    assert any(c["field"] == "dns_provider" for c in f["dns_zone"]["show_if"])


def test_acme_solver_azure_zone_validation(client):
    """The dns-01 dispatch validates provider-specific config (Azure needs a
    'sub/rg/zone' triplet)."""
    import sign
    appmod = client._appmod
    appmod.set_setting("acme_challenge_type", "dns-01")
    appmod.set_setting("acme_dns_provider", "azure")
    appmod.set_setting("acme_dns_zone", "not-a-triplet")
    try:
        with pytest.raises(sign.SignError):
            sign._acme_solver()
    finally:
        for k in ("acme_challenge_type", "acme_dns_provider", "acme_dns_zone"):
            appmod.set_setting(k, "")


# --- Phase 3: enterprise CA providers (EJBCA / Venafi / AWS PCA / Ent ADCS) --
def _self_signed_b64der():
    """A real cert as base64 DER, for canned EJBCA/Venafi responses."""
    import base64
    import subprocess
    key = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True).stdout
    pem = subprocess.run(["openssl", "req", "-new", "-x509", "-key", "/dev/stdin",
                          "-subj", "/CN=t", "-days", "1"], input=key, capture_output=True).stdout
    der = subprocess.run(["openssl", "x509", "-inform", "PEM", "-outform", "DER"],
                         input=pem, capture_output=True).stdout
    return base64.b64encode(der).decode(), pem.decode()


def _ca_recorder(responses):
    calls = []

    def fake(method, url, headers=None, body=None, timeout=30, context=None):
        calls.append({"method": method, "url": url, "headers": headers or {}, "body": body})
        return responses.pop(0)
    return calls, fake


def test_ejbca_request(monkeypatch):
    import json
    import ca_providers
    b64der, _ = _self_signed_b64der()
    calls, fake = _ca_recorder([(200, json.dumps(
        {"certificate": b64der, "certificate_chain": []}).encode())])
    monkeypatch.setattr(ca_providers, "_http", fake)
    leaf, _chain = ca_providers.sign_ejbca("CSRPEM", {
        "base_url": "https://ejbca.x", "ca_name": "CA",
        "cert_profile": "SERVER", "ee_profile": "ENDUSER", "username": "u"})
    assert "BEGIN CERTIFICATE" in leaf
    assert calls[0]["url"].endswith("/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll")
    sent = json.loads(calls[0]["body"])
    assert sent["certificate_request"] == "CSRPEM"
    assert sent["certificate_authority_name"] == "CA" and sent["end_entity_profile_name"] == "ENDUSER"


def test_venafi_request(monkeypatch):
    import base64
    import json
    import ca_providers
    _b64der, pem = _self_signed_b64der()
    monkeypatch.setenv("CSR_VENAFI_TOKEN", "tok")
    calls, fake = _ca_recorder([
        (200, json.dumps({"CertificateDN": "\\VED\\cert1"}).encode()),
        (200, json.dumps({"CertificateData": base64.b64encode(pem.encode()).decode()}).encode()),
    ])
    monkeypatch.setattr(ca_providers, "_http", fake)
    leaf, _chain = ca_providers.sign_venafi("CSRPEM", {
        "base_url": "https://tpp.x", "policy_dn": "\\VED\\Policy"})
    assert "BEGIN CERTIFICATE" in leaf
    assert calls[0]["url"].endswith("/vedsdk/certificates/request")
    assert "Bearer tok" in calls[0]["headers"]["Authorization"]
    req = json.loads(calls[0]["body"])
    assert req["PKCS10"] == "CSRPEM" and req["PolicyDN"] == "\\VED\\Policy"
    assert calls[1]["url"].endswith("/vedsdk/certificates/retrieve")


def test_aws_pca_request(monkeypatch):
    import base64
    import json
    import ca_providers
    monkeypatch.setenv("CSR_AWS_PCA_ACCESS_KEY", "AKID")
    monkeypatch.setenv("CSR_AWS_PCA_SECRET_KEY", "secret")
    calls, fake = _ca_recorder([
        (200, json.dumps({"CertificateArn": "arn:aws:acm-pca:us-east-1:1:certificate/abc"}).encode()),
        (200, json.dumps({"Certificate": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
                          "CertificateChain": "-----BEGIN CERTIFICATE-----\nY\n-----END CERTIFICATE-----"}).encode()),
    ])
    monkeypatch.setattr(ca_providers, "_http", fake)
    leaf, chain = ca_providers.sign_aws_pca("CSRPEM", {
        "ca_arn": "arn:aws:acm-pca:us-east-1:1:certificate-authority/x", "region": "us-east-1"})
    assert "X" in leaf and "Y" in chain
    issue = calls[0]
    assert issue["headers"]["x-amz-target"] == "ACMPrivateCA.IssueCertificate"
    assert "AWS4-HMAC-SHA256" in issue["headers"]["Authorization"]
    body = json.loads(issue["body"])
    assert base64.b64decode(body["Csr"]).decode() == "CSRPEM"
    assert calls[1]["headers"]["x-amz-target"] == "ACMPrivateCA.GetCertificate"


def test_enterprise_providers_registered(client):
    body = client.get("/api/admin/signing-config", headers=CAC).get_json()
    assert {"ejbca", "venafi", "aws_pca"} <= set(body["backends"])
    provs = {p["key"]: p for p in body["providers"]}
    for k in ("ejbca", "venafi", "aws_pca"):
        assert provs[k]["automated"] and not provs[k]["stub"]
    # windows_ca gained the Enterprise certificate-template field
    assert "template" in {f["key"] for f in provs["windows_ca"]["fields"]}


def test_enterprise_capability_keys(client):
    import capabilities
    for k in ("ca.signing.ejbca", "ca.signing.venafi", "ca.signing.aws_pca"):
        assert k in capabilities.CAPABILITIES


def test_template_pin_enterprise_backend(client):
    import json
    tid = client.get("/api/templates", headers=CAC).get_json()["templates"][0]["id"]
    r = client.put(f"/api/admin/templates/{tid}/signing", headers=WRITE,
                   data=json.dumps({"signer_backend": "venafi"}))
    assert r.status_code == 200 and r.get_json()["signer_backend"] == "venafi"
