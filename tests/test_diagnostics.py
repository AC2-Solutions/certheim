"""Configuration self-checks (diagnostics.py) - the health-check battery the
admin UI runs on demand and the support bundle embeds. Community tier."""
import io
import json
import os
import pathlib
import sys
import tempfile
import time
import zipfile

import pytest

pytestmark = pytest.mark.tier(0)

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))

import envcompat  # noqa: E402

ADMIN = "CN=TEST.ADMIN.0000000001,OU=PKI,O=Example,C=US"
USER = "CN=TEST.USER.0000000002,OU=PKI,O=Example,C=US"


def cac(dn):
    return {"X-Client-Verify": "SUCCESS", "X-Client-DN": dn, "X-Client-Serial": "S1"}


@pytest.fixture(scope="module")
def env():
    tmp = tempfile.mkdtemp(prefix="diag-")
    if not (envcompat.getenv("CERTHEIM_DB_URL")
            or envcompat.getenv("CERTHEIM_DB_BACKEND", "").lower() in ("postgres", "postgresql")):
        os.environ["CERTHEIM_DB_PATH"] = os.path.join(tmp, "jobs.db")
    os.environ["CERTHEIM_ENV"] = os.path.join(tmp, "absent.env")
    os.environ["CERTHEIM_BOOTSTRAP_FIRST_ADMIN"] = "1"
    import app as appmod
    appmod.app.config.update(TESTING=True)
    c = appmod.app.test_client()
    c.get("/api/me", headers=cac(ADMIN))
    c.get("/api/me", headers=cac(USER))
    yield {"app": appmod, "client": c, "tmp": tmp}


def _report(env):
    import diagnostics
    return diagnostics.run_all(env["app"].get_setting, env["app"].db)


def _by_id(report):
    return {c["id"]: c for c in report["checks"]}


def test_report_shape_and_never_raises(env):
    report = _report(env)
    assert report["overall"] in ("ok", "warn", "error", "fail")
    assert report["checks"], "no checks ran"
    for c in report["checks"]:
        assert c["status"] in ("ok", "warn", "fail", "skip", "error")
        assert c["id"] and c["summary"]


def test_core_checks_pass_on_healthy_fixture(env):
    checks = _by_id(_report(env))
    assert checks["database"]["status"] == "ok"
    # test env keeps the bootstrap flag on with users present -> the check
    # must call it out as set-but-INERT (it only fires on an empty user table)
    assert checks["auth"]["status"] == "warn"
    assert "BOOTSTRAP" in checks["auth"]["summary"]
    assert "inert" in checks["auth"]["summary"]
    # no email config in the fixture -> warn with guidance, not a crash
    assert checks["email"]["status"] == "warn"


def test_scheduler_marker_lifecycle(env):
    import routes_admin
    # never ran -> warn
    assert _by_id(_report(env))["scheduler"]["status"] == "warn"
    # running the pass records the marker -> ok
    routes_admin.run_expiry_warnings()
    assert _by_id(_report(env))["scheduler"]["status"] == "ok"
    # stale marker -> warn again
    env["app"].set_setting("last_expiry_warn_at", str(time.time() - 3 * 86400))
    c = _by_id(_report(env))["scheduler"]
    assert c["status"] == "warn" and "days ago" in c["summary"]


def test_stuck_jobs_detected(env):
    with env["app"].db() as conn:
        conn.execute(
            "INSERT INTO jobs (id, requester_dn, target_host, status, "
            "created_at, csr_pem) VALUES (?,?,?,?,?,?)",
            ("diagjob01", USER, "old.example.com", "pending",
             time.time() - 10 * 86400, "-"))
    try:
        c = _by_id(_report(env))["stuck-jobs"]
        assert c["status"] == "warn" and "pending" in c["summary"]
    finally:
        with env["app"].db() as conn:
            conn.execute("DELETE FROM jobs WHERE id = 'diagjob01'")
    assert _by_id(_report(env))["stuck-jobs"]["status"] == "ok"


def test_local_auth_without_admin_password_fails(env):
    env["app"].set_setting("auth_mode", "local")
    try:
        c = _by_id(_report(env))["auth"]
        assert c["status"] == "fail" and "password" in c["summary"]
    finally:
        env["app"].set_setting("auth_mode", "mtls")


def test_endpoint_admin_only_and_bundle_embeds(env):
    c = env["client"]
    assert c.get("/api/admin/diagnostics", headers=cac(USER)).status_code == 403
    r = c.get("/api/admin/diagnostics", headers=cac(ADMIN))
    assert r.status_code == 200
    assert r.get_json()["checks"]
    # bundle carries the same report
    r = c.get("/api/admin/support-bundle", headers=cac(ADMIN))
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.data))
    assert "diagnostics.json" in z.namelist()
    assert "diagnostics.txt" in z.namelist()
    diag = json.loads(z.read("diagnostics.json"))
    assert diag["checks"] and diag["overall"] in ("ok", "warn", "error", "fail")


def test_no_secret_material_in_output(env):
    env["app"].set_setting("openbao_addr", "https://vault.example.com")
    env["app"].set_setting("signing_default_backend", "manual")
    blob = json.dumps(_report(env))
    for needle in ("password_hash", "-----BEGIN", "glpat-", "xoxb-"):
        assert needle not in blob
