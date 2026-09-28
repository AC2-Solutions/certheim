"""/api/jobs/hosts: one entry per host with the CURRENT certificate.

A host that auto-renews every few hours (nasmb.ac2.lan hit 201 jobs, 129 still
valid) must read as a single tile: the current cert is the valid one with the
latest expiry, superseded-but-still-valid certs are counted, and hosts with
nothing valid surface first.
"""
import os
import pathlib
import sys
import tempfile
import time
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))

import envcompat  # noqa: E402

ADMIN = "CN=HOSTS.ADMIN.0000000001,OU=PKI,O=Example,C=US"
USER = "CN=HOSTS.USER.0000000002,OU=PKI,O=Example,C=US"
DAY = 86400


def cac(dn):
    return {"X-Client-Verify": "SUCCESS", "X-Client-DN": dn, "X-Client-Serial": "S1"}


@pytest.fixture(scope="module")
def env():
    tmp = tempfile.mkdtemp(prefix="hosts-")
    if not (envcompat.getenv("CERTHEIM_DB_URL")
            or envcompat.getenv("CERTHEIM_DB_BACKEND", "").lower() in ("postgres", "postgresql")):
        os.environ["CERTHEIM_DB_PATH"] = os.path.join(tmp, "jobs.db")
    os.environ["CERTHEIM_ENV"] = os.path.join(tmp, "absent.env")
    os.environ["CERTHEIM_BOOTSTRAP_FIRST_ADMIN"] = "1"
    import app as appmod
    appmod.app.config.update(TESTING=True)
    c = appmod.app.test_client()
    c.get("/api/me", headers=cac(ADMIN))   # first user -> admin
    c.get("/api/me", headers=cac(USER))
    now = time.time()

    def job(host, status, expires_in_days, requester=ADMIN, created_ago=0):
        with appmod.db() as conn:
            conn.execute(
                "INSERT INTO jobs (id, created_at, requester_dn, target_host, sans_json,"
                " csr_pem, status, completed_at, expires_at, cert_type)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, now - created_ago, requester, host,
                 '["%s"]' % host, "csr", status, now - created_ago,
                 None if expires_in_days is None else now + expires_in_days * DAY, "web"))

    # renewal-loop host: three still-valid versions, one expired, one pending
    job("loop.example.com", "issued", 20, created_ago=3 * DAY)
    job("loop.example.com", "issued", 25, created_ago=2 * DAY)
    job("loop.example.com", "issued", 31, created_ago=1 * DAY)   # current
    job("loop.example.com", "expired", -5, created_ago=40 * DAY)
    job("loop.example.com", "pending", None)
    # host whose only cert has lapsed
    job("dead.example.com", "expired", -1, created_ago=33 * DAY)
    # host about to expire
    job("soon.example.com", "issued", 3)
    # healthy host owned by the non-admin user
    job("mine.example.com", "issued", 80, requester=USER)
    return appmod, c


def _hosts(c, dn, q=""):
    r = c.get("/api/jobs/hosts" + (f"?q={q}" if q else ""), headers=cac(dn))
    assert r.status_code == 200, r.get_json()
    return {h["host"]: h for h in r.get_json()["hosts"]}, r.get_json()["hosts"]


def test_current_is_latest_valid_and_history_is_counted(env):
    _, c = env
    by, _ = _hosts(c, ADMIN)
    loop = by["loop.example.com"]
    assert loop["current"]["days_left"] in (30, 31)          # the 31-day one
    assert loop["valid"] == 3 and loop["older_valid"] == 2
    assert loop["counts"] == {"issued": 3, "expired": 1, "pending": 1}
    assert loop["total"] == 5
    assert loop["health"] == "warn"                           # <= 30 days


def test_health_classification_and_ordering(env):
    _, c = env
    by, ordered = _hosts(c, ADMIN)
    assert by["dead.example.com"]["current"] is None
    assert by["dead.example.com"]["health"] == "expired"
    assert by["soon.example.com"]["health"] == "critical"
    assert by["mine.example.com"]["health"] == "ok"
    names = [h["host"] for h in ordered]
    # nothing-valid first, then critical, then warn, then healthy
    assert names.index("dead.example.com") < names.index("soon.example.com") \
        < names.index("loop.example.com") < names.index("mine.example.com")


def test_search_filters_hosts(env):
    _, c = env
    by, _ = _hosts(c, ADMIN, q="loop")
    assert list(by) == ["loop.example.com"]


def test_non_admin_sees_only_own_hosts(env):
    _, c = env
    by, _ = _hosts(c, USER)
    assert list(by) == ["mine.example.com"]
