"""First-run auth defaults: username/password out of the box, first account
registered becomes the admin, CAC/mTLS strictly opt-in; populated installs
with no stored mode freeze to the historical mtls fallback. Community tier."""
import os
import pathlib
import sys
import tempfile

import pytest

pytestmark = pytest.mark.tier(0)

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))

import envcompat  # noqa: E402

CSRF = {"X-Requested-With": "certheim"}
ADMIN = "CN=TEST.ADMIN.0000000001,OU=PKI,O=Example,C=US"


def cac(dn):
    return {"X-Client-Verify": "SUCCESS", "X-Client-DN": dn, "X-Client-Serial": "S1"}


@pytest.fixture(scope="module")
def env():
    tmp = tempfile.mkdtemp(prefix="firstrun-")
    if not (envcompat.getenv("CERTHEIM_DB_URL")
            or envcompat.getenv("CERTHEIM_DB_BACKEND", "").lower() in ("postgres", "postgresql")):
        os.environ["CERTHEIM_DB_PATH"] = os.path.join(tmp, "jobs.db")
    os.environ["CERTHEIM_ENV"] = os.path.join(tmp, "absent.env")
    import app as appmod
    appmod.app.config.update(TESTING=True)
    yield {"app": appmod, "client": appmod.app.test_client()}


@pytest.fixture()
def pristine(env):
    """Snapshot users + the auth_mode row, present an EMPTY install to the code
    under test, and restore afterwards - so this module can simulate first-run
    against the shared in-process app without disturbing other suites."""
    # NOTE: real (not TEMP) scratch tables - db() opens a fresh connection per
    # context, and sqlite TEMP tables are connection-scoped.
    with env["app"].db() as conn:
        conn.execute("DROP TABLE IF EXISTS _fr_users")
        conn.execute("DROP TABLE IF EXISTS _fr_mode")
        conn.execute("CREATE TABLE _fr_users AS SELECT * FROM users")
        conn.execute("CREATE TABLE _fr_mode AS "
                     "SELECT * FROM app_settings WHERE key = 'auth_mode'")
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM app_settings WHERE key = 'auth_mode'")
    try:
        yield
    finally:
        with env["app"].db() as conn:
            conn.execute("DELETE FROM users")
            conn.execute("INSERT INTO users SELECT * FROM _fr_users")
            conn.execute("DELETE FROM app_settings WHERE key = 'auth_mode'")
            conn.execute("INSERT INTO app_settings SELECT * FROM _fr_mode")
            conn.execute("DROP TABLE _fr_users")
            conn.execute("DROP TABLE _fr_mode")


def _register(env, first, last, email, password="Str0ng-Passw0rd!"):
    return env["client"].post("/api/auth/register", headers={**CSRF,
                              "Content-Type": "application/json"},
                              json={"first_name": first, "last_name": last,
                                    "email": email, "password": password})


def test_fresh_install_defaults_to_local(env, pristine, monkeypatch):
    """Container/installer artifacts set CERTHEIM_AUTH_MODE=local; a fresh DB
    must come up in local mode with the first-run register window open."""
    monkeypatch.setenv("CERTHEIM_AUTH_MODE", "local")
    info = env["client"].get("/api/auth/info").get_json()
    assert info["auth_mode"] == "local"
    assert info["first_run"] is True
    assert info["registration_open"] is True
    # the decision was seeded as an explicit setting
    assert env["app"].get_setting("auth_mode") == "local"


def test_first_registration_becomes_admin_then_window_closes(env, pristine, monkeypatch):
    monkeypatch.setenv("CERTHEIM_AUTH_MODE", "local")
    assert env["client"].get("/api/auth/info").get_json()["first_run"] is True
    r = _register(env, "First", "Admin", "first.admin@example.com")
    assert r.status_code == 200, r.get_json()
    with env["app"].db() as conn:
        row = conn.execute("SELECT is_admin, is_active FROM users "
                           "WHERE email = 'first.admin@example.com'").fetchone()
    assert row["is_admin"] == 1 and row["is_active"] == 1
    # window closed: registration reverts to the allow_registration toggle
    info = env["client"].get("/api/auth/info").get_json()
    assert info["first_run"] is False
    assert info["registration_open"] is False
    r = _register(env, "Second", "User", "second.user@example.com")
    assert r.status_code == 403
    # and the first admin can actually sign in
    r = env["client"].post("/api/auth/login", headers={**CSRF,
                           "Content-Type": "application/json"},
                           json={"username": "first.admin",
                                 "password": "Str0ng-Passw0rd!"})
    assert r.status_code == 200


def test_fresh_install_without_env_keeps_mtls(env, pristine, monkeypatch):
    """No install-time default (bare dev run / legacy harness): historical
    mtls fallback holds."""
    monkeypatch.delenv("CERTHEIM_AUTH_MODE", raising=False)
    info = env["client"].get("/api/auth/info").get_json()
    assert info["auth_mode"] == "mtls"
    assert info["registration_open"] is False


def test_populated_install_without_setting_freezes_to_mtls(env, pristine, monkeypatch):
    """Upgrade safety: accounts exist but no stored mode (pre-change install
    that relied on the implicit default) -> mtls, NEVER the env default -
    flipping a live header-auth install would lock its operators out."""
    monkeypatch.setenv("CERTHEIM_AUTH_MODE", "local")
    env["client"].get("/api/me", headers=cac(ADMIN))   # create an account (mtls path)
    with env["app"].db() as conn:
        conn.execute("DELETE FROM app_settings WHERE key = 'auth_mode'")
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
    assert env["app"].auth_mode() == "mtls"
    assert env["app"].get_setting("auth_mode") == "mtls"


def test_explicit_setting_always_wins(env, pristine, monkeypatch):
    monkeypatch.setenv("CERTHEIM_AUTH_MODE", "local")
    env["app"].set_setting("auth_mode", "mtls")
    assert env["app"].auth_mode() == "mtls"
    info = env["client"].get("/api/auth/info").get_json()
    assert info["auth_mode"] == "mtls" and info["first_run"] is False
