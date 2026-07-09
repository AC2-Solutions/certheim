"""Support-bundle redaction tests.

The bundle is admin-downloadable and attached to tickets, so the critical
property is: no secret VALUE ever appears in it, while benign settings are
preserved. Checks operate on the DECOMPRESSED zip content (checking raw zip
bytes would be meaningless — deflate hides plaintext)."""
import io
import os
import sqlite3
import sys
import zipfile
from contextlib import contextmanager

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest

import capabilities
import support_bundle


@pytest.fixture(autouse=True)
def _stub_env_detection():
    """build() calls capabilities.all_status(), whose env detection imports the
    real db module and caches its sqlite path. In this bare-process unit test
    CERTHEIM_DB_PATH isn't set, so that would cache the default path and poison other
    test files that share the process. Pre-seed the env cache so _detect_env()
    (and its db access) never runs, then restore it."""
    saved = capabilities._env_cache
    capabilities._env_cache = {}
    try:
        yield
    finally:
        capabilities._env_cache = saved


def _harness(settings):
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        "CREATE TABLE app_settings (key TEXT PRIMARY KEY, value TEXT);"
        "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, ts REAL, actor TEXT,"
        " action TEXT, result TEXT, detail TEXT);"
        "INSERT INTO audit_log VALUES (1, 1751000000.0, 'adam', 'login', 'ok', 'x');")
    conn.executemany("INSERT INTO app_settings VALUES (?,?)", settings.items())
    conn.row_factory = sqlite3.Row

    @contextmanager
    def db():
        yield conn

    def gs(k):
        r = conn.execute("SELECT value FROM app_settings WHERE key=?", (k,)).fetchone()
        return r[0] if r else None

    return gs, db


SECRETS = {
    "cmp_shared_secret": "sup3r-secret-value",
    "sso_client_secret": "xk-9f8a7b6c5d4e",
    "acme_eab_hmac": "AAAABBBBCCCCDDDD",
    "scep_ra_key_pem": "-----BEGIN PRIVATE KEY-----MIIabc",
    "hsm_pin": "1234",
    "tsa_key_ref": "sealed:tsa",
    "ldap_bind_pw": "hunter2hunter2",
    "openbao_secret_id": "s.9f8a7b6c",
}
BENIGN = {
    "auth_mode": "local",
    "smtp_host": "mail.example.com",
    "openbao_addr": "https://openbao.example.com",
    "acme_directory_url": "https://acme.example.com/directory",
}


def _bundle(settings):
    gs, db = _harness(settings)
    data, fname = support_bundle.build(gs, db, "9.9.9", "commercial")
    z = zipfile.ZipFile(io.BytesIO(data))
    return z, fname


def test_no_secret_value_appears_anywhere():
    z, _ = _bundle({**SECRETS, **BENIGN})
    whole = b"".join(z.read(n) for n in z.namelist()).decode("utf-8", "replace")
    for name, val in SECRETS.items():
        assert val not in whole, f"secret VALUE for {name} leaked into the bundle"


def test_benign_settings_preserved():
    z, _ = _bundle({**SECRETS, **BENIGN})
    settings = z.read("settings.txt").decode()
    for key, val in BENIGN.items():
        assert f"{key} = {val}" in settings, f"{key} wrongly redacted"


def test_secret_keys_still_listed_but_masked():
    z, _ = _bundle(SECRETS)
    settings = z.read("settings.txt").decode()
    for key in SECRETS:
        assert key in settings, f"{key} should still be listed (existence is useful)"
        assert "<redacted" in settings.split(key, 1)[1].split("\n", 1)[0]


def test_bundle_has_expected_members_and_no_pii_tables():
    z, fname = _bundle(BENIGN)
    names = set(z.namelist())
    assert {"info.json", "capabilities.json", "fips.json", "schema.json",
            "settings.txt", "audit-tail.txt", "README.txt"} <= names
    assert fname.startswith("certheim-support-commercial-") and fname.endswith(".zip")
    # schema.json is COUNTS only — no row data
    schema = z.read("schema.json").decode()
    assert "app_settings" in schema and "mail.example.com" not in schema


def test_credential_shaped_value_masked_under_benign_key():
    # a JWT-shaped value under an innocuous key name must still be caught
    z, _ = _bundle({"note": "eyJhbGciOiJI" + "x" * 30})
    settings = z.read("settings.txt").decode()
    assert "eyJhbGci" not in settings
    assert "note = <redacted" in settings
