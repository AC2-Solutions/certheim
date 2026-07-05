"""Disaster-recovery drill — proves the procedures in
docs/operations/backup-restore-upgrade.md actually work.

Three round-trips:
  1. SQLite backup -> restore preserves every row (the online .backup path).
  2. Schema self-migration adds new columns/tables to an OLD database without
     destroying existing data (the N->N+1 upgrade path).
  3. Sealed-keystore ESCROW: export a bundle, wipe the store, import into a fresh
     store, and confirm the Local CA still signs (the "don't lose your CA" path).
     Commercial-only; skips where sealed_store/local_ca are absent.

Dependency-free (sqlite3 + openssl + the app's own db_migrate). Run:
    pytest tests/test_dr_drill.py -q
"""
import os
import sqlite3
import subprocess
import sys
from contextlib import contextmanager

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest

BACKEND = os.path.join(os.path.dirname(__file__), "..", "backend")


# --- 1. backup -> restore preserves rows ------------------------------------
def test_sqlite_backup_restore_preserves_rows(tmp_path):
    src = str(tmp_path / "jobs.db")
    bak = str(tmp_path / "jobs.db.bak")
    c = sqlite3.connect(src)
    c.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY, target_host TEXT, status TEXT)")
    c.executemany("INSERT INTO jobs VALUES (?,?,?)",
                  [(f"job{i}", f"h{i}.example.com", "pending") for i in range(50)])
    c.commit()
    # online .backup (what certinel-backup uses) — WAL-consistent, no downtime
    dst = sqlite3.connect(bak)
    with dst:
        c.backup(dst)
    dst.close()
    c.close()
    r = sqlite3.connect(bak)
    assert r.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 50
    assert r.execute("SELECT target_host FROM jobs WHERE id='job7'").fetchone()[0] == "h7.example.com"
    r.close()


# --- 2. schema self-migration is additive + non-destructive -----------------
def test_schema_migration_is_forward_and_nondestructive(tmp_path):
    """Seed an intentionally OLD jobs table (missing recent columns) + a row,
    run the app's schema init against it (the upgrade path), and assert the new
    columns appear while the old row survives unchanged."""
    dbfile = str(tmp_path / "old.db")
    c = sqlite3.connect(dbfile)
    # A realistic historical 'jobs' shape: the base schema BEFORE the
    # `requester_email` migration was added (that column is applied by a guarded
    # ALTER on startup, so an old DB legitimately lacks it).
    c.execute("""CREATE TABLE jobs (
        id TEXT PRIMARY KEY, created_at REAL NOT NULL, requester_dn TEXT NOT NULL,
        requester_serial TEXT, requester_ip TEXT, target_host TEXT NOT NULL,
        sans_json TEXT NOT NULL DEFAULT '[]', csr_pem TEXT NOT NULL, cert_pem TEXT,
        status TEXT NOT NULL, completed_at REAL, completed_by_dn TEXT, error TEXT,
        has_local_key INTEGER NOT NULL DEFAULT 0, local_key_name TEXT,
        source TEXT NOT NULL DEFAULT 'rhel')""")
    c.execute("INSERT INTO jobs (id, created_at, requester_dn, target_host, csr_pem, status) "
              "VALUES ('legacy-1', 1751000000.0, 'CN=old', 'legacy.example.com', 'x', 'pending')")
    c.commit(); c.close()

    # Run the real startup migration in a SUBPROCESS. This is faithful (it's how
    # the service migrates on boot) AND keeps `app`/`db` out of this test
    # session — importing them here would bind the app's cached DB globals to
    # this temp file and poison a later session-scoped fixture (e.g. smoke).
    env = dict(os.environ, CSR_DB_PATH=dbfile,
               CERTINEL_ENV=str(tmp_path / "absent.env"))
    r = subprocess.run(
        [sys.executable, "-c",
         "import db_migrate; db_migrate.ensure_target_schema('sqlite://' + __import__('os').environ['CSR_DB_PATH'])"],
        cwd=BACKEND, env=env, capture_output=True, text=True)
    assert r.returncode == 0, f"migration failed: {r.stderr}"

    c = sqlite3.connect(dbfile)
    cols = {r[1] for r in c.execute("PRAGMA table_info(jobs)")}
    # columns added by the guarded ALTER TABLE ADD COLUMN migrations
    assert {"requester_email", "auto_renewed_at"} <= cols, "migration didn't add columns"
    # the pre-existing row is intact
    row = c.execute("SELECT target_host, status FROM jobs WHERE id='legacy-1'").fetchone()
    assert row == ("legacy.example.com", "pending"), "existing data mutated by migration"
    # new tables exist too
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"app_settings", "audit_log", "cert_templates"} <= tables
    c.close()


# --- 3. sealed-keystore escrow: export -> fresh store -> Local CA still signs -
class _StubSealedDB:
    """Two independent in-memory sealed stores sharing the sealed_store module,
    swapped via configure() — models 'old instance' vs 'fresh instance'."""
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row


def _openssl(*a, stdin=None):
    return subprocess.run(["openssl", *a], input=stdin, capture_output=True, text=True)


def test_sealed_keystore_escrow_roundtrip(tmp_path, monkeypatch):
    sealed_store = pytest.importorskip("sealed_store")
    local_ca = pytest.importorskip("local_ca")

    settings_a, settings_b = {}, {}
    runtime = str(tmp_path / "rt")
    os.makedirs(runtime, exist_ok=True)
    monkeypatch.setenv("CERTINEL_RUNTIME_DIR", runtime)

    def mk(store_db, settings):
        @contextmanager
        def _db():
            yield store_db
        return _db, (lambda k: settings.get(k)), (lambda k, v: settings.__setitem__(k, v))

    # --- ORIGINAL instance: init keystore, make a Local CA, export escrow ---
    a = sqlite3.connect(":memory:"); a.row_factory = sqlite3.Row
    dbA, getA, setA = mk(a, settings_a)
    sealed_store.configure(get_setting=getA, set_setting=setA, db=dbA,
                           log_event=lambda *x, **k: None)
    sealed_store.init_passphrase("orig-passphrase-123")
    local_ca.configure(get_setting=getA, set_setting=setA, db=dbA,
                       log_event=lambda *x, **k: None, sealed_store=sealed_store)
    local_ca.generate_ca(cn="DR Drill Root")
    assert local_ca.status()["key_present"]
    escrow = sealed_store.export_backup("escrow-passphrase-abc")   # the offline bundle
    ca_cert = local_ca.ca_cert_pem()

    # --- FRESH instance (host lost): new keystore, import escrow, CA signs ---
    b = sqlite3.connect(":memory:"); b.row_factory = sqlite3.Row
    dbB, getB, setB = mk(b, settings_b)
    # carry the *encrypted* CA cert setting across (as a DB restore would)
    settings_b["local_ca_cert_pem"] = ca_cert
    settings_b["local_ca_algo"] = settings_a.get("local_ca_algo", "classic")
    sealed_store.configure(get_setting=getB, set_setting=setB, db=dbB,
                           log_event=lambda *x, **k: None)
    sealed_store.init_passphrase("brand-new-passphrase-xyz")       # different material!
    sealed_store.import_backup(escrow, "escrow-passphrase-abc", overwrite=True)
    local_ca.configure(get_setting=getB, set_setting=setB, db=dbB,
                       log_event=lambda *x, **k: None, sealed_store=sealed_store)

    # the recovered Local CA signs a CSR, and the leaf chains to the original CA
    key, csr = str(tmp_path / "l.key"), str(tmp_path / "l.csr")
    _openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=recovered.example.com")
    cert_pem, chain = local_ca.sign_csr(open(csr).read(), None)
    caf, lf = str(tmp_path / "ca.crt"), str(tmp_path / "leaf.crt")
    open(caf, "w").write(chain); open(lf, "w").write(cert_pem)
    assert _openssl("verify", "-CAfile", caf, lf).returncode == 0, "recovered CA cannot sign"
