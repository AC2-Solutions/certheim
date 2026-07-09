"""db.py - pluggable database backend: SQLite (default) or PostgreSQL.

The whole app is written against the stdlib sqlite3 API:

    with db() as conn:
        row = conn.execute("SELECT ... WHERE x = ?", (x,)).fetchone()
        row["col"]  / row[0]            # both work (sqlite3.Row)

This module lets those *exact* call sites also run on PostgreSQL, by wrapping
psycopg (v3) in a thin compatibility shim so the 350+ query sites don't change:

  * placeholders : '?'  -> '%s'  (and literal '%' -> '%%') on Postgres
  * PRAGMA       : no-op on Postgres (WAL / foreign_keys / busy_timeout etc.)
  * Row          : hybrid mapping+sequence, so row["x"], row[0], dict(row) work
  * rowcount     : exposed on both
  * AUTOINCREMENT / REAL in DDL: translated per dialect by ddl()
  * table_columns(): replaces `PRAGMA table_info` for the idempotent migrations
  * insert_returning_id(): replaces cursor.lastrowid for SERIAL/IDENTITY pkeys

Backend selection (priority): an explicit configure() call from the app (which
may apply an admin setting), else the environment:

    CSR_DB_URL = postgresql://user:pass@host:5432/certinel   -> postgres
    CSR_DB_BACKEND = sqlite | postgres                        -> explicit
    (default)                                                 -> sqlite at CSR_DB_PATH

psycopg is imported lazily, so a SQLite-only install needs no driver and the
offline wheelhouse stays slim.
"""
import os
import envcompat
import sqlite3

# Backend-agnostic exception classes. Code does `except dbx.IntegrityError:` so a
# unique-constraint violation is caught on either backend. psycopg's classes are
# added lazily if/when the postgres driver is imported (see _register_pg_errors).
IntegrityError = (sqlite3.IntegrityError,)
OperationalError = (sqlite3.OperationalError,)
DatabaseError = (sqlite3.DatabaseError,)


def _register_pg_errors():
    global IntegrityError, OperationalError, DatabaseError
    try:
        import psycopg
        IntegrityError = (sqlite3.IntegrityError, psycopg.IntegrityError)
        OperationalError = (sqlite3.OperationalError, psycopg.OperationalError)
        DatabaseError = (sqlite3.DatabaseError, psycopg.DatabaseError)
    except Exception:
        pass


# Resolved configuration (set by configure(), else derived from the environment
# on first use). backend is "sqlite" | "postgres".
_backend = None
_pg_dsn = None
_sqlite_path = None


def configure(backend=None, dsn=None, sqlite_path=None):
    """Pin the backend explicitly (the app calls this at startup after resolving
    env + any admin override). Any argument left None falls back to env/default."""
    global _backend, _pg_dsn, _sqlite_path
    if backend:
        _backend = backend
    if dsn:
        _pg_dsn = dsn
    if sqlite_path:
        _sqlite_path = sqlite_path


def _resolve():
    global _backend, _pg_dsn, _sqlite_path
    if _backend:
        return
    url = envcompat.getenv("CSR_DB_URL", "").strip()
    be = envcompat.getenv("CSR_DB_BACKEND", "").strip().lower()
    if url and not be:
        be = "postgres"
    if be in ("postgres", "postgresql"):
        _backend = "postgres"
        _pg_dsn = _pg_dsn or url or _dsn_from_parts()
    else:
        _backend = "sqlite"
    if not _sqlite_path:
        _sqlite_path = envcompat.getenv("CSR_DB_PATH", "/var/lib/certinel/jobs.db")


def _dsn_from_parts():
    """Build a libpq DSN from discrete CSR_DB_* vars (alternative to CSR_DB_URL)."""
    parts = {
        "host": envcompat.getenv("CSR_DB_HOST", "").strip(),
        "port": envcompat.getenv("CSR_DB_PORT", "").strip(),
        "dbname": envcompat.getenv("CSR_DB_NAME", "").strip(),
        "user": envcompat.getenv("CSR_DB_USER", "").strip(),
        "password": envcompat.getenv("CSR_DB_PASSWORD", "").strip(),
        "sslmode": envcompat.getenv("CSR_DB_SSLMODE", "").strip(),
    }
    return " ".join(f"{k}={v}" for k, v in parts.items() if v)


def backend():
    """'sqlite' or 'postgres'."""
    _resolve()
    return _backend


def is_postgres():
    return backend() == "postgres"


def sqlite_path():
    _resolve()
    return _sqlite_path


def dsn():
    _resolve()
    return _pg_dsn


# --- connection factory -----------------------------------------------------
def connect():
    """Return a connection that quacks like sqlite3.Connection regardless of
    backend. Callers use `with db() as conn:` (the app's context manager) which
    handles commit/rollback/close."""
    if is_postgres():
        return _PgConn(dsn())
    conn = sqlite3.connect(sqlite_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


# --- DDL + schema helpers (dialect-aware) -----------------------------------
def ddl(sql):
    """Translate a SQLite-flavored DDL string to the active dialect. SQLite is
    returned unchanged; Postgres gets AUTOINCREMENT integer pkeys mapped to
    IDENTITY and REAL (epoch floats) widened to DOUBLE PRECISION."""
    if not is_postgres():
        return sql
    import re
    out = sql
    # `INTEGER PRIMARY KEY AUTOINCREMENT` -> identity pkey
    out = re.sub(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
                 "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY",
                 out, flags=re.IGNORECASE)
    out = re.sub(r"\bAUTOINCREMENT\b", "", out, flags=re.IGNORECASE)
    # epoch timestamps are stored as floats; SQLite REAL -> PG double precision.
    out = re.sub(r"\bREAL\b", "DOUBLE PRECISION", out, flags=re.IGNORECASE)
    return out


def prepare(conn):
    """Backend-specific one-time setup, run at the very start of init_db().
    On Postgres, create a case-insensitive `nocase` collation so the app's
    SQLite-style `ORDER BY x COLLATE NOCASE` / `WHERE name = ? COLLATE NOCASE`
    resolve unchanged. ICU ships with RHEL/Alma Postgres; if it's somehow
    absent the CREATE is a no-op and those queries would error (caught by CI)."""
    if not is_postgres():
        return
    try:
        conn.execute(
            "CREATE COLLATION IF NOT EXISTS nocase "
            "(provider = icu, locale = 'und-u-ks-level2', deterministic = false)")
    except Exception:
        pass


def table_columns(conn, table):
    """Set of existing column names for `table` (drives the idempotent
    ADD COLUMN migrations). Replaces `PRAGMA table_info`."""
    if is_postgres():
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = ?", (table,)).fetchall()
        return {r[0] for r in rows}
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def insert_returning_id(conn, sql, params=()):
    """Run an INSERT and return the new integer primary key (the table's `id`).
    Replaces `cursor.lastrowid`, which Postgres doesn't provide."""
    if is_postgres():
        cur = conn.execute(sql.rstrip().rstrip(";") + " RETURNING id", params)
        return cur.fetchone()[0]
    return conn.execute(sql, params).lastrowid


class _SchemaConn:
    """Connection proxy that runs every statement through ddl() - used only by
    init_db() so the SQLite-flavored CREATE/ALTER statements apply on either
    backend without editing each line. PRAGMA/CREATE INDEX pass through ddl()
    unchanged (no AUTOINCREMENT/REAL tokens to rewrite)."""
    def __init__(self, conn):
        self._c = conn

    def execute(self, sql, params=()):
        return self._c.execute(ddl(sql), params)

    def commit(self):
        self._c.commit()

    def rollback(self):
        self._c.rollback()

    def close(self):
        self._c.close()


def schema_connect():
    """A connect() whose statements are dialect-translated; for init_db()."""
    return _SchemaConn(connect())


# --- Postgres compatibility shim --------------------------------------------
def _translate(sql):
    """SQLite '?' placeholders -> psycopg '%s'. Literal '%' must be doubled for
    psycopg's printf-style binding; do that first so the '%s' we insert is left
    intact."""
    return sql.replace("%", "%%").replace("?", "%s")


class Row:
    """Hybrid row: supports row[0], row['col'], dict(row), 'col' in row, len()."""
    __slots__ = ("_cols", "_vals", "_idx")

    def __init__(self, cols, vals):
        self._cols = cols
        self._vals = vals
        self._idx = None

    def _index(self):
        if self._idx is None:
            self._idx = {c: i for i, c in enumerate(self._cols)}
        return self._idx

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._vals[key]
        return self._vals[self._index()[key]]

    def get(self, key, default=None):
        i = self._index().get(key)
        return self._vals[i] if i is not None else default

    def keys(self):
        return list(self._cols)

    def __contains__(self, key):
        return key in self._index()

    def __iter__(self):
        return iter(self._vals)

    def __len__(self):
        return len(self._vals)


class _PgResult:
    """Wraps a psycopg cursor to mimic the object sqlite3 returns from execute()."""
    def __init__(self, cur):
        self._cur = cur
        self._cols = [d.name for d in cur.description] if cur.description else []

    def fetchone(self):
        r = self._cur.fetchone()
        return Row(self._cols, r) if r is not None else None

    def fetchall(self):
        return [Row(self._cols, r) for r in self._cur.fetchall()]

    def __iter__(self):
        for r in self._cur:
            yield Row(self._cols, r)

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def lastrowid(self):  # PG has no lastrowid; use insert_returning_id() instead
        return None


class _Noop:
    """Return value for no-op PRAGMA statements on Postgres."""
    rowcount = 0
    lastrowid = None

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def __iter__(self):
        return iter(())


class _PgConn:
    """Minimal sqlite3.Connection look-alike backed by psycopg (v3)."""
    def __init__(self, conn_dsn):
        import psycopg  # lazy: only needed on postgres installs
        if not conn_dsn:
            raise RuntimeError("postgres backend selected but no DSN configured "
                               "(set CSR_DB_URL or the CSR_DB_* parts)")
        _register_pg_errors()
        self._conn = psycopg.connect(conn_dsn, autocommit=False)

    def execute(self, sql, params=()):
        if sql.lstrip()[:6].upper() == "PRAGMA":
            return _Noop()
        cur = self._conn.cursor()
        cur.execute(_translate(sql), tuple(params))
        return _PgResult(cur)

    def executemany(self, sql, seq):
        cur = self._conn.cursor()
        cur.executemany(_translate(sql), [tuple(p) for p in seq])
        return _PgResult(cur)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()
