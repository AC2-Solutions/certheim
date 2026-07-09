"""db_migrate.py - copy all data between Certheim database backends.

Moves an existing deployment's data from SQLite onto PostgreSQL (or back) without
loss - driven by the CLI `tools/certheim-db-migrate` or the admin Database page.
The target SCHEMA is created by app.init_db() (run against the target first);
this module copies the ROWS. The schema declares no foreign-key constraints, so
a straight table-by-table copy is safe (no dependency ordering needed).

A backend is named by a spec string:
  * SQLite   : "sqlite:/var/lib/certheim/jobs.db"
  * Postgres : a libpq DSN, e.g. "postgresql://user:pw@host:5432/certheim"
"""
import sqlite3

SQLITE_PREFIX = "sqlite:"
# Bookkeeping tables that must never be copied between backends.
_SKIP = {"schema_migrations"}


def is_sqlite_spec(spec):
    return spec.startswith(SQLITE_PREFIX)


def _open(spec):
    """Return (kind, conn, placeholder) for a backend spec. kind is
    'sqlite'|'postgres'; placeholder is '?' or '%s'."""
    if is_sqlite_spec(spec):
        return "sqlite", sqlite3.connect(spec[len(SQLITE_PREFIX):]), "?"
    import psycopg  # lazy
    return "postgres", psycopg.connect(spec, autocommit=False), "%s"


def _tables(kind, conn):
    if kind == "sqlite":
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'").fetchall()
        names = [r[0] for r in rows]
    else:
        cur = conn.cursor()
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
        names = [r[0] for r in cur.fetchall()]
    return [n for n in names if n not in _SKIP]


def _columns(kind, conn, table):
    if kind == "sqlite":
        return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    cur = conn.cursor()
    cur.execute("SELECT column_name FROM information_schema.columns "
                "WHERE table_name = %s ORDER BY ordinal_position", (table,))
    return [r[0] for r in cur.fetchall()]


def _rows(kind, conn, sql):
    if kind == "sqlite":
        return conn.execute(sql).fetchall()
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()


def copy_database(source_spec, target_spec, log=print, wipe_target=False):
    """Copy every table's rows from source to target (schema must already exist
    on the target). Returns {table: rows_copied}. Inserts use ON CONFLICT DO
    NOTHING so a re-run is idempotent; pass wipe_target=True to DELETE target
    rows first for an exact mirror. On a Postgres target, identity sequences are
    advanced past the copied ids so later inserts don't collide."""
    skind, sconn, _ = _open(source_spec)
    tkind, tconn, ph = _open(target_spec)
    counts = {}
    try:
        for t in _tables(skind, sconn):
            scols = _columns(skind, sconn, t)
            tcols = set(_columns(tkind, tconn, t))
            cols = [c for c in scols if c in tcols]  # copy only shared columns
            if not cols:
                continue
            collist = ", ".join('"' + c + '"' for c in cols)
            rows = _rows(skind, sconn, f"SELECT {collist} FROM {t}")
            tcur = tconn.cursor()
            if wipe_target:
                tcur.execute(f"DELETE FROM {t}")
            ins = (f"INSERT INTO {t} ({collist}) "
                   f"VALUES ({', '.join([ph] * len(cols))}) ON CONFLICT DO NOTHING")
            for row in rows:
                tcur.execute(ins, tuple(row))
            tconn.commit()
            if tkind == "postgres" and "id" in cols and rows:
                # advance the IDENTITY sequence (no-op if 'id' isn't serial)
                try:
                    tcur.execute(
                        "SELECT setval(pg_get_serial_sequence(%s, 'id'), "
                        f"(SELECT MAX(id) FROM {t}))", (t,))
                    tconn.commit()
                except Exception:
                    tconn.rollback()
            counts[t] = len(rows)
            log(f"  {t}: {len(rows)} rows")
        return counts
    finally:
        sconn.close()
        tconn.close()


def current_source_spec():
    """The spec for the deployment's CURRENT database, from the live config."""
    import db as dbx
    if dbx.is_postgres():
        return dbx.dsn()
    return SQLITE_PREFIX + dbx.sqlite_path()


def ensure_target_schema(target_spec):
    """Create the Certheim schema on the target by pointing the app's config at
    it and running init_db(). Restores the prior config afterward."""
    import db as dbx
    import app
    saved = (dbx._backend, dbx._pg_dsn, dbx._sqlite_path)
    try:
        dbx._backend = dbx._pg_dsn = dbx._sqlite_path = None
        if is_sqlite_spec(target_spec):
            dbx.configure(backend="sqlite", sqlite_path=target_spec[len(SQLITE_PREFIX):])
        else:
            dbx.configure(backend="postgres", dsn=target_spec)
        app.init_db()
    finally:
        dbx._backend, dbx._pg_dsn, dbx._sqlite_path = saved
