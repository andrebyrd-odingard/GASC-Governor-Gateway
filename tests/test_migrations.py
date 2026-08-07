"""Alembic migration tests."""
import os
import subprocess
import pytest


POSTGRES_TEST_DSN = os.environ.get("POSTGRES_TEST_DSN", "")


@pytest.mark.skipif(not POSTGRES_TEST_DSN, reason="POSTGRES_TEST_DSN not set")
def test_alembic_upgrade_head():
    """Alembic can migrate an empty database to the current schema."""
    import psycopg2
    import urllib.parse

    parsed = urllib.parse.urlparse(POSTGRES_TEST_DSN)
    dbname = parsed.path.lstrip('/')
    user = parsed.username
    password = parsed.password
    host = parsed.hostname
    port = parsed.port or 5432

    conn = psycopg2.connect(
        dbname=dbname, user=user, password=password, host=host, port=port
    )
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    conn.close()

    env = os.environ.copy()
    env["POSTGRES_DSN"] = POSTGRES_TEST_DSN
    env["PYTHONPATH"] = "."
    result = subprocess.run(
        ["alembic", "upgrade", "head"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"alembic upgrade failed: {result.stderr}"

    # Verify the schema contains expected tables
    conn = psycopg2.connect(
        dbname=dbname, user=user, password=password, host=host, port=port
    )
    with conn.cursor() as cur:
        cur.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        """)
        tables = {row[0] for row in cur.fetchall()}
    conn.close()

    expected = {
        'alembic_version',
        'calibration_runs',
        'checkpoints',
        'edges',
        'external_effects',
        'nodes',
        'quarantine_events',
        'quarantine_ledger',
        'recurrence_events',
        'reintegration_horizon',
        'repair_candidates',
        'shadow_decisions',
        'signal_attempts',
        'withdrawal_ledger',
    }
    assert expected.issubset(tables), f"Missing tables: {expected - tables}"
