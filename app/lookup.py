"""Paired unsafe/safe SQLite lookups using synthetic, disposable data only.

The unsafe fixture is intentionally vulnerable to SQL injection AND omits tenant
scope. The safe lookup binds values and takes a trusted context from its caller.
Neither function implements login, identity verification, or real authorization.
"""

import sqlite3


SIMULATED_TENANT = "tenant-alpha"
MAX_EMAIL_LENGTH = 128


def validate_email(email: str) -> str:
    """Bound input without hiding the injection lesson behind a pattern filter."""
    if not isinstance(email, str) or not email.strip():
        raise ValueError("A non-empty email lookup value is required")
    if len(email) > MAX_EMAIL_LENGTH:
        raise ValueError("The email lookup value is too long")
    if any(ord(character) < 32 or ord(character) == 127 for character in email):
        raise ValueError("Control characters are not allowed")
    return email


def make_database() -> sqlite3.Connection:
    """Return a fresh in-memory database. No disk, credentials, or real users."""
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE users "
        "(id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, "
        "email TEXT NOT NULL, display_name TEXT NOT NULL)"
    )
    connection.executemany(
        "INSERT INTO users (id, tenant_id, email, display_name) VALUES (?, ?, ?, ?)",
        [
            (1, "tenant-alpha", "alice@example.test", "Alice Example"),
            (2, "tenant-beta", "bob@example.test", "Bob Example"),
            (3, "tenant-alpha", "carol@example.test", "Carol Example"),
        ],
    )
    connection.commit()
    return connection


def vulnerable_lookup(connection: sqlite3.Connection, email: str) -> list[dict]:
    """INTENTIONALLY UNSAFE: scanner fixture, never copy into real software."""
    validate_email(email)
    # Deliberate SAST finding: untrusted data is concatenated into SQL.
    # Deliberate authorization flaw: no tenant constraint is present.
    rows = connection.execute(
        "SELECT id, tenant_id, email, display_name FROM users WHERE email = '"
        + email
        + "'"
    ).fetchall()
    return [dict(row) for row in rows]


def safe_lookup(
    connection: sqlite3.Connection,
    email: str,
    *,
    authorized_tenant_id: str,
) -> list[dict]:
    """Bind both inputs; tenant scope must come from a trusted caller context.

    In the HTTP fixture that context is a fixed server-owned simulation, not a
    query parameter, header, session, or verified identity. This is not a complete
    production authorization design.
    """
    validate_email(email)
    if not isinstance(authorized_tenant_id, str) or not authorized_tenant_id.strip():
        raise ValueError("Trusted tenant scope is required")
    rows = connection.execute(
        "SELECT id, tenant_id, email, display_name FROM users "
        "WHERE tenant_id = ? AND email = ? ORDER BY id",
        (authorized_tenant_id, email),
    ).fetchall()
    return [dict(row) for row in rows]
