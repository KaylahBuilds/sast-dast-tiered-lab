"""Annotated scanner inputs; functions are not executed as application tests.

Matching is a review signal, not a verdict that an exploit exists. Only direct
construction inside execute() is covered. This is intentionally not a taint rule.
"""


def direct_concatenation(connection, email):
    # ruleid: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users WHERE email = '" + email + "'")


def direct_percent_formatting(connection, email):
    # ruleid: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users WHERE email = '%s'" % email)


def direct_percent_tuple(connection, tenant, email):
    # ruleid: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users WHERE tenant_id = '%s' AND email = '%s'" % (tenant, email))


def direct_format_call(connection, email):
    # ruleid: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users WHERE email = '{}'".format(email))


def still_constructs_sql_with_other_bound_values(connection, email, tenant):
    # ruleid: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users WHERE email = '" + email + "' AND tenant_id = ?", (tenant,))


def trusted_literal_fragments_candidate(connection):
    """Expected finding, but not injection: a deliberate triage false positive."""
    # ruleid: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users " + "WHERE id = 1")


def bound_values(connection, authorized_tenant_id, email):
    # ok: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users WHERE tenant_id = ? AND email = ?", (authorized_tenant_id, email))


def literal_statement(connection):
    # ok: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users WHERE id = 1")


def adjacent_literal_fragments(connection):
    # ok: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users " "WHERE id = 1")


def formatted_data_bound_separately(connection, email):
    # ok: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users WHERE email = ?", ("{}".format(email),))


def unrelated_formatting(email):
    # ok: lab-python-sql-string-construction
    print("Requested email: {}".format(email))


def parameterization_without_authorization(connection, email):
    """No syntactic finding does not establish tenant isolation."""
    # ok: lab-python-sql-string-construction
    connection.execute("SELECT id FROM users WHERE email = ?", (email,))
