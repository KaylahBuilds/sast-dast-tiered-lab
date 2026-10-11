from contextlib import closing
import unittest

from app.lookup import MAX_EMAIL_LENGTH, make_database, safe_lookup, vulnerable_lookup


class LookupTests(unittest.TestCase):
    def setUp(self):
        self.connection = make_database()
        self.addCleanup(self.connection.close)

    def test_ordinary_vulnerable_lookup_returns_synthetic_user(self):
        rows = vulnerable_lookup(self.connection, "alice@example.test")
        self.assertEqual([row["display_name"] for row in rows], ["Alice Example"])

    def test_ordinary_safe_lookup_preserves_expected_behavior(self):
        rows = safe_lookup(
            self.connection, "alice@example.test", authorized_tenant_id="tenant-alpha"
        )
        self.assertEqual([row["id"] for row in rows], [1])

    def test_injection_expands_vulnerable_results(self):
        rows = vulnerable_lookup(self.connection, "' OR 1=1 --")
        self.assertEqual({row["id"] for row in rows}, {1, 2, 3})

    def test_same_injection_is_literal_data_in_safe_lookup(self):
        rows = safe_lookup(
            self.connection, "' OR 1=1 --", authorized_tenant_id="tenant-alpha"
        )
        self.assertEqual(rows, [])

    def test_vulnerable_lookup_omits_tenant_scope(self):
        rows = vulnerable_lookup(self.connection, "bob@example.test")
        self.assertEqual([row["tenant_id"] for row in rows], ["tenant-beta"])

    def test_safe_lookup_excludes_another_tenants_user(self):
        self.assertEqual(safe_lookup(
            self.connection, "bob@example.test", authorized_tenant_id="tenant-alpha"
        ), [])

    def test_trusted_context_can_select_its_own_tenant(self):
        rows = safe_lookup(
            self.connection, "bob@example.test", authorized_tenant_id="tenant-beta"
        )
        self.assertEqual([row["id"] for row in rows], [2])

    def test_tenant_scope_is_also_bound_as_data(self):
        rows = safe_lookup(
            self.connection, "bob@example.test", authorized_tenant_id="' OR 1=1 --"
        )
        self.assertEqual(rows, [])

    def test_missing_trusted_scope_is_rejected(self):
        for tenant in (None, "", " "):
            with self.subTest(tenant=tenant), self.assertRaises(ValueError):
                safe_lookup(self.connection, "alice@example.test", authorized_tenant_id=tenant)

    def test_both_paths_reject_unbounded_or_control_character_inputs(self):
        for value in (None, "", " ", "x" * (MAX_EMAIL_LENGTH + 1), "a\x00b", "a\nb"):
            for mode in ("safe", "vulnerable"):
                with self.subTest(mode=mode, value=value), self.assertRaises(ValueError):
                    if mode == "safe":
                        safe_lookup(self.connection, value, authorized_tenant_id="tenant-alpha")
                    else:
                        vulnerable_lookup(self.connection, value)

    def test_databases_are_fresh_and_do_not_share_writes(self):
        self.connection.execute("DELETE FROM users")
        with closing(make_database()) as second:
            self.assertEqual(second.execute("SELECT count(*) FROM users").fetchone()[0], 3)


if __name__ == "__main__":
    unittest.main()
