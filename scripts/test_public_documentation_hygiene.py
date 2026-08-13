from __future__ import annotations

import ipaddress
import unittest

from scripts.check_public_documentation_hygiene import inspect_text


class PublicDocumentationHygieneTests(unittest.TestCase):
    def test_rejects_global_address_without_echoing_value(self) -> None:
        value = str(ipaddress.ip_address(0x08080808))
        violations = inspect_text("docs/public.md", f"endpoint = {value}")

        self.assertEqual([item.category for item in violations], ["non-documentation IPv4 address"])
        self.assertNotIn(value, repr(violations))

    def test_rejects_private_address(self) -> None:
        value = str(ipaddress.ip_address(0x0A000001))

        self.assertEqual(len(inspect_text("docs/public.md", value)), 1)

    def test_allows_loopback_and_documentation_addresses(self) -> None:
        text = "\n".join(
            str(ipaddress.ip_address(value))
            for value in (0x7F000001, 0xC0000201, 0xC6336401, 0xCB007101)
        )

        self.assertEqual(inspect_text("docs/example.md", text), [])

    def test_rejects_privileged_ssh_target_without_echoing_target(self) -> None:
        target = "root@" + "operator-host"
        violations = inspect_text("docs/public.md", f"connect to {target}")

        self.assertEqual([item.category for item in violations], ["privileged SSH target"])
        self.assertNotIn(target, repr(violations))

    def test_rejects_ssh_alias_command_without_echoing_alias(self) -> None:
        alias = "operator-" + "node"
        violations = inspect_text("docs/public.md", f"ssh {alias}")

        self.assertEqual(
            [item.category for item in violations], ["operational SSH alias command"]
        )
        self.assertNotIn(alias, repr(violations))

    def test_rejects_authentication_diagnostic(self) -> None:
        diagnostic = "Permission denied" + " (publickey)"
        violations = inspect_text("docs/public.md", diagnostic)

        self.assertEqual([item.category for item in violations], ["authentication diagnostic"])
        self.assertNotIn(diagnostic, repr(violations))

    def test_rejects_jump_host_topology(self) -> None:
        marker = "Proxy" + "Jump"

        self.assertEqual(
            [item.category for item in inspect_text("docs/public.md", marker)],
            ["jump-host topology"],
        )

    def test_rejects_host_identifier_and_privileged_account_context(self) -> None:
        host_context = "host `" + "operator-node" + "`"
        account_context = "user `" + "root" + "`"
        violations = inspect_text(
            "docs/public.md", f"{host_context}\n{account_context}"
        )

        self.assertEqual(
            [item.category for item in violations],
            ["operational host identifier", "privileged account context"],
        )
        self.assertNotIn(host_context, repr(violations))
        self.assertNotIn(account_context, repr(violations))

    def test_rejects_direct_host_reference(self) -> None:
        host = "Operator" + "Node"
        violations = inspect_text("docs/public.md", f"direct {host} PATH")

        self.assertEqual([item.category for item in violations], ["direct host reference"])
        self.assertNotIn(host, repr(violations))

    def test_rejects_mixed_allowed_and_disallowed_addresses(self) -> None:
        allowed = str(ipaddress.ip_address(0x7F000001))
        blocked = str(ipaddress.ip_address(0x0A000001))

        self.assertEqual(len(inspect_text("docs/public.md", f"{allowed} {blocked}")), 1)

    def test_ignores_non_address_version_text(self) -> None:
        self.assertEqual(inspect_text("docs/public.md", "release 2.0.1"), [])


if __name__ == "__main__":
    unittest.main()
