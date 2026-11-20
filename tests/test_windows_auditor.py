"""
DefePass - Unit Tests for Windows SAM Auditor
Module: tests/test_windows_auditor.py

Verifies:
- Privilege check (IsUserAnAdmin == 0 vs != 0).
- NTLM hash computation using PyCryptodome MD4 (OpenSSL 3 safe).
- Pwdump/secretsdump parsing into memory structures.
- Auditing logic (single-pass wordlist stream, early exit, hash-to-user dict mapping).
- Temporary hive deletion in finally block.
- Safe reporting (ONLY Username, Algorithm='NTLM', Status).
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from windows_auditor import (
    WindowsSamAuditor,
    check_admin_privilege,
    compute_ntlm_hash,
)


class TestWindowsSamAuditor(unittest.TestCase):
    """Test suite for WindowsSamAuditor."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)

        # Wordlist containing 'password' and 'Password123!'
        self.wordlist_content = "wrongpass\npassword\nPassword123!\nsunshine\n"
        self.wordlist_file = self.temp_dir_path / "wordlist.txt"
        self.wordlist_file.write_text(self.wordlist_content, encoding="utf-8")

        # Known NTLM hashes:
        # 'password'     -> 8846f7eaee8fb117ad06bdd830b7586c
        # 'Password123!' -> 2b576acbe6bcfda7294d6bd18041b8fe
        # 'Unbreakable'  -> 6b27e8a946b21617ab6f671239cf20dc (not in wordlist)
        self.hash_dump_content = (
            "# Exported NTLM hashes\n"
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "UserWeak:1001:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::\n"
            "UserStrong:1002:aad3b435b51404eeaad3b435b51404ee:6b27e8a946b21617ab6f671239cf20dc:::\n"
            "DisabledGuest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        )
        self.hash_file = self.temp_dir_path / "hashes.txt"
        self.hash_file.write_text(self.hash_dump_content, encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_compute_ntlm_hash_known_vectors(self) -> None:
        """Verify NTLM hash matches standard reference vectors using PyCryptodome MD4."""
        # Empty string
        self.assertEqual(compute_ntlm_hash(""), "31d6cfe0d16ae931b73c59d7e0c089c0")
        # 'password'
        self.assertEqual(compute_ntlm_hash("password"), "8846f7eaee8fb117ad06bdd830b7586c")
        # 'Password123!'
        self.assertEqual(compute_ntlm_hash("Password123!"), "2b576acbe6bcfda7294d6bd18041b8fe")

    def test_check_admin_privilege_non_admin(self) -> None:
        """Verify PermissionError raised when not running as Administrator."""
        with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=0, create=True):
            with self.assertRaises(PermissionError) as ctx:
                check_admin_privilege()
            self.assertIn("Administrator", str(ctx.exception))

    def test_check_admin_privilege_admin(self) -> None:
        """Verify check passes when running as Administrator."""
        with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1, create=True):
            try:
                check_admin_privilege()
            except PermissionError:
                self.fail("check_admin_privilege raised PermissionError for Admin.")

    def test_parse_hash_dump(self) -> None:
        """Verify parsing of exported pwdump / secretsdump lines into memory."""
        auditor = WindowsSamAuditor(
            hash_file_path=self.hash_file,
            check_admin=False,
        )
        accounts = auditor.extract_ntlm_hashes()
        self.assertEqual(len(accounts), 4)

        usernames = [a["username"] for a in accounts]
        self.assertIn("Administrator", usernames)
        self.assertIn("UserWeak", usernames)
        self.assertIn("UserStrong", usernames)
        self.assertIn("DisabledGuest", usernames)

    def test_audit_accounts_detection_and_safe_reporting(self) -> None:
        """
        Verify:
        1. Correct detection of weak vs strong passwords.
        2. Output findings contain ONLY Username, Algorithm, and Status.
        3. Plaintext passwords NEVER exist in output.
        """
        auditor = WindowsSamAuditor(
            hash_file_path=self.hash_file,
            wordlist_path=self.wordlist_file,
            check_admin=False,
        )
        findings = auditor.audit_accounts()

        self.assertEqual(len(findings), 4)
        findings_map = {f["Username"]: f for f in findings}

        # Administrator ('password' in wordlist) -> Weak / Matched
        admin_res = findings_map["Administrator"]
        self.assertEqual(admin_res["Algorithm"], "NTLM")
        self.assertEqual(admin_res["Status"], "Weak / Matched")

        # UserWeak ('Password123!' in wordlist) -> Weak / Matched
        weak_res = findings_map["UserWeak"]
        self.assertEqual(weak_res["Algorithm"], "NTLM")
        self.assertEqual(weak_res["Status"], "Weak / Matched")

        # UserStrong (not in wordlist) -> Strong / Not Matched
        strong_res = findings_map["UserStrong"]
        self.assertEqual(strong_res["Algorithm"], "NTLM")
        self.assertEqual(strong_res["Status"], "Strong / Not Matched")

        # DisabledGuest (empty password hash 31d6cfe0d16ae931b73c59d7e0c089c0) -> Weak / Empty Password
        guest_res = findings_map["DisabledGuest"]
        self.assertEqual(guest_res["Algorithm"], "NTLM")
        self.assertEqual(guest_res["Status"], "Weak / Empty Password")

        # Verify exact dictionary structure and zero plaintext leaks
        for item in findings:
            self.assertEqual(set(item.keys()), {"Username", "Algorithm", "Status"})
            clean_str = (
                str(item)
                .lower()
                .replace("'status': 'weak / matched'", "")
                .replace("'status': 'weak / empty password'", "")
            )
            self.assertNotIn("password", clean_str)
            self.assertNotIn("password123!", clean_str)

    def test_temporary_hives_deleted_in_finally_block(self) -> None:
        """
        Verify that exported hive files are deleted in the finally block
        even if an error occurs during extraction.
        """
        dummy_sam = self.temp_dir_path / "sam.hive"
        dummy_system = self.temp_dir_path / "system.hive"
        dummy_sam.write_bytes(b"dummy_sam_content")
        dummy_system.write_bytes(b"dummy_system_content")

        auditor = WindowsSamAuditor(check_admin=False)

        # Mock export_live_hives to return our dummy hives
        # and mock _extract_from_hives to raise a simulated error
        with patch("windows_auditor.export_live_hives", return_value=(dummy_sam, dummy_system)):
            with patch.object(auditor, "_extract_from_hives", side_effect=RuntimeError("Simulated extraction crash")):
                with self.assertRaises(RuntimeError):
                    auditor.extract_ntlm_hashes()

        # Both hive files MUST be deleted in the finally block!
        self.assertFalse(dummy_sam.exists(), "sam.hive was not deleted in finally block!")
        self.assertFalse(dummy_system.exists(), "system.hive was not deleted in finally block!")


if __name__ == "__main__":
    unittest.main()
