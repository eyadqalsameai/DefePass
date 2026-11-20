"""
DefePass - Unit Tests for Linux Shadow Auditor
Module: tests/test_linux_auditor.py

Verifies:
- Privilege checking (UID 0 vs non-root).
- Shadow file parsing (filtering comments, locked/disabled accounts, empty hashes).
- Hash algorithm identification (yescrypt, SHA-512, SHA-256, bcrypt, MD5, DES).
- Auditing logic with mock libcrypt (constant-time comparison, early exit on first match).
- Safe reporting (ONLY Username, Algorithm, Status; no plaintext credentials).
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from linux_auditor import (
    LinuxShadowAuditor,
    check_root_privilege,
    identify_hash_algorithm,
)


class MockCryptLib:
    """Mock implementation of system libcrypt for cross-platform unit testing."""

    def __init__(self, match_map=None) -> None:
        # Map of (candidate_bytes, salt_bytes) -> returned hash bytes
        self.match_map = match_map or {}
        self.call_count = 0
        self.calls = []

    def crypt(self, key: bytes, salt: bytes):
        self.call_count += 1
        self.calls.append((key, salt))
        return self.match_map.get((key, salt), b"mismatch_hash_bytes")


class TestLinuxShadowAuditor(unittest.TestCase):
    """Test suite for LinuxShadowAuditor."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)

        # Create dummy shadow file
        self.shadow_content = (
            "# Linux /etc/shadow test file\n"
            "\n"
            "root:$y$j9T$salt$root_yescrypt_hash:19000:0:99999:7:::\n"
            "daemon:*:19000:0:99999:7:::\n"  # Disabled (*)
            "bin:!:19000:0:99999:7:::\n"     # Locked (!)
            "sys:!$6$salt$locked_sha512:19000:0:99999:7:::\n" # Locked (!...)
            "empty_user::19000:0:99999:7:::\n" # Empty hash
            "alice:$6$salt_alice$alice_sha512_hash:19000:0:99999:7:::\n"
            "bob:$5$salt_bob$bob_sha256_hash:19000:0:99999:7:::\n"
            "charlie:$2b$10$salt_charlie$charlie_bcrypt_hash:19000:0:99999:7:::\n"
            "legacy_user:abC123XyZ4567:19000:0:99999:7:::\n" # 13 chars DES
        )
        self.shadow_file = self.temp_dir_path / "shadow"
        self.shadow_file.write_text(self.shadow_content, encoding="utf-8")

        # Create dummy wordlist
        self.wordlist_content = "wrongpass1\npassword\nwrongpass2\n123456\n"
        self.wordlist_file = self.temp_dir_path / "wordlist.txt"
        self.wordlist_file.write_text(self.wordlist_content, encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_privilege_check_fails_on_non_root(self) -> None:
        """Verify PermissionError is raised when UID != 0."""
        with patch("os.geteuid", return_value=1000, create=True):
            with self.assertRaises(PermissionError) as ctx:
                check_root_privilege()
            self.assertIn("sudo", str(ctx.exception))

    def test_privilege_check_passes_on_root(self) -> None:
        """Verify check_root_privilege passes when UID == 0."""
        with patch("os.geteuid", return_value=0, create=True):
            try:
                check_root_privilege()
            except PermissionError:
                self.fail("check_root_privilege raised PermissionError for root user.")

    def test_identify_hash_algorithm(self) -> None:
        """Verify correct algorithm identification based on hash prefix."""
        self.assertEqual(identify_hash_algorithm("$y$j9T$..."), "yescrypt")
        self.assertEqual(identify_hash_algorithm("$6$rounds=5000$..."), "SHA-512")
        self.assertEqual(identify_hash_algorithm("$5$salt$..."), "SHA-256")
        self.assertEqual(identify_hash_algorithm("$2b$12$..."), "bcrypt")
        self.assertEqual(identify_hash_algorithm("$2a$10$..."), "bcrypt")
        self.assertEqual(identify_hash_algorithm("$1$salt$..."), "MD5")
        self.assertEqual(identify_hash_algorithm("abC123XyZ4567"), "DES")
        self.assertEqual(identify_hash_algorithm(""), "Empty")
        self.assertEqual(identify_hash_algorithm("$unknown$hash"), "Unknown")

    def test_parse_shadow_entries_filters_locked_and_empty(self) -> None:
        """Verify locked, disabled, and empty accounts are skipped, leaving only active users."""
        auditor = LinuxShadowAuditor(
            shadow_path=self.shadow_file,
            check_root=False,
        )
        entries = auditor.parse_shadow_entries()
        usernames = [entry["username"] for entry in entries]

        # Active accounts that should be present
        self.assertIn("root", usernames)
        self.assertIn("alice", usernames)
        self.assertIn("bob", usernames)
        self.assertIn("charlie", usernames)
        self.assertIn("legacy_user", usernames)

        # Disabled / locked / empty accounts that MUST be excluded
        self.assertNotIn("daemon", usernames)
        self.assertNotIn("bin", usernames)
        self.assertNotIn("sys", usernames)
        self.assertNotIn("empty_user", usernames)

    def test_audit_accounts_detection_and_early_exit(self) -> None:
        """
        Verify:
        1. Correct matching (Weak vs Strong).
        2. Early exit upon first match (does not iterate through the rest of wordlist).
        3. Findings dictionary contains ONLY 'Username', 'Algorithm', 'Status'.
        4. Plaintext passwords NEVER exist in output.
        """
        # Set up mock crypt where 'root' matches 'password' (the 2nd candidate)
        # and 'alice' matches none.
        root_hash = b"$y$j9T$salt$root_yescrypt_hash"
        alice_hash = b"$6$salt_alice$alice_sha512_hash"

        mock_crypt = MockCryptLib(
            match_map={
                (b"password", root_hash): root_hash,
            }
        )

        # Single active user shadow file for precise call counting
        single_user_shadow = self.temp_dir_path / "shadow_single"
        single_user_shadow.write_text(
            "root:$y$j9T$salt$root_yescrypt_hash:19000:0:99999:7:::\n",
            encoding="utf-8",
        )

        auditor = LinuxShadowAuditor(
            shadow_path=single_user_shadow,
            wordlist_path=self.wordlist_file,
            check_root=False,
            crypt_lib=mock_crypt,
        )

        findings = auditor.audit_accounts()

        # Wordlist has 4 entries: wrongpass1, password, wrongpass2, 123456
        # 'password' is at index 2 (second call). With early exit, call_count should be exactly 2!
        self.assertEqual(
            mock_crypt.call_count,
            2,
            f"Expected early exit at 2 calls, but got {mock_crypt.call_count}",
        )

        self.assertEqual(len(findings), 1)
        res = findings[0]

        # Verify exact required fields
        self.assertEqual(set(res.keys()), {"Username", "Algorithm", "Status"})
        self.assertEqual(res["Username"], "root")
        self.assertEqual(res["Algorithm"], "yescrypt")
        self.assertEqual(res["Status"], "Weak / Matched")

        # Verify plaintext password is not in the object or str representation
        self.assertNotIn("password", str(res))

    def test_audit_accounts_strong_user(self) -> None:
        """Verify account with password not in wordlist reports 'Strong / Not Matched'."""
        mock_crypt = MockCryptLib(match_map={})  # No match

        single_user_shadow = self.temp_dir_path / "shadow_single"
        single_user_shadow.write_text(
            "alice:$6$salt_alice$alice_sha512_hash:19000:0:99999:7:::\n",
            encoding="utf-8",
        )

        auditor = LinuxShadowAuditor(
            shadow_path=single_user_shadow,
            wordlist_path=self.wordlist_file,
            check_root=False,
            crypt_lib=mock_crypt,
        )

        findings = auditor.audit_accounts()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Username"], "alice")
        self.assertEqual(findings[0]["Algorithm"], "SHA-512")
        self.assertEqual(findings[0]["Status"], "Strong / Not Matched")

    @patch("concurrent.futures.ProcessPoolExecutor")
    def test_audit_accounts_parallel_process_pool_executor(self, mock_executor_cls) -> None:
        """Verify ProcessPoolExecutor is used when crypt_lib=None with correct max_workers."""
        import os
        mock_executor = MagicMock()
        mock_executor_cls.return_value.__enter__.return_value = mock_executor

        mock_future = MagicMock()
        mock_future.result.return_value = {
            "Username": "alice",
            "Algorithm": "SHA-512",
            "Status": "Strong / Not Matched",
        }
        mock_executor.submit.return_value = mock_future

        single_user_shadow = self.temp_dir_path / "shadow_single"
        single_user_shadow.write_text(
            "alice:$6$salt_alice$alice_sha512_hash:19000:0:99999:7:::\n",
            encoding="utf-8",
        )

        auditor = LinuxShadowAuditor(
            shadow_path=single_user_shadow,
            wordlist_path=self.wordlist_file,
            check_root=False,
            crypt_lib=None,
        )

        findings = auditor.audit_accounts()

        expected_max_workers = min(1, os.cpu_count() or 1)
        mock_executor_cls.assert_called_once_with(max_workers=expected_max_workers)
        mock_executor.submit.assert_called_once()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Username"], "alice")


if __name__ == "__main__":
    unittest.main()
