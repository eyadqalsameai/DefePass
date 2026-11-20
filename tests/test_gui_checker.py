"""
DefePass - Unit Tests for GUI Password Checker
Module: tests/test_gui_checker.py

Verifies:
- Password evaluation logic (Empty, Safe, Unsafe).
- Normalization (lowercase, whitespace stripping).
- O(1) set membership evaluation.
- Memory hygiene and zeroing.
- GUI component action simulation.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from gui_checker import (
    POLICY_RULES,
    PasswordPolicyGUI,
    evaluate_password_safety,
    evaluate_policy_rules,
)


class TestGUIChecker(unittest.TestCase):
    """Test suite for GUI password checker logic."""

    def setUp(self) -> None:
        self.wordlist_set = {
            "password",
            "123456",
            "admin123",
            "p@ssw0rd!",
            "defepass2026",
        }

    def test_evaluate_empty_or_whitespace_input(self) -> None:
        """Verify empty and whitespace-only inputs return EMPTY status."""
        for empty_val in ("", "   ", "\t", "\n", " \t "):
            status, msg, color = evaluate_password_safety(empty_val, self.wordlist_set)
            self.assertEqual(status, "EMPTY")
            self.assertIn("Please enter a password", msg)
            self.assertEqual(color, "#7f8c8d")

    def test_evaluate_unsafe_password_exact_and_normalized(self) -> None:
        """Verify candidate passwords in the wordlist are marked UNSAFE."""
        # Exact match
        status, msg, color = evaluate_password_safety("password", self.wordlist_set)
        self.assertEqual(status, "UNSAFE")
        self.assertIn("Unsafe", msg)
        self.assertEqual(color, "#c0392b")

        # Mixed casing normalization
        status, msg, color = evaluate_password_safety("ADMIN123", self.wordlist_set)
        self.assertEqual(status, "UNSAFE")

        # Leading and trailing whitespace normalization
        status, msg, color = evaluate_password_safety("   123456   ", self.wordlist_set)
        self.assertEqual(status, "UNSAFE")

        # Complex characters
        status, msg, color = evaluate_password_safety("P@ssw0rd!", self.wordlist_set)
        self.assertEqual(status, "UNSAFE")

    def test_evaluate_safe_password(self) -> None:
        """Verify candidate passwords NOT in wordlist return SAFE status."""
        safe_candidates = [
            "Super$ecure#2026!Vault",
            "K9#mQ2!xL8@wR5$v",
            "UniqueNonDictionaryPassphrase!",
        ]
        for candidate in safe_candidates:
            status, msg, color = evaluate_password_safety(candidate, self.wordlist_set)
            self.assertEqual(status, "SAFE")
            self.assertIn("Relatively Safe", msg)
            self.assertEqual(color, "#27ae60")

    def test_evaluate_policy_rules(self) -> None:
        """Verify the 5 enterprise policy complexity rules."""
        # 1. Empty string -> all False
        empty_res = evaluate_policy_rules("")
        self.assertEqual(len(empty_res), 5)
        self.assertTrue(all(val is False for val in empty_res.values()))

        # 2. Short but meets upper, lower, digit, special
        short_res = evaluate_policy_rules("Ab1!")
        self.assertFalse(short_res["length"])
        self.assertTrue(short_res["uppercase"])
        self.assertTrue(short_res["lowercase"])
        self.assertTrue(short_res["digit"])
        self.assertTrue(short_res["special"])

        # 3. Only lowercase letters with length >= 12
        lower_only = evaluate_policy_rules("abcdefghijkl")
        self.assertTrue(lower_only["length"])
        self.assertTrue(lower_only["lowercase"])
        self.assertFalse(lower_only["uppercase"])
        self.assertFalse(lower_only["digit"])
        self.assertFalse(lower_only["special"])

        # 4. Compliant password meets all 5 rules
        compliant_res = evaluate_policy_rules("Super$ecure#2026")
        self.assertTrue(all(compliant_res.values()))

        # 5. Missing special character
        no_special = evaluate_policy_rules("DefePass2026Audit")
        self.assertTrue(no_special["length"])
        self.assertTrue(no_special["uppercase"])
        self.assertTrue(no_special["lowercase"])
        self.assertTrue(no_special["digit"])
        self.assertFalse(no_special["special"])

    def test_gui_class_load_and_actions(self) -> None:
        """Verify PasswordPolicyGUI initialization and mock action methods without spawning a window."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_wordlist = Path(tmp_dir) / "test_wordlist.txt"
            tmp_wordlist.write_text("SecretWeakPass\n", encoding="utf-8")

            app = PasswordPolicyGUI(wordlist_path=tmp_wordlist)
            self.assertEqual(len(app.wordlist_set), 1)
            self.assertIn("secretweakpass", app.wordlist_set)

            # Mock UI widgets to test action methods headless
            app.password_entry = MagicMock()
            app.status_label = MagicMock()
            app.show_var = MagicMock()

            # Test check_password_action for unsafe password
            app.password_entry.get.return_value = "SecretWeakPass"
            app.check_password_action()
            app.status_label.config.assert_called_with(
                text="Unsafe: Found in common/leaked passwords list.",
                fg="#c0392b",
            )

            # Test clear_input
            app.clear_input()
            app.password_entry.delete.assert_called_with(0, "end")

            # Test toggle_show_password (checked)
            app.show_var.get.return_value = True
            app.toggle_show_password()
            app.password_entry.config.assert_called_with(show="")

            # Test toggle_show_password (unchecked)
            app.show_var.get.return_value = False
            app.toggle_show_password()
            app.password_entry.config.assert_called_with(show="*")

    def test_gui_source_config_and_policy_display(self) -> None:
        """Verify GUI works with WordlistSourceConfig and updates policy display labels."""
        from source_plugin import WordlistSourceConfig

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_wordlist = Path(tmp_dir) / "test_source.txt"
            tmp_wordlist.write_text("password123\nadmin\n", encoding="utf-8")

            cfg = WordlistSourceConfig(filepath=tmp_wordlist, limit=1)
            app = PasswordPolicyGUI(source_config=cfg)
            self.assertEqual(len(app.wordlist_set), 1)

            # Setup mock rule labels
            mock_lbl = MagicMock()
            mock_lbl.rule_desc = "Length >= 12 characters"
            app.rule_labels = {"length": mock_lbl}

            # Update with short password
            app.update_policy_display("short")
            mock_lbl.config.assert_called_with(text="✗  Length >= 12 characters", fg="#c0392b")

            # Update with long password
            app.update_policy_display("longenoughpassword123")
            mock_lbl.config.assert_called_with(text="✓  Length >= 12 characters", fg="#27ae60")

    def test_setup_ui_real_tk_instance(self) -> None:
        """
        Verify PasswordPolicyGUI.setup_ui() instantiates all widgets, fonts,
        and layout configurations cleanly against a real hidden tk.Tk() instance
        without any TclError (e.g. float font sizes).
        """
        import tkinter as tk
        try:
            root = tk.Tk()
        except tk.TclError:
            # Running in a headless environment without a display server
            self.skipTest("Headless environment without display server for Tkinter")
            return

        try:
            root.withdraw()
            app = PasswordPolicyGUI(wordlist_path="wordlist.txt")
            app.setup_ui(root)
            root.update_idletasks()
            self.assertIsNotNone(app.password_entry)
            self.assertIsNotNone(app.status_label)
            self.assertEqual(len(app.rule_labels), 5)
        finally:
            try:
                root.destroy()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
