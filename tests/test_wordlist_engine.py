"""
DefePass - Unit Tests for Wordlist Engine
Module: tests/test_wordlist_engine.py

Verifies correctness, edge cases, and performance properties of:
- stream_wordlist() generator mode
- load_wordlist_set() normalized set mode
- secure_wipe_buffer() memory hygiene helper
"""

import inspect
import tempfile
import unittest
from pathlib import Path

from wordlist_engine import (
    load_wordlist_set,
    secure_wipe_buffer,
    stream_wordlist,
)


class TestWordlistEngine(unittest.TestCase):
    """Test suite for wordlist_engine loader routines."""

    def setUp(self) -> None:
        """Create a temporary directory and test files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)

        # Standard test wordlist with blank lines, mixed casing, and trailing spaces
        self.sample_content = (
            "password\n"
            "  123456  \n"
            "\n"
            "Admin123\n"
            "\n\n"
            "P@ssw0rd!\n"
            "DefePass_Sec\n"
        )
        self.sample_file = self.temp_dir_path / "sample_wordlist.txt"
        self.sample_file.write_text(self.sample_content, encoding="utf-8")

    def tearDown(self) -> None:
        """Clean up temporary test files."""
        self.temp_dir.cleanup()

    def test_stream_wordlist_is_generator(self) -> None:
        """Verify that stream_wordlist returns a generator object for memory efficiency."""
        gen = stream_wordlist(self.sample_file)
        self.assertTrue(
            inspect.isgenerator(gen),
            "stream_wordlist must return a Python generator to prevent buffering entire file in RAM.",
        )
        # Consume one item to ensure it operates properly
        first_item = next(gen)
        self.assertEqual(first_item, "password")

    def test_stream_wordlist_yields_stripped_passwords(self) -> None:
        """Verify stream_wordlist strips whitespace, skips blank lines, and preserves casing."""
        items = list(stream_wordlist(self.sample_file))
        expected = [
            "password",
            "123456",
            "Admin123",
            "P@ssw0rd!",
            "DefePass_Sec",
        ]
        self.assertEqual(items, expected)

    def test_stream_wordlist_file_not_found(self) -> None:
        """Verify FileNotFoundError is raised when file does not exist."""
        non_existent = self.temp_dir_path / "does_not_exist.txt"
        with self.assertRaises(FileNotFoundError):
            list(stream_wordlist(non_existent))

    def test_stream_wordlist_directory_error(self) -> None:
        """Verify IsADirectoryError is raised if path is a directory."""
        with self.assertRaises(IsADirectoryError):
            list(stream_wordlist(self.temp_dir_path))

    def test_load_wordlist_set_normalization(self) -> None:
        """Verify load_wordlist_set returns lowercased stripped words in a set."""
        word_set = load_wordlist_set(self.sample_file)
        self.assertIsInstance(word_set, set)

        # Should be normalized to lowercase
        self.assertIn("password", word_set)
        self.assertIn("123456", word_set)
        self.assertIn("admin123", word_set)
        self.assertIn("p@ssw0rd!", word_set)
        self.assertIn("defepass_sec", word_set)

        # Original uppercase forms should not exist unless identical to lowercase
        self.assertNotIn("Admin123", word_set)
        self.assertNotIn("P@ssw0rd!", word_set)

        # Total count should be 5 unique normalized entries
        self.assertEqual(len(word_set), 5)

    def test_load_wordlist_set_file_not_found(self) -> None:
        """Verify FileNotFoundError is raised for missing files in set mode."""
        non_existent = self.temp_dir_path / "does_not_exist.txt"
        with self.assertRaises(FileNotFoundError):
            load_wordlist_set(non_existent)

    def test_load_wordlist_set_directory_error(self) -> None:
        """Verify IsADirectoryError is raised if directory passed."""
        with self.assertRaises(IsADirectoryError):
            load_wordlist_set(self.temp_dir_path)

    def test_sample_wordlist_file_exists_and_loads(self) -> None:
        """Verify the project's root wordlist.txt can be streamed and loaded."""
        root_wordlist = Path("wordlist.txt")
        self.assertTrue(root_wordlist.exists(), "wordlist.txt must exist in project root.")

        stream_count = sum(1 for _ in stream_wordlist(root_wordlist))
        self.assertGreater(stream_count, 0)

        word_set = load_wordlist_set(root_wordlist)
        self.assertGreater(len(word_set), 0)
        self.assertIn("password", word_set)

    def test_secure_wipe_buffer(self) -> None:
        """Verify secure_wipe_buffer zeroes bytearrays and clears mutable sequences."""
        # Bytearray wipe
        sensitive_bytes = bytearray(b"SecretCandidate123")
        original_len = len(sensitive_bytes)
        secure_wipe_buffer(sensitive_bytes)
        self.assertEqual(len(sensitive_bytes), original_len)
        self.assertEqual(sensitive_bytes, bytearray(original_len))

        # Mutable list wipe
        sensitive_list = ["p", "a", "s", "s"]
        secure_wipe_buffer(sensitive_list)
        self.assertTrue(all(item is None for item in sensitive_list))

        # None handling
        try:
            secure_wipe_buffer(None)
        except Exception as e:
            self.fail(f"secure_wipe_buffer(None) raised an exception: {e}")


if __name__ == "__main__":
    unittest.main()
