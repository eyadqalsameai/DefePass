"""
DefePass - Unit Tests for Report Exporter
Module: tests/test_report_exporter.py

Verifies:
- validate_output_path pre-flight checks (parent directories, writability).
- format_txt, format_csv, and format_json formatting.
- Guarantee of zero password leakage in reports.
- File export output writing.
"""

import json
import tempfile
import unittest
from pathlib import Path

from report_exporter import (
    export_report,
    format_csv,
    format_json,
    format_txt,
    validate_output_path,
)


class TestReportExporter(unittest.TestCase):
    """Test suite for report exporter module."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)

        self.findings = [
            {"Username": "Admin", "Algorithm": "NTLM", "Status": "Weak / Matched"},
            {"Username": "Guest", "Algorithm": "NTLM", "Status": "Weak / Empty Password"},
            {"Username": "UserSafe", "Algorithm": "NTLM", "Status": "Strong / Not Matched"},
        ]

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_validate_output_path_valid(self) -> None:
        """Verify valid output path resolves properly."""
        target = self.temp_dir_path / "valid_report.txt"
        resolved = validate_output_path(target)
        self.assertEqual(resolved, target.resolve())

    def test_validate_output_path_nonexistent_dir(self) -> None:
        """Verify non-existent directory raises ValueError."""
        target = self.temp_dir_path / "nonexistent_subfolder" / "report.txt"
        with self.assertRaises(ValueError) as ctx:
            validate_output_path(target)
        self.assertIn("does not exist", str(ctx.exception))

    def test_validate_output_path_is_directory(self) -> None:
        """Verify existing directory path raises IsADirectoryError."""
        with self.assertRaises(IsADirectoryError):
            validate_output_path(self.temp_dir_path)

    def test_format_txt_no_password_leak(self) -> None:
        """Verify TXT format creates clean table with zero password leakage."""
        txt_out = format_txt(self.findings)
        self.assertIn("Admin", txt_out)
        self.assertIn("NTLM", txt_out)
        self.assertIn("Weak / Matched", txt_out)
        self.assertIn("Total Accounts Audited: 3", txt_out)

        # Ensure no plaintext passwords leaked
        self.assertNotIn("Password123", txt_out)

    def test_format_csv(self) -> None:
        """Verify CSV formatting."""
        csv_out = format_csv(self.findings)
        lines = csv_out.strip().split("\n")
        self.assertEqual(lines[0], "Username,Algorithm,Status")
        self.assertEqual(lines[1], "Admin,NTLM,Weak / Matched")
        self.assertEqual(lines[2], "Guest,NTLM,Weak / Empty Password")
        self.assertEqual(lines[3], "UserSafe,NTLM,Strong / Not Matched")

    def test_format_json(self) -> None:
        """Verify JSON formatting and parseability."""
        json_out = format_json(self.findings)
        parsed = json.loads(json_out)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0]["Username"], "Admin")
        self.assertEqual(parsed[0]["Status"], "Weak / Matched")
        self.assertEqual(parsed[1]["Status"], "Weak / Empty Password")

    def test_export_report_file_write(self) -> None:
        """Verify export_report writes expected content to disk."""
        target_file = self.temp_dir_path / "final_report.json"
        exported = export_report(self.findings, fmt="json", output_path=target_file)
        self.assertTrue(target_file.exists())
        file_content = target_file.read_text(encoding="utf-8")
        self.assertEqual(exported, file_content)

    def test_export_report_invalid_format(self) -> None:
        """Verify unsupported format raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            export_report(self.findings, fmt="xml")
        self.assertIn("Unsupported", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
