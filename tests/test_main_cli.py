"""
DefePass - Unit Tests for Unified CLI
Module: tests/test_main_cli.py

Verifies:
- Argument parser configuration and mutual exclusivity.
- Unified --audit flag auto-detecting Linux vs Windows.
- Strict CLI validation rules (exit code 2):
  * -i without -u
  * -u without -i
  * -i combined with explicit -p/-w
  * -o combined with --gui
  * --limit <= 0
  * Non-HTTPS URL
- Output formatting options and aliases.
"""

from io import StringIO
import os
from pathlib import Path
import platform
import sys
import unittest
from unittest.mock import MagicMock, patch

from main import build_argument_parser, main, maybe_reexec_in_venv


class TestMainCLI(unittest.TestCase):
    """Test suite for main CLI arguments and strict validation rules."""

    def setUp(self) -> None:
        self.parser = build_argument_parser()

    def test_mode_flags_mutual_exclusion(self) -> None:
        """Verify that mode flags cannot be combined."""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--audit", "--gui"])

        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--audit-linux", "--audit-windows"])

        with self.assertRaises(SystemExit):
            self.parser.parse_args([])

    def test_valid_mode_flags_parse(self) -> None:
        """Verify individual mode flags parse properly."""
        args_audit = self.parser.parse_args(["--audit"])
        self.assertTrue(args_audit.audit)

        args_gui = self.parser.parse_args(["--gui"])
        self.assertTrue(args_gui.gui)

        args_linux = self.parser.parse_args(["--audit-linux"])
        self.assertTrue(args_linux.audit_linux)

        args_windows = self.parser.parse_args(["--audit-windows"])
        self.assertTrue(args_windows.audit_windows)

    def test_aliases_and_options(self) -> None:
        """Verify -p is alias for -w, --limit, --format, and -o."""
        args = self.parser.parse_args([
            "--audit",
            "-p", "custom.txt",
            "-o", "out.csv",
            "--format", "csv",
            "--limit", "100",
        ])
        self.assertEqual(args.wordlist, "custom.txt")
        self.assertEqual(args.output, "out.csv")
        self.assertEqual(args.format, "csv")
        self.assertEqual(args.limit, 100)

    def test_validation_online_without_url(self) -> None:
        """Verify -i without -u raises parser error (exit code 2)."""
        with patch("sys.argv", ["main.py", "--audit", "-i"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 2)

    def test_validation_url_without_online(self) -> None:
        """Verify -u without -i raises parser error (exit code 2)."""
        with patch("sys.argv", ["main.py", "--audit", "-u", "https://example.com/list.txt"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 2)

    def test_validation_online_combined_with_explicit_local_path(self) -> None:
        """Verify -i combined with explicit -p/-w raises parser error (exit code 2)."""
        with patch("sys.argv", ["main.py", "--audit", "-i", "-u", "https://example.com/list.txt", "-p", "local.txt"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 2)

    def test_validation_output_combined_with_gui(self) -> None:
        """Verify -o combined with --gui is rejected to enforce GUI Zero-Logging policy."""
        with patch("sys.argv", ["main.py", "--gui", "-o", "report.txt"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 2)

    def test_validation_limit_non_positive(self) -> None:
        """Verify --limit <= 0 raises parser error (exit code 2)."""
        with patch("sys.argv", ["main.py", "--audit", "--limit", "0"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 2)

        with patch("sys.argv", ["main.py", "--audit", "--limit", "-10"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 2)

    def test_validation_insecure_url_scheme(self) -> None:
        """Verify non-https URL raises parser error (exit code 2)."""
        with patch("sys.argv", ["main.py", "--audit", "-i", "-u", "http://insecure.com/list.txt"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 2)

    @patch("platform.system", return_value="Linux")
    @patch("linux_auditor.LinuxShadowAuditor.audit_accounts", return_value=[])
    def test_auto_audit_routes_to_linux_on_linux_os(self, mock_audit, mock_sys) -> None:
        """Verify --audit triggers LinuxShadowAuditor when platform is Linux."""
        with patch("sys.argv", ["main.py", "--audit"]):
            with patch("sys.stdout", new_callable=StringIO) as mock_out:
                exit_code = main()
                self.assertEqual(exit_code, 0)
                mock_audit.assert_called_once()
                self.assertIn("DefePass", mock_out.getvalue())

    @patch("platform.system", return_value="Windows")
    @patch("windows_auditor.WindowsSamAuditor.audit_accounts", return_value=[])
    def test_auto_audit_routes_to_windows_on_windows_os(self, mock_audit, mock_sys) -> None:
        """Verify --audit triggers WindowsSamAuditor when platform is Windows."""
        with patch("sys.argv", ["main.py", "--audit"]):
            with patch("sys.stdout", new_callable=StringIO) as mock_out:
                exit_code = main()
                self.assertEqual(exit_code, 0)
                mock_audit.assert_called_once()
                self.assertIn("DefePass", mock_out.getvalue())

    @patch("gui_checker.launch_gui")
    def test_gui_flag_routes_to_launch_gui(self, mock_launch) -> None:
        """Verify --gui invokes launch_gui with configured source."""
        with patch("sys.argv", ["main.py", "--gui", "-w", "wordlist.txt"]):
            with patch("sys.stdout", new_callable=StringIO):
                exit_code = main()
                self.assertEqual(exit_code, 0)
                mock_launch.assert_called_once()
                source_cfg = mock_launch.call_args[1].get("source_config")
                self.assertIsNotNone(source_cfg)
                self.assertEqual(source_cfg.filepath, "wordlist.txt")

    @patch("subprocess.run")
    @patch("sys.exit")
    def test_maybe_reexec_in_venv_when_already_in_venv(self, mock_exit, mock_run) -> None:
        """Verify maybe_reexec_in_venv does nothing when already running in a virtual environment."""
        # 1. Active virtual environment (prefix != base_prefix)
        with patch("sys.prefix", "/home/user/DefePass/.venv"), patch("sys.base_prefix", "/usr"):
            result = maybe_reexec_in_venv()
            self.assertFalse(result)
            mock_run.assert_not_called()
            mock_exit.assert_not_called()

        # 2. Guard environment variable is active
        with patch("sys.prefix", "/usr"), patch("sys.base_prefix", "/usr"), patch.dict("os.environ", {"DEFEPASS_VENV_ACTIVE": "1"}):
            result = maybe_reexec_in_venv()
            self.assertFalse(result)
            mock_run.assert_not_called()
            mock_exit.assert_not_called()

    @patch("subprocess.run")
    @patch("sys.exit")
    def test_maybe_reexec_in_venv_triggers_when_outside_venv(self, mock_exit, mock_run) -> None:
        """Verify maybe_reexec_in_venv triggers subprocess.run when outside venv and .venv exists."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        dummy_sys_exe = "C:\\Python315\\python.exe" if sys.platform == "win32" else "/usr/bin/python3"
        clean_env = {k: v for k, v in os.environ.items() if k != "DEFEPASS_VENV_ACTIVE"}

        with patch("sys.prefix", "/usr"), patch("sys.base_prefix", "/usr"), \
             patch("sys.executable", dummy_sys_exe), \
             patch.dict("os.environ", clean_env, clear=True), \
             patch("sys.argv", ["main.py", "--audit", "-v"]):

            result = maybe_reexec_in_venv()
            # If sys.exit was called, result won't be returned in normal flow, but our test mocks sys.exit
            mock_run.assert_called_once()
            call_args, call_kwargs = mock_run.call_args
            cmd = call_args[0]

            # Verify first element is .venv python interpreter and second is main.py path
            self.assertTrue(cmd[0].endswith("python.exe") or cmd[0].endswith("python"))
            self.assertTrue(cmd[1].endswith("main.py"))
            self.assertEqual(cmd[2:], ["--audit", "-v"])

            # Verify DEFEPASS_VENV_ACTIVE is set in child env
            self.assertEqual(call_kwargs["env"].get("DEFEPASS_VENV_ACTIVE"), "1")
            mock_exit.assert_called_once_with(0)

    @patch("subprocess.run")
    @patch("sys.exit")
    @patch("pathlib.Path.is_file", return_value=False)
    def test_maybe_reexec_in_venv_when_venv_missing(self, mock_is_file, mock_exit, mock_run) -> None:
        """Verify maybe_reexec_in_venv does nothing if .venv directory/interpreter does not exist."""
        clean_env = {k: v for k, v in os.environ.items() if k != "DEFEPASS_VENV_ACTIVE"}
        with patch("sys.prefix", "/usr"), patch("sys.base_prefix", "/usr"), patch.dict("os.environ", clean_env, clear=True):
            result = maybe_reexec_in_venv()
            self.assertFalse(result)
            mock_run.assert_not_called()
            mock_exit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
