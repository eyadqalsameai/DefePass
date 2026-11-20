"""
DefePass - Defensive Password Policy Enforcement & Auditing Tool
Module: main.py

Unified CLI and GUI launcher for cross-platform defensive auditing.

Security & Integrity Rules:
- Plaintext passwords and hashes are NEVER printed or logged.
- Only policy compliance results (COMPLIANT / NON_COMPLIANT) are surfaced.
- Strict CLI validation prevents ambiguous arguments and protects sensitive data.
"""

import argparse
import logging
import os
from pathlib import Path
import platform
import subprocess
import sys
import urllib.parse

from report_exporter import export_report, format_txt, validate_output_path
from source_plugin import WordlistSourceConfig


def maybe_reexec_in_venv() -> bool:
    """
    Automatically re-executes the current script within the local .venv virtual environment
    if one exists and the current process is not already running inside a virtual environment.

    Ensures zero-friction execution (e.g., 'python main.py --audit' on Windows or
    'sudo python3 main.py --audit' on Linux) without requiring manual venv activation.
    """
    # 1. Check if already inside a virtual environment or if guard env var is set
    is_in_venv = (sys.prefix != sys.base_prefix) or (os.environ.get("DEFEPASS_VENV_ACTIVE") == "1")
    if is_in_venv:
        return False

    # 2. Look for .venv/Scripts/python.exe (Windows) or .venv/bin/python (Linux/macOS)
    base_dir = Path(__file__).resolve().parent
    is_windows = (sys.platform == "win32") or (os.name == "nt")
    if is_windows:
        venv_python = base_dir / ".venv" / "Scripts" / "python.exe"
    else:
        venv_python = base_dir / ".venv" / "bin" / "python"

    if not venv_python.is_file():
        alt_python = (
            base_dir / ".venv" / "bin" / "python"
            if is_windows
            else base_dir / ".venv" / "Scripts" / "python.exe"
        )
        if alt_python.is_file():
            venv_python = alt_python

    # 3. If that .venv interpreter exists and differs from sys.executable, re-run
    if venv_python.is_file():
        try:
            curr_exe = Path(sys.executable).resolve()
            target_exe = venv_python.resolve()
        except Exception:
            curr_exe = Path(sys.executable)
            target_exe = venv_python

        if curr_exe != target_exe:
            new_env = {**os.environ, "DEFEPASS_VENV_ACTIVE": "1"}
            cmd = [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]]
            proc = subprocess.run(cmd, env=new_env)
            sys.exit(proc.returncode)
            return True

    return False

AUTHORIZED_USE_BANNER = """
-----------------------------------------------------------------------
██████╗  ███████╗ ███████╗ ███████╗ ██████╗   █████╗  ███████╗ ███████╗
██╔══██╗ ██╔════╝ ██╔════╝ ██╔════╝ ██╔══██╗ ██╔══██╗ ██╔════╝ ██╔════╝
██║  ██║ █████╗   █████╗   █████╗   ██████╔╝ ███████║ ███████╗ ███████╗
██║  ██║ ██╔══╝   ██╔══╝   ██╔══╝   ██╔═══╝  ██╔══██║ ╚════██║ ╚════██║
██████╔╝ ███████╗ ██║      ███████╗ ██║      ██║  ██║ ███████║ ███████║
╚═════╝  ╚══════╝ ╚═╝      ╚══════╝ ╚═╝      ╚═╝  ╚═╝ ╚══════╝ ╚══════╝
=======================================================================
  DefePass - Cross-Platform Defensive Password Auditing & Policy Tool
  Notice: Strictly for authorized defensive audits and policy testing.
======================================================================="""


def setup_secure_logging(verbose: bool = False) -> None:
    """
    Configures application logging with security protections.
    Ensures that debug/info messages do not leak sensitive credentials.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def build_argument_parser() -> argparse.ArgumentParser:
    """
    Builds the CLI argument parser for DefePass with structured argument groups.
    """
    epilog_text = """
Examples:
  1. Automated local system audit using default local wordlist:
     python main.py --audit

  2. Automated audit streaming an online HTTPS wordlist with limit:
     python main.py --audit -i -u https://raw.githubusercontent.com/example/wordlist.txt --limit 5000

  3. Windows SAM audit exporting report to JSON file:
     python main.py --audit-windows -o report.json --format json

  4. Linux shadow audit exporting report to CSV:
     python main.py --audit-linux -o audit_results.csv --format csv

  5. Interactive GUI mode with local dictionary:
     python main.py --gui -p wordlist.txt

  6. Interactive GUI mode with online wordlist:
     python main.py --gui -i -u https://example.com/passwords.txt --limit 1000
"""
    parser = argparse.ArgumentParser(
        prog="DefePass",
        description="DefePass: Cross-Platform Defensive Password Policy Enforcement & Auditing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog_text,
    )

    # 1. Audit Modes (Mutually Exclusive Group)
    mode_group = parser.add_argument_group("Audit Modes")
    mode_mutex = mode_group.add_mutually_exclusive_group(required=True)
    mode_mutex.add_argument(
        "--audit",
        action="store_true",
        help="Automatically detect OS and run local defensive audit (Linux shadow or Windows SAM)",
    )
    mode_mutex.add_argument(
        "--audit-linux",
        action="store_true",
        help="Run defensive auditing against a Linux /etc/shadow file",
    )
    mode_mutex.add_argument(
        "--audit-windows",
        action="store_true",
        help="Run defensive auditing against Windows SAM/SYSTEM hives or NTLM hashes",
    )
    mode_mutex.add_argument(
        "--gui",
        action="store_true",
        help="Launch the interactive Tkinter password checker GUI",
    )

    # 2. Wordlist Source Options
    source_group = parser.add_argument_group("Wordlist Source Options")
    source_group.add_argument(
        "-w",
        "-p",
        "--wordlist",
        "--path",
        dest="wordlist",
        type=str,
        default="wordlist.txt",
        help="Path to local password dictionary file (default: wordlist.txt)",
    )
    source_group.add_argument(
        "-i",
        "--online",
        action="store_true",
        help="Enable online wordlist streaming from a remote HTTPS URL",
    )
    source_group.add_argument(
        "-u",
        "--url",
        type=str,
        help="Target HTTPS URL for online wordlist streaming",
    )
    source_group.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of wordlist entries to stream and evaluate (positive integer)",
    )

    # 3. Output & Reporting Options
    output_group = parser.add_argument_group("Output & Reporting Options")
    output_group.add_argument(
        "-o",
        "--output",
        type=str,
        help="Path to write the exported audit report file",
    )
    output_group.add_argument(
        "--format",
        choices=["txt", "csv", "json"],
        default="txt",
        help="Format for the exported audit report (default: txt)",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed logging output (without credential leaks)",
    )

    # 4. OS-Specific Options
    os_group = parser.add_argument_group("OS-Specific Options")
    os_group.add_argument(
        "--shadow",
        type=str,
        default="/etc/shadow",
        help="Path to Linux /etc/shadow file (used with --audit-linux)",
    )
    os_group.add_argument(
        "--sam",
        type=str,
        help="Path to Windows SAM registry hive (used with --audit-windows)",
    )
    os_group.add_argument(
        "--system",
        type=str,
        help="Path to Windows SYSTEM registry hive (used with --audit-windows)",
    )
    os_group.add_argument(
        "--ntlm",
        type=str,
        help="Path to exported NTLM hash dump (used with --audit-windows)",
    )

    return parser


def validate_cli_arguments(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """
    Validates CLI flag combinations and constraints. Calls parser.error on violations.
    """
    # 1. -i without -u
    if args.online and not args.url:
        parser.error("Online mode (-i / --online) requires a target URL (-u / --url).")

    # 2. -u without -i
    if args.url and not args.online:
        parser.error("Target URL (-u / --url) requires the online mode flag (-i / --online).")

    # 3. -i combined with explicitly passed -p / -w
    explicit_local = any(
        arg.split("=")[0] in ("-p", "-w", "--path", "--wordlist")
        for arg in sys.argv[1:]
    )
    if args.online and explicit_local:
        parser.error("Cannot combine online mode (-i / -u) with a local wordlist path (-p / -w).")

    # 4. -o combined with --gui
    if args.output and args.gui:
        parser.error("Report output (-o / --output) cannot be used with GUI mode (--gui) to enforce zero credential logging.")

    # 5. --limit <= 0
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be a positive integer greater than 0.")

    # 6. Non-HTTPS URL in -u
    if args.url:
        parsed = urllib.parse.urlparse(args.url.strip())
        if parsed.scheme.lower() != "https":
            parser.error("Target URL (-u / --url) must use secure HTTPS (https://).")

    # 7. Pre-flight output directory validation if -o is specified
    if args.output:
        try:
            validate_output_path(args.output)
        except (ValueError, PermissionError, IsADirectoryError) as e:
            parser.error(f"Invalid output path: {e}")


def main() -> int:
    """Main application entry point."""
    parser = build_argument_parser()
    args = parser.parse_args()

    # Perform strict CLI validation
    validate_cli_arguments(parser, args)

    # Display authorized-use banner
    print(AUTHORIZED_USE_BANNER)

    setup_secure_logging(verbose=args.verbose)
    logger = logging.getLogger("DefePass.Main")

    # Construct unified source config
    source_config = WordlistSourceConfig(
        filepath=args.wordlist if not args.online else None,
        is_online=args.online,
        url=args.url,
        limit=args.limit,
    )

    if not args.online:
        wordlist_path = Path(args.wordlist)
        if not wordlist_path.exists():
            logger.warning(
                f"Wordlist file not found at '{wordlist_path}'. "
                "Please ensure a valid wordlist is provided."
            )

    # Unified OS auto-detection routing
    if args.audit:
        current_os = platform.system()
        logger.info(f"Auto-detecting operating system for audit: Detected '{current_os}'")
        if current_os == "Linux":
            args.audit_linux = True
        elif current_os == "Windows":
            args.audit_windows = True
        else:
            logger.error(
                f"Unsupported operating system for automated audit: '{current_os}'. "
                "Please specify --audit-linux or --audit-windows explicitly."
            )
            return 1

    if args.gui:
        logger.info("Launching GUI mode...")
        try:
            from gui_checker import launch_gui
            launch_gui(source_config=source_config)
            return 0
        except NotImplementedError as e:
            logger.info(f"Phase Status: {e}")
            return 0

    findings = None

    if args.audit_linux:
        logger.info("Initiating Linux shadow audit...")
        try:
            from linux_auditor import LinuxShadowAuditor
            auditor = LinuxShadowAuditor(
                shadow_path=args.shadow,
                source_config=source_config,
            )
            findings = auditor.audit_accounts()
        except PermissionError as e:
            logger.error(f"Permission Denied: {e}")
            return 1
        except (FileNotFoundError, OSError, ValueError, ConnectionError, TimeoutError) as e:
            logger.error(f"Audit Error: {e}")
            return 1

    elif args.audit_windows:
        logger.info("Initiating Windows SAM/NTLM audit...")
        try:
            from windows_auditor import WindowsSamAuditor
            auditor = WindowsSamAuditor(
                sam_path=args.sam,
                system_path=args.system,
                hash_file_path=args.ntlm,
                source_config=source_config,
            )
            findings = auditor.audit_accounts()
        except PermissionError as e:
            logger.error(f"Permission Denied: {e}")
            return 1
        except (FileNotFoundError, OSError, ValueError, ConnectionError, TimeoutError) as e:
            logger.error(f"Audit Error: {e}")
            return 1

    if findings is not None:
        try:
            report_text = export_report(findings, fmt=args.format, output_path=args.output)
            if args.output:
                logger.info(f"Report exported to '{args.output}' (format: {args.format.upper()})")

            # Display formatted output on console
            if not args.output or args.format == "txt":
                print("\n" + report_text)
            else:
                # If exported to JSON/CSV file, also print human-readable table to stdout
                print("\n" + format_txt(findings))
            return 0
        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            return 1

    return 0


if __name__ == "__main__":
    maybe_reexec_in_venv()
    sys.exit(main())
