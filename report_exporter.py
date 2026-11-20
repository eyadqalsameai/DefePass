"""
DefePass - Safe Report Exporter
Module: report_exporter.py

Exports defensive auditing results in TXT, CSV, or JSON formats without credential leakage.

Security & Integrity Rules:
- NEVER log, print, or export plaintext passwords or candidate hashes.
- Reports contain strictly: Username, Algorithm, and Status.
- Pre-flight output path validation ensures early failure on invalid directories or permissions.
"""

import csv
import io
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Union


def validate_output_path(filepath: Union[str, Path]) -> Path:
    """
    Validates that the output file path is safe and writable before starting an audit.

    :param filepath: Target report output path.
    :return: Resolved Path instance.
    :raises ValueError: If parent directory does not exist or is not a directory.
    :raises PermissionError: If parent directory is not writable.
    :raises IsADirectoryError: If output path already points to a directory.
    """
    path = Path(filepath).resolve()

    if path.exists() and path.is_dir():
        raise IsADirectoryError(f"Specified output path is an existing directory, not a file: '{path}'")

    parent = path.parent
    if not parent.exists():
        raise ValueError(f"Output directory does not exist: '{parent}'. Please create the folder first.")

    if not parent.is_dir():
        raise ValueError(f"Output parent path is not a directory: '{parent}'")

    # Pre-flight check: verify writable permission by touching a temporary probe
    probe = parent / f".defepass_probe_{os.getpid()}.tmp"
    try:
        probe.touch()
        probe.unlink()
    except OSError as e:
        raise PermissionError(f"Output directory '{parent}' is not writable: {e}") from e

    return path


def format_txt(findings: List[Dict[str, str]]) -> str:
    """Formats findings into a clean ASCII table."""
    lines = [
        "=" * 65,
        f"{'Username':<20} | {'Algorithm':<15} | {'Status':<25}",
        "=" * 65,
    ]
    for item in findings:
        u = item.get("Username", "Unknown")
        a = item.get("Algorithm", "Unknown")
        s = item.get("Status", "Unknown")
        lines.append(f"{u:<20} | {a:<15} | {s:<25}")

    lines.append("=" * 65)
    lines.append(f"Total Accounts Audited: {len(findings)}\n")
    return "\n".join(lines)


def format_csv(findings: List[Dict[str, str]]) -> str:
    """Formats findings into CSV representation."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["Username", "Algorithm", "Status"])
    for item in findings:
        writer.writerow([
            item.get("Username", ""),
            item.get("Algorithm", ""),
            item.get("Status", ""),
        ])
    return output.getvalue()


def format_json(findings: List[Dict[str, str]]) -> str:
    """Formats findings into structured JSON."""
    safe_data = [
        {
            "Username": item.get("Username", ""),
            "Algorithm": item.get("Algorithm", ""),
            "Status": item.get("Status", ""),
        }
        for item in findings
    ]
    return json.dumps(safe_data, indent=2) + "\n"


def export_report(
    findings: List[Dict[str, str]],
    fmt: str = "txt",
    output_path: Optional[Union[str, Path]] = None,
) -> str:
    """
    Formats and optionally saves audit findings to disk in the specified format.

    :param findings: List of audit outcome dictionaries.
    :param fmt: Output format ('txt', 'csv', 'json'). Default: 'txt'.
    :param output_path: Optional filepath to write report.
    :return: The formatted string report.
    :raises ValueError: If format is unsupported or path is invalid.
    """
    normalized_fmt = fmt.strip().lower()
    if normalized_fmt == "txt":
        content = format_txt(findings)
    elif normalized_fmt == "csv":
        content = format_csv(findings)
    elif normalized_fmt == "json":
        content = format_json(findings)
    else:
        raise ValueError(f"Unsupported report format '{fmt}'. Choose from: 'txt', 'csv', 'json'.")

    if output_path:
        valid_path = validate_output_path(output_path)
        valid_path.write_text(content, encoding="utf-8")

    return content
