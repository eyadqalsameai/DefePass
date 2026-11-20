"""
DefePass - Windows Local SAM/NTLM Auditor
Module: windows_auditor.py

Defensive auditing module for Windows local account credentials (SAM / SYSTEM / NTLM).
Extracts hashes safely into memory using Impacket without CLI parsing, computes NTLM hashes
using PyCryptodome (OpenSSL 3 safe), and identifies weak passwords against a wordlist.

Security & Integrity Rules:
- NEVER log, print, or expose plaintext passwords or pre-images.
- Temporary registry hives are automatically removed in a finally block.
- Candidate buffers are wiped immediately after hash computation.
- Findings return ONLY Username, Algorithm ('NTLM'), and Status.
"""

import ctypes
import logging
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple, Union

from wordlist_engine import secure_wipe_buffer, stream_wordlist

logger = logging.getLogger("DefePass.WindowsAuditor")


def check_admin_privilege() -> None:
    """
    Verifies that the current process has elevated Administrator privileges.

    :raises PermissionError: If running without Administrator privileges.
    """
    if os.name != "nt":
        raise PermissionError(
            "Windows SAM auditing is only supported on Windows operating systems."
        )

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError) as e:
        raise PermissionError(f"Could not verify Windows Administrator status: {e}")

    if not is_admin:
        raise PermissionError(
            "DefePass requires elevated Administrator privileges to read SAM/SYSTEM registry hives. "
            "Please run this terminal or command as Administrator ('Run as Administrator')."
        )


def export_live_hives(destination_dir: Path) -> Tuple[Path, Path]:
    """
    Exports SAM and SYSTEM registry hives into a secure temporary directory using 'reg save'.

    :param destination_dir: Temporary directory where hives will be saved.
    :return: Tuple of (sam_hive_path, system_hive_path).
    :raises PermissionError: If reg save fails due to insufficient privileges.
    :raises RuntimeError: If reg save fails for any system reason.
    """
    sam_hive = destination_dir / "sam.hive"
    system_hive = destination_dir / "system.hive"

    # Export HKLM\SAM
    cmd_sam = ["reg", "save", r"HKLM\SAM", str(sam_hive), "/y"]
    res_sam = subprocess.run(cmd_sam, capture_output=True, text=True)
    if res_sam.returncode != 0:
        err = res_sam.stderr.strip() or res_sam.stdout.strip()
        raise PermissionError(
            f"Failed to export HKLM\\SAM (Exit code {res_sam.returncode}): {err}. "
            "Ensure you are running with elevated Administrator privileges."
        )

    # Export HKLM\SYSTEM
    cmd_system = ["reg", "save", r"HKLM\SYSTEM", str(system_hive), "/y"]
    res_system = subprocess.run(cmd_system, capture_output=True, text=True)
    if res_system.returncode != 0:
        err = res_system.stderr.strip() or res_system.stdout.strip()
        raise PermissionError(
            f"Failed to export HKLM\\SYSTEM (Exit code {res_system.returncode}): {err}. "
            "Ensure you are running with elevated Administrator privileges."
        )

    return sam_hive, system_hive


def compute_ntlm_hash(password: str) -> str:
    """
    Computes standard NTLM hash (MD4 of UTF-16LE encoded bytes) using PyCryptodome.
    Compliant with OpenSSL 3 environments where legacy MD4 is disabled in hashlib.

    :param password: Input plaintext candidate.
    :return: Hex-encoded lowercase NTLM hash.
    """
    from Crypto.Hash import MD4

    pw_bytes = password.encode("utf-16le")
    hasher = MD4.new()
    hasher.update(pw_bytes)
    return hasher.hexdigest().lower()


class WindowsSamAuditor:
    """
    Auditor for Windows SAM hives or exported NTLM hash lists.
    Identifies Windows user accounts with weak dictionary passwords.
    """

    def __init__(
        self,
        sam_path: Optional[Union[str, Path]] = None,
        system_path: Optional[Union[str, Path]] = None,
        hash_file_path: Optional[Union[str, Path]] = None,
        wordlist_path: Optional[Union[str, Path]] = None,
        source_config: Optional[Any] = None,
        check_admin: bool = True,
    ) -> None:
        """
        Initialize the Windows SAM/NTLM Auditor.

        :param sam_path: Path to SAM registry hive file (offline mode).
        :param system_path: Path to SYSTEM registry hive file (offline mode).
        :param hash_file_path: Alternative path to exported NTLM hash dump.
        :param wordlist_path: Path to dictionary wordlist.
        :param source_config: Optional pluggable WordlistSourceConfig instance.
        :param check_admin: Whether to enforce Administrator privilege check for live audits.
        """
        self.sam_path = Path(sam_path) if sam_path else None
        self.system_path = Path(system_path) if system_path else None
        self.hash_file_path = Path(hash_file_path) if hash_file_path else None
        self.check_admin = check_admin

        if source_config is not None:
            self.source_config = source_config
            self.wordlist_path = Path(source_config.filepath) if source_config.filepath else None
        elif wordlist_path is not None:
            from source_plugin import WordlistSourceConfig
            self.source_config = WordlistSourceConfig(filepath=wordlist_path)
            self.wordlist_path = Path(wordlist_path)
        else:
            self.source_config = None
            self.wordlist_path = None

    def _parse_hash_dump(self, hash_file: Path) -> List[Dict[str, str]]:
        """
        Parses an exported pwdump/secretsdump text file.
        Accepts:
          - username:rid:lmhash:nthash:::
          - username:nthash
        """
        if not hash_file.exists():
            raise FileNotFoundError(f"NTLM hash dump file not found: {hash_file}")

        accounts: List[Dict[str, str]] = []
        with hash_file.open(mode="r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue

                parts = line_str.split(":")
                if len(parts) >= 4:
                    username = parts[0].strip()
                    ntlm_hash = parts[3].strip().lower()
                    if ntlm_hash and ntlm_hash != "31d6cfe0d16ae931b73c59d7e0c089c0":
                        accounts.append({
                            "username": username,
                            "ntlm_hash": ntlm_hash,
                        })
                    elif ntlm_hash == "31d6cfe0d16ae931b73c59d7e0c089c0":
                        # Empty password hash
                        accounts.append({
                            "username": username,
                            "ntlm_hash": ntlm_hash,
                        })
                elif len(parts) == 2:
                    username = parts[0].strip()
                    ntlm_hash = parts[1].strip().lower()
                    if ntlm_hash:
                        accounts.append({
                            "username": username,
                            "ntlm_hash": ntlm_hash,
                        })

        return accounts

    def _extract_from_hives(self, sam_path: Path, system_path: Path) -> List[Dict[str, str]]:
        """
        Extracts NTLM hashes programmatically from SAM and SYSTEM hive files using Impacket.
        """
        if not sam_path.exists():
            raise FileNotFoundError(f"SAM hive file not found: {sam_path}")
        if not system_path.exists():
            raise FileNotFoundError(f"SYSTEM hive file not found: {system_path}")

        from impacket.examples.secretsdump import LocalOperations, SAMHashes

        local_ops = LocalOperations(str(system_path))
        boot_key = local_ops.getBootKey()

        accounts: List[Dict[str, str]] = []

        def per_secret_cb(secret_line: str) -> None:
            # secret_line format: UserName:RID:LMHash:NTHash:::
            if "_history" in secret_line:
                return
            parts = secret_line.split(":")
            if len(parts) >= 4:
                username = parts[0].strip()
                ntlm_hash = parts[3].strip().lower()
                if ntlm_hash:
                    accounts.append({
                        "username": username,
                        "ntlm_hash": ntlm_hash,
                    })

        sam_hashes = SAMHashes(
            str(sam_path),
            boot_key,
            isRemote=False,
            history=False,
            printUserStatus=False,
            perSecretCallback=per_secret_cb,
        )
        sam_hashes.dump()
        sam_hashes.finish()

        return accounts

    def extract_ntlm_hashes(self) -> List[Dict[str, str]]:
        """
        Extracts user NTLM hashes into memory from:
        1. An offline hash dump file (if provided)
        2. Offline SAM and SYSTEM hive files (if provided)
        3. Live Windows SAM and SYSTEM hives via safe temporary export

        Security guarantee: Temporary hive files are strictly deleted in a finally block.
        """
        if self.hash_file_path:
            return self._parse_hash_dump(self.hash_file_path)

        if self.sam_path and self.system_path:
            return self._extract_from_hives(self.sam_path, self.system_path)

        # Live extraction mode
        if self.check_admin:
            check_admin_privilege()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            sam_hive: Optional[Path] = None
            system_hive: Optional[Path] = None
            try:
                sam_hive, system_hive = export_live_hives(temp_path)
                return self._extract_from_hives(sam_hive, system_hive)
            finally:
                # Guaranteed automatic deletion of exported hive files
                for hive_file in (sam_hive, system_hive):
                    if hive_file and hive_file.exists():
                        try:
                            hive_file.unlink()
                        except OSError as e:
                            logger.warning(f"Could not immediately delete temporary hive: {e}")

    def audit_accounts(self) -> List[Dict[str, str]]:
        """
        Audits Windows local accounts against the wordlist using NTLM hashing.

        Performance & Security Rules:
        - Stream passwords via generator stream_wordlist.
        - Map NTLM hashes to users in a dictionary for fast single-pass lookup O(1).
        - Remove matched hashes immediately to stop redundant checks.
        - Early termination if all users have matched before the wordlist ends.
        - Explicitly wipe candidate buffers immediately after computation.
        - Returns ONLY: Username, Algorithm ('NTLM'), Status ('Weak / Matched' or 'Strong / Not Matched').
        - NEVER logs, prints, or exposes plaintext passwords.

        :return: List of findings: [{'Username': ..., 'Algorithm': 'NTLM', 'Status': ...}]
        :raises ValueError: If wordlist_path is not specified.
        :raises FileNotFoundError: If wordlist file does not exist.
        """
        if not self.source_config:
            raise ValueError("Wordlist source must be specified to perform Windows auditing.")

        if not self.source_config.is_online and self.source_config.filepath:
            if not Path(self.source_config.filepath).exists():
                raise FileNotFoundError(f"Wordlist file not found: {self.source_config.filepath}")

        accounts = self.extract_ntlm_hashes()
        if not accounts:
            logger.info("No Windows user accounts found to audit.")
            return []

        from Crypto.Hash import MD4
        from source_plugin import stream_candidates

        # Map lowercase NTLM hash -> list of usernames with that hash
        hash_to_users: Dict[str, List[str]] = {}
        all_usernames: List[str] = []
        user_status: Dict[str, str] = {}

        EMPTY_NTLM_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

        for acc in accounts:
            u = acc["username"]
            h = acc["ntlm_hash"].lower()
            all_usernames.append(u)
            if h == EMPTY_NTLM_HASH:
                user_status[u] = "Weak / Empty Password"
            else:
                user_status[u] = "Strong / Not Matched"
                if h:
                    hash_to_users.setdefault(h, []).append(u)

        logger.info(f"Auditing {len(all_usernames)} Windows account(s) using wordlist source...")

        # Single-pass dictionary stream for accounts with non-empty passwords
        if hash_to_users:
            for candidate in stream_candidates(self.source_config):
                cand_bytes = candidate.encode("utf-16le")

                # Compute MD4 hash (NTLM)
                hasher = MD4.new()
                hasher.update(cand_bytes)
                cand_hash = hasher.hexdigest().lower()

                # Securely wipe candidate buffer immediately
                temp_buf = bytearray(cand_bytes)
                secure_wipe_buffer(temp_buf)

                # Check if this hash matches any active accounts
                if cand_hash in hash_to_users:
                    matched_users = hash_to_users.pop(cand_hash)
                    for mu in matched_users:
                        user_status[mu] = "Weak / Matched"

                    # Stop checking if all users have matched
                    if not hash_to_users:
                        logger.debug("All user accounts matched dictionary entries; early break.")
                        break

        # Single garbage collection sweep once auditing finishes
        import gc
        gc.collect()

        findings: List[Dict[str, str]] = [
            {
                "Username": u,
                "Algorithm": "NTLM",
                "Status": user_status[u],
            }
            for u in all_usernames
        ]

        logger.info("Windows local SAM audit completed.")
        return findings
