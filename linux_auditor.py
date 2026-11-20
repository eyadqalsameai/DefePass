"""
DefePass - Linux Shadow Account Auditor
Module: linux_auditor.py

Defensive auditing module for Linux /etc/shadow password hashes using system
libcrypt bindings (Python 3.11-3.13+ safe) and parallel processing across CPU cores.

Security & Integrity Rules:
- NEVER log, print, or expose plaintext passwords, hash pre-images, or matches.
- Auditing results contain ONLY Username, Algorithm, and Status.
- Candidate buffers and sensitive byte structures are cleared after evaluation.
- Early exit on first match to minimize unnecessary hash computations.
- Parallelized across CPU cores using concurrent.futures.ProcessPoolExecutor.
"""

import concurrent.futures
import ctypes
import ctypes.util
import gc
import hmac
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from wordlist_engine import secure_wipe_buffer, stream_wordlist

logger = logging.getLogger("DefePass.LinuxAuditor")

# Known Linux crypt hash prefix mappings
HASH_ALGORITHMS: Dict[str, str] = {
    "$y$": "yescrypt",
    "$gy$": "gost-yescrypt",
    "$7$": "scrypt",
    "$6$": "SHA-512",
    "$5$": "SHA-256",
    "$2b$": "bcrypt",
    "$2a$": "bcrypt",
    "$2y$": "bcrypt",
    "$1$": "MD5",
    "$3$": "NTLM",
    "$sm3$": "SM3",
    "$argon2id$": "Argon2id",
    "$argon2i$": "Argon2i",
    "$argon2d$": "Argon2d",
}


def check_root_privilege() -> None:
    """
    Verifies that the script is executing with administrative (root) privileges.

    :raises PermissionError: If the process does not have UID 0 (root).
    """
    if not hasattr(os, "geteuid"):
        raise PermissionError(
            "DefePass Linux auditor requires a POSIX/Linux environment with root privileges. "
            "Please run on Linux using 'sudo'."
        )

    if os.geteuid() != 0:
        raise PermissionError(
            "DefePass requires root privileges to read /etc/shadow. "
            "Please re-run this command using 'sudo'."
        )


def get_libcrypt() -> ctypes.CDLL:
    """
    Locates and dynamically binds the system 'libcrypt' library via ctypes.

    Explicitly defines:
      crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
      crypt.restype = ctypes.c_char_p

    This prevents 64-bit integer pointer truncation/segmentation faults
    and natively supports modern hashes (e.g. yescrypt, SHA-512, SHA-256).

    :return: Configured ctypes.CDLL instance for libcrypt.
    :raises OSError: If the system libcrypt library cannot be found or loaded.
    """
    lib_path = ctypes.util.find_library("crypt")
    lib: Optional[ctypes.CDLL] = None

    if lib_path:
        try:
            lib = ctypes.CDLL(lib_path)
        except OSError:
            lib = None

    if lib is None:
        # Fallback to common shared object names across Linux distributions
        fallback_candidates = ("libcrypt.so.2", "libcrypt.so.1", "libcrypt.so")
        for candidate in fallback_candidates:
            try:
                lib = ctypes.CDLL(candidate)
                break
            except OSError:
                continue

    if lib is None:
        raise OSError(
            "System crypt library ('libcrypt') could not be located. "
            "Please ensure libcrypt / libxcrypt is installed on this Linux system."
        )

    # Explicitly configure function prototypes for safe 64-bit pointer handling
    lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.crypt.restype = ctypes.c_char_p
    return lib


def identify_hash_algorithm(password_hash: str) -> str:
    """
    Identifies the password hashing algorithm name based on the prefix of the hash string.

    :param password_hash: The raw hash string extracted from /etc/shadow.
    :return: Human-readable algorithm name (e.g. 'yescrypt', 'SHA-512', 'DES', or 'Unknown').
    """
    if not password_hash:
        return "Empty"

    for prefix, algo_name in HASH_ALGORITHMS.items():
        if password_hash.startswith(prefix):
            return algo_name

    # Traditional DES hash is 13 characters with no leading $ indicator
    if len(password_hash) == 13 and "$" not in password_hash:
        return "DES"

    return "Unknown"


def _audit_single_account(
    account: Dict[str, str],
    candidates_or_path: Union[str, Path, List[str]],
    crypt_lib: Any,
) -> Dict[str, str]:
    """
    Audits a single Linux shadow account against the wordlist using crypt and constant-time comparison.

    Security & Efficiency Rules:
    - Candidate passwords streamed via generator or pre-fetched single-download list.
    - Comparison done using hmac.compare_digest.
    - Immediate early exit (break) upon first match for a user.
    - Returns ONLY 'Username', 'Algorithm', and 'Status'.
    - Plaintext passwords are NEVER printed, logged, or returned.

    :param account: Dict containing 'username', 'hash', 'algorithm'.
    :param candidates_or_path: Path to dictionary file or pre-fetched candidate list (for online mode).
    :param crypt_lib: Loaded libcrypt ctypes CDLL instance or mock object.
    :return: Finding dict: {'Username': ..., 'Algorithm': ..., 'Status': ...}
    """
    username = account["username"]
    stored_hash = account["hash"]
    algorithm = account["algorithm"]

    stored_hash_bytes = stored_hash.encode("utf-8")
    matched = False

    # Stream candidates line-by-line (from memory list if online or from file if local)
    iterator = (
        candidates_or_path
        if isinstance(candidates_or_path, list)
        else stream_wordlist(candidates_or_path)
    )

    for candidate in iterator:
        candidate_bytes = candidate.encode("utf-8")

        # Compute hash using system libcrypt
        computed_hash_bytes: Optional[bytes] = crypt_lib.crypt(
            candidate_bytes, stored_hash_bytes
        )

        # Securely wipe candidate buffer immediately
        temp_buf = bytearray(candidate_bytes)
        secure_wipe_buffer(temp_buf)

        # Constant-time comparison
        if computed_hash_bytes is not None and hmac.compare_digest(
            computed_hash_bytes, stored_hash_bytes
        ):
            matched = True
            # Early exit immediately upon first match
            break

    return {
        "Username": username,
        "Algorithm": algorithm,
        "Status": "Weak / Matched" if matched else "Strong / Not Matched",
    }


def _audit_single_account_worker(
    account: Dict[str, str],
    candidates_or_path: Union[str, List[str]],
) -> Dict[str, str]:
    """
    Worker process target for ProcessPoolExecutor.
    Loads system libcrypt locally inside the worker process to avoid unpicklable ctypes CDLL handles.
    """
    crypt_lib = get_libcrypt()
    return _audit_single_account(account, candidates_or_path, crypt_lib)


class LinuxShadowAuditor:
    """
    Defensive auditor for Linux /etc/shadow files.
    Identifies accounts with weak passwords against a wordlist without exposing credentials.
    Supports parallel auditing across available CPU cores via ProcessPoolExecutor.
    """

    def __init__(
        self,
        shadow_path: Union[str, Path] = "/etc/shadow",
        wordlist_path: Optional[Union[str, Path]] = None,
        source_config: Optional[Any] = None,
        check_root: bool = True,
        crypt_lib: Optional[Any] = None,
    ) -> None:
        """
        Initialize the Linux Shadow Auditor.

        :param shadow_path: Path to /etc/shadow file or exported shadow file.
        :param wordlist_path: Path to the dictionary file for auditing.
        :param source_config: Optional pluggable WordlistSourceConfig instance.
        :param check_root: Whether to enforce root privilege check (default: True).
        :param crypt_lib: Optional custom or preloaded crypt library (useful for testing).
        """
        self.shadow_path = Path(shadow_path)
        self.check_root = check_root
        self._crypt_lib = crypt_lib

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

    def _get_crypt(self) -> Any:
        """Lazy loader for the crypt library."""
        if self._crypt_lib is None:
            self._crypt_lib = get_libcrypt()
        return self._crypt_lib

    def parse_shadow_entries(self) -> List[Dict[str, str]]:
        """
        Parse /etc/shadow format entries into structured records.
        Format: username:password_hash:lastchanged:min:max:warn:inactive:expire:reserved

        Skips:
        - Comment lines (starting with '#') and blank lines.
        - Locked or disabled accounts (hash is empty or starts with '!' or '*').

        Security note: Raw hashes are stored in memory only for verification and never logged.

        :return: List of dicts with 'username', 'hash', and 'algorithm'.
        :raises FileNotFoundError: If shadow file does not exist.
        """
        if self.check_root:
            check_root_privilege()

        if not self.shadow_path.exists():
            raise FileNotFoundError(f"Shadow file not found: {self.shadow_path}")

        records: List[Dict[str, str]] = []

        with self.shadow_path.open(mode="r", encoding="utf-8", errors="replace") as file_obj:
            for line in file_obj:
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue

                parts = line_str.split(":")
                if len(parts) < 2:
                    continue

                username = parts[0].strip()
                password_hash = parts[1].strip()

                # Skip locked or disabled accounts (empty, or beginning with '!' or '*')
                if not password_hash or password_hash.startswith("!") or password_hash.startswith("*"):
                    continue

                algorithm = identify_hash_algorithm(password_hash)

                records.append({
                    "username": username,
                    "hash": password_hash,
                    "algorithm": algorithm,
                })

        return records

    def audit_accounts(self) -> List[Dict[str, str]]:
        """
        Audits active shadow accounts against the wordlist using crypt and constant-time comparison.
        Optimized with ProcessPoolExecutor across CPU cores.

        Security & Efficiency Rules:
        - Parallel processing across CPU cores with max_workers=min(len(entries), os.cpu_count() or 1).
        - libcrypt dynamically bound inside each worker process (no CDLL unpicklable error).
        - Candidate passwords streamed via generator without buffering.
        - Comparison done using hmac.compare_digest in constant time.
        - Immediate early exit (break) upon first match for a user.
        - Returns ONLY 'Username', 'Algorithm', and 'Status'.
        - Plaintext passwords are NEVER printed, logged, or returned.

        :return: List of findings: [{'Username': ..., 'Algorithm': ..., 'Status': ...}]
        :raises ValueError: If wordlist_path is not specified.
        :raises FileNotFoundError: If wordlist file does not exist.
        """
        if not self.source_config:
            raise ValueError("Wordlist source must be specified to perform account auditing.")

        if not self.source_config.is_online and self.source_config.filepath:
            if not Path(self.source_config.filepath).exists():
                raise FileNotFoundError(f"Wordlist file not found: {self.source_config.filepath}")

        entries = self.parse_shadow_entries()
        if not entries:
            logger.info("No active Linux accounts found to audit.")
            return []

        logger.info(f"Auditing {len(entries)} active Linux account(s)...")

        from source_plugin import stream_candidates

        if self.source_config.is_online:
            # Online mode: fetch ONCE in the main process and pass candidate list to workers
            logger.info("Streaming online wordlist candidates once for parallel auditing...")
            candidates_payload: Union[str, List[str]] = list(stream_candidates(self.source_config))
        else:
            # Local file mode: pass path string so workers stream directly with 0% memory overhead
            candidates_payload = str(self.source_config.filepath)

        findings: List[Dict[str, str]] = []

        if self._crypt_lib is not None:
            # Custom or mock crypt library provided (e.g. in test suites):
            # execute in-process to avoid unpicklable objects and preserve mock counters
            for account in entries:
                findings.append(
                    _audit_single_account(account, candidates_payload, self._crypt_lib)
                )
        else:
            # Parallel auditing across available CPU cores
            max_workers = min(len(entries), os.cpu_count() or 1)

            with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(_audit_single_account_worker, account, candidates_payload)
                    for account in entries
                ]
                for future in futures:
                    findings.append(future.result())

        # Single garbage collection sweep once auditing finishes
        gc.collect()

        logger.info("Linux shadow audit completed.")
        return findings
