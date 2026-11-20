"""
DefePass - Wordlist Engine
Module: wordlist_engine.py

Provides high-performance, memory-efficient wordlist loading and streaming
for password auditing and interactive policy enforcement.

Security & Integrity Rules:
- NEVER log, print, or write plaintext passwords or candidates to stdout,
  logs, or persistent storage.
- Stream large files via generators to avoid RAM exhaustion.
- Provide secure cleanup helpers for sensitive mutable buffers.
"""

from pathlib import Path
from typing import Generator, Iterable, MutableSequence, Optional, Set, Union


def stream_wordlist(
    filepath: Union[str, Path],
    encoding: str = "utf-8",
    errors: str = "replace",
) -> Generator[str, None, None]:
    """
    Yields stripped candidate passwords line-by-line from a wordlist file.

    Designed for high-throughput batch auditing (Linux /etc/shadow or Windows SAM)
    without buffering the entire wordlist into system memory.

    :param filepath: Path to the target wordlist file.
    :param encoding: Character encoding to use (default: utf-8).
    :param errors: Error handling scheme for encoding errors (default: replace).
    :yield: Candidate password string stripped of trailing newlines/whitespace.
    :raises FileNotFoundError: If the file does not exist.
    :raises IsADirectoryError: If the path points to a directory.
    :raises PermissionError: If the file cannot be accessed due to permissions.
    """
    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"Wordlist file not found: {path}")

    if path.is_dir():
        raise IsADirectoryError(f"Wordlist path is a directory, not a file: {path}")

    with path.open(mode="r", encoding=encoding, errors=errors) as file_obj:
        for line in file_obj:
            stripped = line.strip()
            if stripped:
                yield stripped


def load_wordlist_set(
    filepath: Union[str, Path],
    encoding: str = "utf-8",
    errors: str = "replace",
) -> Set[str]:
    """
    Loads normalized passwords into a Python set for O(1) constant-time lookup.

    Designed for interactive password checkers (e.g. GUI policy enforcement)
    where individual user passwords must be tested instantaneously against known
    compromised or prohibited dictionary terms.

    Normalization applies `.strip().lower()` to ensure case-insensitive matching.

    :param filepath: Path to the target wordlist file.
    :param encoding: Character encoding to use (default: utf-8).
    :param errors: Error handling scheme for encoding errors (default: replace).
    :return: A set containing lowercased, stripped password strings.
    :raises FileNotFoundError: If the file does not exist.
    :raises IsADirectoryError: If the path points to a directory.
    :raises PermissionError: If the file cannot be accessed due to permissions.
    """
    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"Wordlist file not found: {path}")

    if path.is_dir():
        raise IsADirectoryError(f"Wordlist path is a directory, not a file: {path}")

    wordlist_set: Set[str] = set()

    with path.open(mode="r", encoding=encoding, errors=errors) as file_obj:
        for line in file_obj:
            stripped = line.strip()
            if stripped:
                wordlist_set.add(stripped.lower())

    return wordlist_set


def secure_wipe_buffer(buffer: Optional[Union[bytearray, MutableSequence]]) -> None:
    """
    Overwrites mutable sensitive buffers (such as bytearrays or lists) with zeroes
    to prevent plaintext secrets from lingering in memory.

    Note: Python immutable strings cannot be overwritten in-place, but mutable
    structures (bytearrays, character lists) should be wiped immediately after use.

    :param buffer: Mutable sequence holding sensitive bytes or characters.
    """
    if buffer is None:
        return

    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0
    elif isinstance(buffer, MutableSequence):
        for i in range(len(buffer)):
            buffer[i] = None  # type: ignore


# Forward declarations from pluggable source engine for clean API integration
def get_source_engine():
    """Lazy importer for source_plugin primitives."""
    from source_plugin import WordlistSourceConfig, load_candidates_set, stream_candidates
    return WordlistSourceConfig, stream_candidates, load_candidates_set

