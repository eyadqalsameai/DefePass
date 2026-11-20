"""
DefePass - Pluggable Wordlist Source Engine
Module: source_plugin.py

Provides pluggable local file and online HTTPS streaming for password dictionaries.
Supports transparent gzip decompression, content-type verification, SSL certificate verification,
automatic GitHub blob URL normalization, and word limits.

Security & Integrity Rules:
- Enforce secure HTTPS (https://) for all online sources; reject insecure schemes.
- Check Content-Type to reject HTML pages (e.g., GitHub repo web pages).
- Incrementally stream candidate passwords line-by-line (0% RAM buffering).
- Use certifi for robust SSL CA certificate verification without disabling validation.
- NEVER log or store candidate passwords to persistent storage.
"""

from dataclasses import dataclass
import gzip
import io
import logging
from pathlib import Path
import re
import socket
import ssl
from typing import Generator, Optional, Set, Union
import urllib.error
import urllib.parse
import urllib.request

from wordlist_engine import stream_wordlist

logger = logging.getLogger("DefePass.SourcePlugin")


def get_ssl_context() -> ssl.SSLContext:
    """
    Creates an SSLContext configured with certifi's CA bundle if certifi is installed,
    falling back to ssl.create_default_context().
    Ensures reliable SSL certificate verification on Windows and Linux VMs without disabling verification.
    """
    try:
        import certifi  # type: ignore[import-untyped]
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def normalize_github_blob_url(url: str) -> str:
    """
    Convenience normalization for GitHub web interface blob URLs:
    https://github.com/<owner>/<repo>/blob/<branch>/<path>
    into direct raw content URLs:
    https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>

    :param url: Input HTTPS URL string.
    :return: Normalized raw URL if matching GitHub blob structure, otherwise original URL.
    """
    cleaned_url = url.strip()
    parsed = urllib.parse.urlsplit(cleaned_url)
    if parsed.scheme.lower() == "https" and parsed.netloc.lower() in ("github.com", "www.github.com"):
        match = re.match(r"^/([^/]+)/([^/]+)/blob/(.+)$", parsed.path)
        if match:
            owner, repo, branch_and_path = match.groups()
            new_path = f"/{owner}/{repo}/{branch_and_path}"
            return urllib.parse.urlunsplit(
                ("https", "raw.githubusercontent.com", new_path, parsed.query, parsed.fragment)
            )
    return cleaned_url


@dataclass
class WordlistSourceConfig:
    """
    Configuration for wordlist sourcing (local file or online streaming).
    """
    filepath: Optional[Union[str, Path]] = "wordlist.txt"
    is_online: bool = False
    url: Optional[str] = None
    limit: Optional[int] = None

    def validate(self) -> None:
        """
        Validates source parameters and raises ValueError on configuration errors.
        """
        if self.limit is not None and self.limit <= 0:
            raise ValueError("--limit must be a positive integer greater than 0.")

        if self.is_online:
            if not self.url or not self.url.strip():
                raise ValueError("Online mode (-i / --online) requires a target URL (-u / --url).")

            parsed = urllib.parse.urlparse(self.url.strip())
            if parsed.scheme.lower() != "https":
                raise ValueError(
                    f"Insecure or invalid URL scheme '{parsed.scheme}://'. "
                    "Only secure HTTPS URLs (https://) are permitted."
                )
        else:
            if not self.filepath:
                raise ValueError("Local wordlist mode requires a valid file path.")


def stream_candidates(config: WordlistSourceConfig) -> Generator[str, None, None]:
    """
    Incrementally yields stripped password candidates from the configured source
    (local file or remote HTTPS stream), up to the optional limit.

    :param config: WordlistSourceConfig instance.
    :yield: Cleaned candidate string.
    :raises ValueError: On invalid config or HTML response.
    :raises ConnectionError: On network or HTTP errors.
    :raises TimeoutError: On connection/read timeouts.
    :raises FileNotFoundError: If local wordlist file does not exist.
    """
    config.validate()

    count = 0
    max_limit = config.limit

    if not config.is_online:
        # Local file streaming
        local_path = Path(config.filepath)  # type: ignore[arg-type]
        for word in stream_wordlist(local_path):
            yield word
            count += 1
            if max_limit is not None and count >= max_limit:
                break
        return

    # Online HTTPS streaming
    raw_url = config.url.strip()  # type: ignore[union-attr]
    url = normalize_github_blob_url(raw_url)
    if url != raw_url:
        logger.info(
            "Automatically normalized GitHub blob URL '%s' to raw URL: '%s'",
            raw_url,
            url,
        )

    headers = {
        "User-Agent": "DefePass-Auditor/1.0 (+https://github.com/defepass; security-audit)",
        "Accept": "text/plain, application/x-gzip, application/octet-stream, */*",
    }
    req = urllib.request.Request(url, headers=headers)
    ssl_context = get_ssl_context()

    try:
        response = urllib.request.urlopen(req, timeout=15, context=ssl_context)
    except urllib.error.HTTPError as e:
        code = e.code
        reason = e.reason
        try:
            e.close()
        except Exception:
            pass
        raise ConnectionError(
            f"HTTP Error {code} ({reason}) while accessing wordlist URL: {url}"
        ) from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, socket.timeout):
            raise TimeoutError(
                f"Connection timed out after 15s while fetching wordlist from: {url}"
            ) from e
        raise ConnectionError(
            f"Network connection failed for '{url}': {e.reason}"
        ) from e
    except (socket.timeout, TimeoutError) as e:
        raise TimeoutError(
            f"Connection timed out after 15s while fetching wordlist from: {url}"
        ) from e

    try:
        # Verify Content-Type is not HTML (e.g. GitHub HTML page instead of raw file)
        content_type = response.info().get_content_type().lower()
        if content_type == "text/html":
            raise ValueError(
                f"URL returned web page HTML content ('{content_type}'). "
                "Please provide a direct Raw/plain-text or .gz URL instead of a web page."
            )

        # Check for gzip compression
        content_encoding = (response.info().get("Content-Encoding") or "").lower()
        is_gzip = url.lower().endswith(".gz") or "gzip" in content_encoding

        stream_obj = gzip.GzipFile(fileobj=response, mode="rb") if is_gzip else response
        text_reader = io.TextIOWrapper(stream_obj, encoding="utf-8", errors="replace")

        for line in text_reader:
            stripped = line.strip()
            if stripped:
                yield stripped
                count += 1
                if max_limit is not None and count >= max_limit:
                    break
    finally:
        response.close()


def load_candidates_set(config: WordlistSourceConfig) -> Set[str]:
    """
    Loads normalized candidates into an in-memory set for O(1) instant lookup.
    Normalization: .strip().lower()

    :param config: WordlistSourceConfig instance.
    :return: Set of lowercased, stripped candidate strings.
    """
    candidates_set: Set[str] = set()
    for word in stream_candidates(config):
        candidates_set.add(word.lower())
    return candidates_set
