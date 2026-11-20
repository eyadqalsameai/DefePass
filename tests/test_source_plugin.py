"""
DefePass - Unit Tests for Pluggable Wordlist Source Engine
Module: tests/test_source_plugin.py

Verifies:
- WordlistSourceConfig validation (schemes, limits, missing URLs).
- Local streaming and limit enforcement.
- Mocked HTTPS online streaming (plain text, gzip decompression).
- HTML Content-Type rejection (guarding against GitHub web page URLs).
- Network and timeout error handling.
- Set-loading normalization.
"""

import gzip
import io
import socket
import ssl
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from source_plugin import (
    WordlistSourceConfig,
    get_ssl_context,
    load_candidates_set,
    normalize_github_blob_url,
    stream_candidates,
)


class MockHTTPResponse:
    """Mock HTTP response object for urllib.request.urlopen."""

    def __init__(self, raw_bytes: bytes, content_type: str = "text/plain", content_encoding: str = ""):
        self.raw_bytes = raw_bytes
        self.stream = io.BytesIO(raw_bytes)
        self.content_type = content_type
        self.content_encoding = content_encoding

    @property
    def closed(self) -> bool:
        return self.stream.closed

    def read(self, *args):
        return self.stream.read(*args)

    def readinto(self, *args):
        return self.stream.readinto(*args)

    def readline(self, *args):
        return self.stream.readline(*args)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return self.stream.seekable()

    def writable(self) -> bool:
        return False

    def __iter__(self):
        return iter(self.stream)

    def info(self):
        headers = {
            "Content-Type": self.content_type,
            "Content-Encoding": self.content_encoding,
        }
        mock_info = MagicMock()
        mock_info.get_content_type.return_value = self.content_type
        mock_info.get.side_effect = lambda k, default=None: headers.get(k, default)
        return mock_info

    def close(self):
        self.stream.close()


class TestSourcePlugin(unittest.TestCase):
    """Test suite for pluggable wordlist source engine."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)
        self.local_file = self.temp_dir_path / "test_words.txt"
        self.local_file.write_text("word1\nword2\nword3\nword4\nword5\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_config_validation_limit(self) -> None:
        """Verify invalid limit values raise ValueError."""
        with self.assertRaises(ValueError):
            WordlistSourceConfig(limit=0).validate()

        with self.assertRaises(ValueError):
            WordlistSourceConfig(limit=-5).validate()

        # Valid limit
        WordlistSourceConfig(limit=10).validate()

    def test_config_validation_online_scheme(self) -> None:
        """Verify only https:// is accepted for online sources."""
        # Missing URL
        with self.assertRaises(ValueError):
            WordlistSourceConfig(is_online=True, url="").validate()

        # HTTP scheme rejected
        with self.assertRaises(ValueError):
            WordlistSourceConfig(is_online=True, url="http://example.com/list.txt").validate()

        # File scheme rejected
        with self.assertRaises(ValueError):
            WordlistSourceConfig(is_online=True, url="file:///etc/passwd").validate()

        # Valid HTTPS accepted
        cfg = WordlistSourceConfig(is_online=True, url="https://example.com/list.txt")
        cfg.validate()

    def test_local_streaming_and_limit(self) -> None:
        """Verify local file streaming respects limit."""
        cfg_unlimited = WordlistSourceConfig(filepath=self.local_file)
        results = list(stream_candidates(cfg_unlimited))
        self.assertEqual(results, ["word1", "word2", "word3", "word4", "word5"])

        cfg_limited = WordlistSourceConfig(filepath=self.local_file, limit=2)
        limited_results = list(stream_candidates(cfg_limited))
        self.assertEqual(limited_results, ["word1", "word2"])

    @patch("urllib.request.urlopen")
    def test_online_streaming_plain_text(self, mock_urlopen) -> None:
        """Verify plain text online streaming via HTTPS."""
        data = b"online1\nonline2\nonline3\n"
        mock_urlopen.return_value = MockHTTPResponse(data, content_type="text/plain")

        cfg = WordlistSourceConfig(is_online=True, url="https://example.com/raw.txt", limit=2)
        candidates = list(stream_candidates(cfg))
        self.assertEqual(candidates, ["online1", "online2"])

    @patch("urllib.request.urlopen")
    def test_online_streaming_gzip_transparent(self, mock_urlopen) -> None:
        """Verify transparent GZIP decompression for .gz URLs."""
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(b"gzword1\ngzword2\ngzword3\n")
        compressed_bytes = buf.getvalue()

        mock_urlopen.return_value = MockHTTPResponse(
            compressed_bytes,
            content_type="application/octet-stream",
            content_encoding="gzip",
        )

        cfg = WordlistSourceConfig(is_online=True, url="https://example.com/words.txt.gz")
        candidates = list(stream_candidates(cfg))
        self.assertEqual(candidates, ["gzword1", "gzword2", "gzword3"])

    @patch("urllib.request.urlopen")
    def test_online_rejects_html_content_type(self, mock_urlopen) -> None:
        """Verify HTML Content-Type is rejected with advice for raw/plain-text."""
        html_bytes = b"<!DOCTYPE html><html><body><h1>GitHub Page</h1></body></html>"
        mock_urlopen.return_value = MockHTTPResponse(html_bytes, content_type="text/html")

        cfg = WordlistSourceConfig(is_online=True, url="https://github.com/user/repo/blob/main/list.txt")
        with self.assertRaises(ValueError) as ctx:
            list(stream_candidates(cfg))
        self.assertIn("Raw", str(ctx.exception))

    @patch("urllib.request.urlopen")
    def test_online_network_errors(self, mock_urlopen) -> None:
        """Verify HTTP and connection errors are converted to clear messages."""
        # HTTP Error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://example.com", 404, "Not Found", {}, io.BytesIO(b"")
        )
        cfg = WordlistSourceConfig(is_online=True, url="https://example.com/missing.txt")
        with self.assertRaises(ConnectionError) as ctx:
            list(stream_candidates(cfg))
        self.assertIn("404", str(ctx.exception))

        # Timeout Error
        mock_urlopen.side_effect = socket.timeout("timed out")
        with self.assertRaises(TimeoutError) as ctx:
            list(stream_candidates(cfg))
        self.assertIn("timed out", str(ctx.exception).lower())

    def test_load_candidates_set_normalizes(self) -> None:
        """Verify set loading applies lowercase normalization."""
        cfg = WordlistSourceConfig(filepath=self.local_file)
        c_set = load_candidates_set(cfg)
        self.assertIn("word1", c_set)
        self.assertEqual(len(c_set), 5)

    def test_normalize_github_blob_url(self) -> None:
        """Verify GitHub blob URLs are normalized to raw content URLs."""
        # Standard blob URL
        blob_url = "https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k.txt"
        expected_raw = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k.txt"
        self.assertEqual(normalize_github_blob_url(blob_url), expected_raw)

        # www.github.com subdomain
        www_url = "https://www.github.com/user/project/blob/main/deep/path/words.gz"
        expected_www = "https://raw.githubusercontent.com/user/project/main/deep/path/words.gz"
        self.assertEqual(normalize_github_blob_url(www_url), expected_www)

        # Already raw URL - unchanged
        already_raw = "https://raw.githubusercontent.com/user/project/main/words.txt"
        self.assertEqual(normalize_github_blob_url(already_raw), already_raw)

        # Non-GitHub URL - unchanged
        other_url = "https://example.com/blob/main/list.txt"
        self.assertEqual(normalize_github_blob_url(other_url), other_url)

        # GitHub repo home or tree URL - unchanged
        tree_url = "https://github.com/user/project"
        self.assertEqual(normalize_github_blob_url(tree_url), tree_url)

    def test_get_ssl_context(self) -> None:
        """Verify SSL context creation with and without certifi fallback."""
        # Normal execution
        ctx = get_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

        # Mock ImportError when certifi is missing
        with patch.dict("sys.modules", {"certifi": None}):
            fallback_ctx = get_ssl_context()
            self.assertIsInstance(fallback_ctx, ssl.SSLContext)
            self.assertEqual(fallback_ctx.verify_mode, ssl.CERT_REQUIRED)

    @patch("urllib.request.urlopen")
    def test_online_streaming_normalizes_github_and_passes_ssl_context(self, mock_urlopen) -> None:
        """Verify stream_candidates normalizes GitHub blob URLs and passes SSLContext."""
        mock_urlopen.return_value = MockHTTPResponse(b"secret1\nsecret2\n")

        blob_url = "https://github.com/sec/lists/blob/main/passwords.txt"
        cfg = WordlistSourceConfig(is_online=True, url=blob_url)
        candidates = list(stream_candidates(cfg))
        self.assertEqual(candidates, ["secret1", "secret2"])

        # Check call arguments to urlopen
        mock_urlopen.assert_called_once()
        req_arg, = mock_urlopen.call_args[0]
        kwargs = mock_urlopen.call_args[1]

        # Target URL was rewritten to raw.githubusercontent.com
        self.assertEqual(
            req_arg.get_full_url(),
            "https://raw.githubusercontent.com/sec/lists/main/passwords.txt",
        )
        # SSLContext was passed in kwargs
        self.assertIn("context", kwargs)
        self.assertIsInstance(kwargs["context"], ssl.SSLContext)


if __name__ == "__main__":
    unittest.main()
