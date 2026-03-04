"""
Tests for the SNI Extractor service.
Tests TLS Client Hello parsing and hostname extraction.
"""

import pytest
from app.services.sni_extractor import extract_sni, is_tls_client_hello
from app.services.classifier import classify_domain, _matches_domain


# ============================================================================
# SNI Extractor Tests
# ============================================================================

class TestSNIExtractor:
    """Tests for the SNI extraction from TLS Client Hello packets."""

    def test_not_tls(self):
        """Non-TLS payload should return None."""
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n"
        assert extract_sni(payload) is None

    def test_too_short(self):
        """Payload shorter than minimum TLS record should return None."""
        assert extract_sni(b"") is None
        assert extract_sni(b"\x16\x03") is None
        assert extract_sni(b"\x16\x03\x01") is None

    def test_is_tls_client_hello_check(self):
        """Quick check for TLS Client Hello identification."""
        # Not TLS at all
        assert is_tls_client_hello(b"Hello") is False
        # Too short
        assert is_tls_client_hello(b"\x16\x03") is False

    def test_valid_tls_client_hello(self):
        """
        Test extraction from a real-ish TLS Client Hello.
        This constructs a minimal valid Client Hello with an SNI extension.
        """
        # Build a minimal TLS Client Hello with SNI for "example.com"
        hostname = b"example.com"
        
        # SNI extension payload
        sni_extension = (
            b"\x00\x00"  # Extension type: SNI (0x0000)
            + (len(hostname) + 5).to_bytes(2, "big")  # Extension length
            + (len(hostname) + 3).to_bytes(2, "big")  # SNI list length
            + b"\x00"  # SNI type: hostname
            + len(hostname).to_bytes(2, "big")  # SNI length
            + hostname  # The hostname
        )
        
        extensions = len(sni_extension).to_bytes(2, "big") + sni_extension
        
        # Client Hello body (after handshake header)
        client_hello = (
            b"\x03\x03"  # Client version: TLS 1.2
            + b"\x00" * 32  # Random (32 bytes)
            + b"\x00"  # Session ID length: 0
            + b"\x00\x02\x00\xff"  # Cipher suites: 2 bytes, 1 suite
            + b"\x01\x00"  # Compression: 1 method (null)
            + extensions
        )
        
        # Handshake header
        handshake = (
            b"\x01"  # Client Hello
            + len(client_hello).to_bytes(3, "big")  # Length (3 bytes)
            + client_hello
        )
        
        # TLS Record
        tls_record = (
            b"\x16"  # Content type: Handshake
            + b"\x03\x01"  # TLS 1.0
            + len(handshake).to_bytes(2, "big")  # Record length
            + handshake
        )
        
        result = extract_sni(tls_record)
        assert result == "example.com"


# ============================================================================
# Classifier Tests
# ============================================================================

class TestClassifier:
    """Tests for domain-to-app classification using suffix matching."""

    def test_exact_match(self):
        """Exact domain match should classify correctly."""
        assert classify_domain("youtube.com") == "YouTube"
        assert classify_domain("facebook.com") == "Facebook"
        assert classify_domain("netflix.com") == "Netflix"

    def test_subdomain_match(self):
        """Subdomain should match the parent domain."""
        assert classify_domain("www.youtube.com") == "YouTube"
        assert classify_domain("api.github.com") == "GitHub"
        assert classify_domain("cdn.discord.com") == "Discord"

    def test_no_substring_match(self):
        """Substring-only match should NOT classify as the app."""
        # This was the bug in the C++ engine before the fix
        assert classify_domain("youtubedownloader.com") != "YouTube"
        assert classify_domain("notgoogle.com") != "Google"
        assert classify_domain("myfacebook.com") != "Facebook"

    def test_case_insensitive(self):
        """Classification should be case-insensitive."""
        assert classify_domain("YouTube.COM") == "YouTube"
        assert classify_domain("WWW.NETFLIX.COM") == "Netflix"

    def test_googlevideo_is_youtube(self):
        """googlevideo.com is YouTube's CDN, not Google."""
        assert classify_domain("r1---sn-abc.googlevideo.com") == "YouTube"
        assert classify_domain("googlevideo.com") == "YouTube"

    def test_unknown_domain(self):
        """Unknown domain with SNI should be classified as HTTPS, not Unknown."""
        assert classify_domain("random-website.example.org") == "HTTPS"

    def test_empty_sni(self):
        """Empty SNI should return Unknown."""
        assert classify_domain("") == "Unknown"
        assert classify_domain(None) == "Unknown"

    def test_matches_domain_helper(self):
        """Test the internal _matches_domain function directly."""
        assert _matches_domain("youtube.com", "youtube.com") is True
        assert _matches_domain("www.youtube.com", "youtube.com") is True
        assert _matches_domain("youtubedownloader.com", "youtube.com") is False
        assert _matches_domain("com", "youtube.com") is False
