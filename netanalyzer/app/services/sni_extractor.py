"""
SNI Extractor — Extracts Server Name Indication from TLS Client Hello packets.

In a DPI system, the SNI field is the most important signal for identifying
which website/app a user is accessing over HTTPS. Without SNI extraction,
all HTTPS traffic would be opaque (we'd only see IP addresses).

How SNI extraction works:
1. Check if the TCP payload starts with a TLS record (content type 0x16)
2. Parse the TLS Handshake header to find a Client Hello (type 0x01)
3. Skip over the random bytes, session ID, cipher suites, compression methods
4. Parse the extensions section to find extension type 0x0000 (SNI)
5. Read the hostname from the SNI extension

This is the Python equivalent of include/sni_extractor.h in the C++ engine.
"""

import struct
from typing import Optional


def extract_sni(payload: bytes) -> Optional[str]:
    """
    Extract the Server Name Indication (SNI) from a TLS Client Hello packet.

    Args:
        payload: Raw TCP payload bytes (starting after the TCP header)

    Returns:
        The hostname string (e.g., 'www.youtube.com') or None if not a TLS
        Client Hello or the SNI extension is not present.
    """
    # Need at least 5 bytes for the TLS record header
    if len(payload) < 5:
        return None

    # Check TLS record: content type must be 0x16 (Handshake)
    content_type = payload[0]
    if content_type != 0x16:
        return None

    # TLS version (2 bytes) — we accept any TLS version
    # Record length (2 bytes)
    try:
        tls_version = struct.unpack("!H", payload[1:3])[0]
        record_length = struct.unpack("!H", payload[3:5])[0]
    except struct.error:
        return None

    # Sanity check: record shouldn't be larger than remaining data
    if 5 + record_length > len(payload):
        return None

    # Parse the handshake header (starts at offset 5)
    offset = 5

    # Handshake type must be 0x01 (Client Hello)
    if offset >= len(payload) or payload[offset] != 0x01:
        return None
    offset += 1

    # Handshake length (3 bytes, big-endian)
    if offset + 3 > len(payload):
        return None
    handshake_length = (payload[offset] << 16) | (payload[offset + 1] << 8) | payload[offset + 2]
    offset += 3

    # Client version (2 bytes) — skip
    offset += 2

    # Client random (32 bytes) — skip
    offset += 32

    if offset >= len(payload):
        return None

    # Session ID (variable length, prefixed by 1-byte length)
    session_id_length = payload[offset]
    offset += 1 + session_id_length

    if offset + 2 > len(payload):
        return None

    # Cipher suites (variable length, prefixed by 2-byte length)
    cipher_suites_length = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2 + cipher_suites_length

    if offset >= len(payload):
        return None

    # Compression methods (variable length, prefixed by 1-byte length)
    compression_length = payload[offset]
    offset += 1 + compression_length

    if offset + 2 > len(payload):
        return None

    # Extensions section (variable length, prefixed by 2-byte length)
    extensions_length = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2

    # Walk through extensions to find SNI (type 0x0000)
    extensions_end = offset + extensions_length

    while offset + 4 <= extensions_end and offset + 4 <= len(payload):
        # Extension type (2 bytes)
        ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
        # Extension length (2 bytes)
        ext_length = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
        offset += 4

        if ext_type == 0x0000:  # SNI extension
            # SNI extension contains:
            #   - SNI list length (2 bytes)
            #   - SNI type (1 byte): 0x00 = hostname
            #   - SNI length (2 bytes)
            #   - SNI value (variable)
            if offset + 5 > len(payload):
                return None

            # Skip SNI list length
            offset += 2

            # SNI type (must be 0x00 for hostname)
            sni_type = payload[offset]
            offset += 1

            if sni_type != 0x00:
                return None

            # SNI hostname length
            sni_length = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2

            if offset + sni_length > len(payload):
                return None

            # Extract the hostname
            hostname = payload[offset:offset + sni_length].decode("ascii", errors="ignore")
            return hostname.lower()

        # Skip to next extension
        offset += ext_length

    return None


def is_tls_client_hello(payload: bytes) -> bool:
    """
    Quick check if a TCP payload looks like a TLS Client Hello.
    Used as a fast-path filter before attempting full SNI extraction.
    """
    if len(payload) < 6:
        return False

    # Content type 0x16 (Handshake) + handshake type 0x01 (Client Hello)
    return payload[0] == 0x16 and payload[5] == 0x01
