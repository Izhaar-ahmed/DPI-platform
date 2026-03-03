"""
Traffic Classifier — Maps domain names to application types.

Uses the same suffix matching algorithm as the C++ engine's types.cpp.
This ensures both engines produce identical classification results for
the same traffic.

Why suffix matching (not substring):
  - "youtube.com"    matches "youtube.com"         ✓ (exact)
  - "www.youtube.com" matches "youtube.com"        ✓ (subdomain)
  - "youtubedownloader.com" does NOT match         ✓ (different domain)

The C++ engine had a bug where it used sni.find() (substring matching)
which caused false positives. Both engines now use proper suffix matching.
"""

from typing import Optional


# Domain-to-app mapping table.
# Order matters: YouTube is checked before Google because
# googlevideo.com is a YouTube CDN domain that would otherwise
# be misclassified as Google.
APP_DOMAIN_MAP: dict[str, list[str]] = {
    "YouTube":    ["youtube.com", "youtu.be", "googlevideo.com"],
    "Facebook":   ["facebook.com", "fb.com", "fbcdn.net"],
    "Instagram":  ["instagram.com", "cdninstagram.com"],
    "WhatsApp":   ["whatsapp.com", "whatsapp.net"],
    "Google":     ["google.com", "googleapis.com", "gstatic.com"],
    "Netflix":    ["netflix.com", "nflxvideo.net"],
    "TikTok":     ["tiktok.com", "tiktokcdn.com"],
    "Spotify":    ["spotify.com", "scdn.co"],
    "Twitter/X":  ["twitter.com", "twimg.com", "x.com"],
    "Amazon":     ["amazon.com", "amazonaws.com"],
    "Microsoft":  ["microsoft.com", "live.com", "office.com"],
    "Apple":      ["apple.com", "icloud.com"],
    "Telegram":   ["telegram.org", "t.me"],
    "Zoom":       ["zoom.us", "zoom.com"],
    "Discord":    ["discord.com", "discordapp.com"],
    "GitHub":     ["github.com", "githubusercontent.com"],
    "Cloudflare": ["cloudflare.com"],
}


def _matches_domain(sni: str, domain: str) -> bool:
    """
    Check if an SNI matches a domain using proper suffix matching.

    Rules:
      - Exact match: "youtube.com" == "youtube.com"
      - Subdomain match: "www.youtube.com" ends with ".youtube.com"
      - NOT substring: "youtubedownloader.com" != "youtube.com"
    """
    if sni == domain:
        return True

    # Check if sni ends with ".domain" (subdomain match)
    suffix = "." + domain
    return sni.endswith(suffix)


def classify_domain(sni: str) -> str:
    """
    Classify a domain (SNI) into an application type.

    Args:
        sni: Server Name Indication hostname (e.g., 'www.youtube.com')

    Returns:
        Application name (e.g., 'YouTube') or 'Unknown' if not recognized.
    """
    if not sni:
        return "Unknown"

    # Normalize to lowercase for case-insensitive matching
    sni_lower = sni.lower().strip()

    for app_name, domains in APP_DOMAIN_MAP.items():
        for domain in domains:
            if _matches_domain(sni_lower, domain):
                return app_name

    # SNI present but unrecognized — still mark as HTTPS rather than Unknown
    # because we know it's encrypted web traffic
    return "HTTPS"
