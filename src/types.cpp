#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

// ============================================================================
// Domain Suffix Matching — FIX for naive substring matching bug
// ============================================================================
//
// The old code used sni.find("youtube") which would incorrectly match
// "youtubedownloader.com" as YouTube. In production DPI systems, suffix
// matching is the correct approach:
//   "youtube.com"          matches "youtube.com"       ✓ (exact)
//   "www.youtube.com"      matches "youtube.com"       ✓ (subdomain)
//   "youtubedownloader.com" does NOT match "youtube.com" ✓ (different domain)
//
// This is critical for correctness — a substring match could cause
// legitimate traffic to be misclassified or incorrectly blocked.
// ============================================================================

static bool matchesDomain(const std::string& sni, const std::string& domain) {
    // Exact match — "youtube.com" == "youtube.com"
    if (sni == domain) return true;

    // Subdomain match — "www.youtube.com" ends with ".youtube.com"
    if (sni.size() > domain.size()) {
        std::string suffix = "." + domain;
        return sni.size() >= suffix.size() &&
               sni.compare(sni.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    return false;
}

// Structure to hold domain-to-app mappings for clean iteration
struct AppMapping {
    AppType app;
    const char* domains[4];  // null-terminated list, max 4 domains per app
};

// Every app's known domain signatures.
// Order matters: more specific apps (YouTube) are checked before
// broader ones (Google) to avoid misclassification.
static const AppMapping APP_MAPPINGS[] = {
    // YouTube checked before Google because googlevideo.com serves YouTube content
    { AppType::YOUTUBE,    { "youtube.com", "youtu.be", "googlevideo.com", nullptr } },
    { AppType::FACEBOOK,   { "facebook.com", "fb.com", "fbcdn.net", nullptr } },
    { AppType::INSTAGRAM,  { "instagram.com", "cdninstagram.com", nullptr, nullptr } },
    { AppType::WHATSAPP,   { "whatsapp.com", "whatsapp.net", nullptr, nullptr } },
    { AppType::GOOGLE,     { "google.com", "googleapis.com", "gstatic.com", nullptr } },
    { AppType::NETFLIX,    { "netflix.com", "nflxvideo.net", nullptr, nullptr } },
    { AppType::TIKTOK,     { "tiktok.com", "tiktokcdn.com", nullptr, nullptr } },
    { AppType::SPOTIFY,    { "spotify.com", "scdn.co", nullptr, nullptr } },
    { AppType::TWITTER,    { "twitter.com", "twimg.com", "x.com", nullptr } },
    { AppType::AMAZON,     { "amazon.com", "amazonaws.com", nullptr, nullptr } },
    { AppType::MICROSOFT,  { "microsoft.com", "live.com", "office.com", nullptr } },
    { AppType::APPLE,      { "apple.com", "icloud.com", nullptr, nullptr } },
    { AppType::TELEGRAM,   { "telegram.org", "t.me", nullptr, nullptr } },
    { AppType::ZOOM,       { "zoom.us", "zoom.com", nullptr, nullptr } },
    { AppType::DISCORD,    { "discord.com", "discordapp.com", nullptr, nullptr } },
    { AppType::GITHUB,     { "github.com", "githubusercontent.com", nullptr, nullptr } },
    { AppType::CLOUDFLARE, { "cloudflare.com", nullptr, nullptr, nullptr } },
};

// Map SNI/domain to application type using proper suffix matching
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for case-insensitive matching
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    // Iterate through all known app domain mappings
    for (const auto& mapping : APP_MAPPINGS) {
        for (int i = 0; mapping.domains[i] != nullptr; i++) {
            if (matchesDomain(lower_sni, mapping.domains[i])) {
                return mapping.app;
            }
        }
    }
    
    // If SNI is present but not recognized, still mark as TLS/HTTPS
    // This is better than UNKNOWN because we know it's encrypted web traffic
    return AppType::HTTPS;
}

} // namespace DPI
