#include "rule_manager.h"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <cstdio>

namespace DPI {

// ============================================================================
// Helper Functions
// ============================================================================

std::string RuleManager::trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

// ============================================================================
// IP Blocking
// ============================================================================

uint32_t RuleManager::parseIP(const std::string& ip) {
    uint32_t result = 0;
    int octet = 0;
    int shift = 0;
    
    for (char c : ip) {
        if (c == '.') {
            result |= (octet << shift);
            shift += 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    result |= (octet << shift);
    
    return result;
}

std::string RuleManager::ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

void RuleManager::blockIP(uint32_t ip) {
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_ips_.insert(ip);
    std::cout << "[RuleManager] Blocked IP: " << ipToString(ip) << std::endl;
}

void RuleManager::blockIP(const std::string& ip) {
    blockIP(parseIP(ip));
}

void RuleManager::unblockIP(uint32_t ip) {
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_ips_.erase(ip);
    std::cout << "[RuleManager] Unblocked IP: " << ipToString(ip) << std::endl;
}

void RuleManager::unblockIP(const std::string& ip) {
    unblockIP(parseIP(ip));
}

bool RuleManager::isIPBlocked(uint32_t ip) const {
    std::shared_lock<std::shared_mutex> lock(ip_mutex_);
    return blocked_ips_.count(ip) > 0;
}

std::vector<std::string> RuleManager::getBlockedIPs() const {
    std::shared_lock<std::shared_mutex> lock(ip_mutex_);
    std::vector<std::string> result;
    for (uint32_t ip : blocked_ips_) {
        result.push_back(ipToString(ip));
    }
    return result;
}

// ============================================================================
// Application Blocking
// ============================================================================

void RuleManager::blockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(app_mutex_);
    blocked_apps_.insert(app);
    std::cout << "[RuleManager] Blocked app: " << appTypeToString(app) << std::endl;
}

void RuleManager::unblockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(app_mutex_);
    blocked_apps_.erase(app);
    std::cout << "[RuleManager] Unblocked app: " << appTypeToString(app) << std::endl;
}

bool RuleManager::isAppBlocked(AppType app) const {
    std::shared_lock<std::shared_mutex> lock(app_mutex_);
    return blocked_apps_.count(app) > 0;
}

std::vector<AppType> RuleManager::getBlockedApps() const {
    std::shared_lock<std::shared_mutex> lock(app_mutex_);
    return std::vector<AppType>(blocked_apps_.begin(), blocked_apps_.end());
}

// ============================================================================
// Domain Blocking
// ============================================================================

void RuleManager::blockDomain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    
    if (domain.find('*') != std::string::npos) {
        domain_patterns_.push_back(domain);
    } else {
        blocked_domains_.insert(domain);
    }
    
    std::cout << "[RuleManager] Blocked domain: " << domain << std::endl;
}

void RuleManager::unblockDomain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    
    if (domain.find('*') != std::string::npos) {
        auto it = std::find(domain_patterns_.begin(), domain_patterns_.end(), domain);
        if (it != domain_patterns_.end()) {
            domain_patterns_.erase(it);
        }
    } else {
        blocked_domains_.erase(domain);
    }
    
    std::cout << "[RuleManager] Unblocked domain: " << domain << std::endl;
}

bool RuleManager::domainMatchesPattern(const std::string& domain, const std::string& pattern) {
    // Handle *.example.com pattern
    if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        std::string suffix = pattern.substr(1);  // .example.com
        
        // Check if domain ends with the pattern
        if (domain.size() >= suffix.size() &&
            domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
        
        // Also match the bare domain (example.com matches *.example.com)
        if (domain == pattern.substr(2)) {
            return true;
        }
    }
    
    return false;
}

bool RuleManager::isDomainBlocked(const std::string& domain) const {
    std::shared_lock<std::shared_mutex> lock(domain_mutex_);
    
    // Check exact match
    if (blocked_domains_.count(domain) > 0) {
        return true;
    }
    
    // Check patterns
    std::string lower_domain = domain;
    std::transform(lower_domain.begin(), lower_domain.end(), lower_domain.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    for (const auto& pattern : domain_patterns_) {
        std::string lower_pattern = pattern;
        std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        
        if (domainMatchesPattern(lower_domain, lower_pattern)) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> RuleManager::getBlockedDomains() const {
    std::shared_lock<std::shared_mutex> lock(domain_mutex_);
    std::vector<std::string> result(blocked_domains_.begin(), blocked_domains_.end());
    result.insert(result.end(), domain_patterns_.begin(), domain_patterns_.end());
    return result;
}

// ============================================================================
// Port Blocking
// ============================================================================

void RuleManager::blockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(port_mutex_);
    blocked_ports_.insert(port);
    std::cout << "[RuleManager] Blocked port: " << port << std::endl;
}

void RuleManager::unblockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(port_mutex_);
    blocked_ports_.erase(port);
}

bool RuleManager::isPortBlocked(uint16_t port) const {
    std::shared_lock<std::shared_mutex> lock(port_mutex_);
    return blocked_ports_.count(port) > 0;
}

// ============================================================================
// Combined Check
// ============================================================================

std::optional<RuleManager::BlockReason> RuleManager::shouldBlock(
    uint32_t src_ip,
    uint16_t dst_port,
    AppType app,
    const std::string& domain) const {
    
    // Check IP first (most specific)
    if (isIPBlocked(src_ip)) {
        return BlockReason{BlockReason::IP, ipToString(src_ip)};
    }
    
    // Check port
    if (isPortBlocked(dst_port)) {
        return BlockReason{BlockReason::PORT, std::to_string(dst_port)};
    }
    
    // Check app
    if (isAppBlocked(app)) {
        return BlockReason{BlockReason::APP, appTypeToString(app)};
    }
    
    // Check domain
    if (!domain.empty() && isDomainBlocked(domain)) {
        return BlockReason{BlockReason::DOMAIN_RULE, domain};
    }
    
    return std::nullopt;
}

// ============================================================================
// Persistence — .ini format (original, preserved)
// ============================================================================

bool RuleManager::saveRules(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    // Save blocked IPs
    file << "[BLOCKED_IPS]\n";
    for (const auto& ip : getBlockedIPs()) {
        file << ip << "\n";
    }
    
    // Save blocked apps
    file << "\n[BLOCKED_APPS]\n";
    for (const auto& app : getBlockedApps()) {
        file << appTypeToString(app) << "\n";
    }
    
    // Save blocked domains
    file << "\n[BLOCKED_DOMAINS]\n";
    for (const auto& domain : getBlockedDomains()) {
        file << domain << "\n";
    }
    
    // Save blocked ports
    file << "\n[BLOCKED_PORTS]\n";
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        for (uint16_t port : blocked_ports_) {
            file << port << "\n";
        }
    }
    
    file.close();
    std::cout << "[RuleManager] Rules saved to: " << filename << std::endl;
    return true;
}

bool RuleManager::loadRules(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    std::string current_section;
    
    while (std::getline(file, line)) {
        // Skip empty lines
        if (line.empty()) continue;
        
        // Check for section headers
        if (line[0] == '[') {
            current_section = line;
            continue;
        }
        
        // Process based on section
        if (current_section == "[BLOCKED_IPS]") {
            blockIP(line);
        } else if (current_section == "[BLOCKED_APPS]") {
            // Convert string back to AppType
            for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
                if (appTypeToString(static_cast<AppType>(i)) == line) {
                    blockApp(static_cast<AppType>(i));
                    break;
                }
            }
        } else if (current_section == "[BLOCKED_DOMAINS]") {
            blockDomain(line);
        } else if (current_section == "[BLOCKED_PORTS]") {
            blockPort(static_cast<uint16_t>(std::stoi(line)));
        }
    }
    
    file.close();
    last_loaded_time_ = std::chrono::system_clock::now();
    std::cout << "[RuleManager] Rules loaded from: " << filename << std::endl;
    return true;
}

// ============================================================================
// Persistence — JSON format (new)
// ============================================================================
//
// JSON format:
// {
//   "blocked_ips": ["192.168.1.50"],
//   "blocked_apps": ["YouTube", "TikTok"],
//   "blocked_domains": ["tiktok.com", "*.ads.google.com"],
//   "blocked_ports": [6881],
//   "updated_at": "2024-01-15T10:00:00Z"
// }
//
// Uses stdlib only — no nlohmann, no rapidjson.
// JSON escaping is minimal since IPs/domains/app names are simple strings.
// ============================================================================

static std::string jsonEscapeStr(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            default:   out += c;      break;
        }
    }
    return out;
}

bool RuleManager::saveRulesJSON(const std::string& filename) const {
    std::ostringstream j;
    j << "{\n";
    
    // Blocked IPs
    j << "  \"blocked_ips\": [";
    auto ips = getBlockedIPs();
    for (size_t i = 0; i < ips.size(); i++) {
        if (i > 0) j << ", ";
        j << "\"" << jsonEscapeStr(ips[i]) << "\"";
    }
    j << "],\n";
    
    // Blocked apps
    j << "  \"blocked_apps\": [";
    auto apps = getBlockedApps();
    for (size_t i = 0; i < apps.size(); i++) {
        if (i > 0) j << ", ";
        j << "\"" << jsonEscapeStr(appTypeToString(apps[i])) << "\"";
    }
    j << "],\n";
    
    // Blocked domains
    j << "  \"blocked_domains\": [";
    auto domains = getBlockedDomains();
    for (size_t i = 0; i < domains.size(); i++) {
        if (i > 0) j << ", ";
        j << "\"" << jsonEscapeStr(domains[i]) << "\"";
    }
    j << "],\n";
    
    // Blocked ports
    j << "  \"blocked_ports\": [";
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        bool first = true;
        for (uint16_t port : blocked_ports_) {
            if (!first) j << ", ";
            first = false;
            j << port;
        }
    }
    j << "],\n";
    
    // Timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    gmtime_r(&time_t, &tm_buf);
    char time_str[32];
    std::strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    j << "  \"updated_at\": \"" << time_str << "\"\n";
    
    j << "}\n";
    
    // Atomic write: temp file first, then rename
    std::string temp = filename + ".tmp";
    std::ofstream f(temp);
    if (!f.is_open()) return false;
    f << j.str();
    f.close();
    
    if (!f.good()) {
        std::remove(temp.c_str());
        return false;
    }
    
    if (std::rename(temp.c_str(), filename.c_str()) != 0) {
        std::remove(temp.c_str());
        return false;
    }
    
    std::cout << "[RuleManager] Rules saved (JSON) to: " << filename << std::endl;
    return true;
}

// Simple JSON array parser: extracts string values from a JSON array
// Input: ["value1", "value2", "value3"]
// Returns: vector of unquoted strings
static std::vector<std::string> parseJSONStringArray(const std::string& arr) {
    std::vector<std::string> result;
    bool in_string = false;
    std::string current;
    
    for (size_t i = 0; i < arr.size(); i++) {
        char c = arr[i];
        
        if (c == '"' && (i == 0 || arr[i-1] != '\\')) {
            if (in_string) {
                result.push_back(current);
                current.clear();
            }
            in_string = !in_string;
        } else if (in_string) {
            if (c == '\\' && i + 1 < arr.size()) {
                // Handle escaped characters
                i++;
                switch (arr[i]) {
                    case '"':  current += '"'; break;
                    case '\\': current += '\\'; break;
                    default:   current += arr[i]; break;
                }
            } else {
                current += c;
            }
        }
    }
    
    return result;
}

// Simple JSON array parser for integers
static std::vector<int> parseJSONIntArray(const std::string& arr) {
    std::vector<int> result;
    std::string current;
    
    for (char c : arr) {
        if (c >= '0' && c <= '9') {
            current += c;
        } else if (!current.empty()) {
            result.push_back(std::stoi(current));
            current.clear();
        }
    }
    if (!current.empty()) {
        result.push_back(std::stoi(current));
    }
    
    return result;
}

bool RuleManager::loadRulesJSON(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cout << "[RuleManager] No rules file found at: " << filename 
                  << " (starting with empty rules)\n";
        return false;
    }
    
    // Read entire file
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    file.close();
    
    // Clear existing rules before loading
    clearAll();
    
    // Simple key-based parsing: find each array by key name
    auto findArray = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\"";
        size_t pos = content.find(search);
        if (pos == std::string::npos) return "";
        
        // Find the opening bracket
        size_t bracket_start = content.find('[', pos);
        if (bracket_start == std::string::npos) return "";
        
        // Find matching closing bracket
        int depth = 0;
        size_t bracket_end = bracket_start;
        for (size_t i = bracket_start; i < content.size(); i++) {
            if (content[i] == '[') depth++;
            if (content[i] == ']') depth--;
            if (depth == 0) {
                bracket_end = i;
                break;
            }
        }
        
        return content.substr(bracket_start, bracket_end - bracket_start + 1);
    };
    
    // Load blocked IPs
    auto ip_arr = findArray("blocked_ips");
    if (!ip_arr.empty()) {
        for (const auto& ip : parseJSONStringArray(ip_arr)) {
            blockIP(ip);
        }
    }
    
    // Load blocked apps
    auto app_arr = findArray("blocked_apps");
    if (!app_arr.empty()) {
        for (const auto& app_name : parseJSONStringArray(app_arr)) {
            for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
                if (appTypeToString(static_cast<AppType>(i)) == app_name) {
                    blockApp(static_cast<AppType>(i));
                    break;
                }
            }
        }
    }
    
    // Load blocked domains
    auto domain_arr = findArray("blocked_domains");
    if (!domain_arr.empty()) {
        for (const auto& domain : parseJSONStringArray(domain_arr)) {
            blockDomain(domain);
        }
    }
    
    // Load blocked ports
    auto port_arr = findArray("blocked_ports");
    if (!port_arr.empty()) {
        for (int port : parseJSONIntArray(port_arr)) {
            if (port > 0 && port <= 65535) {
                blockPort(static_cast<uint16_t>(port));
            }
        }
    }
    
    last_loaded_time_ = std::chrono::system_clock::now();
    std::cout << "[RuleManager] Rules loaded (JSON) from: " << filename << std::endl;
    return true;
}

// ============================================================================
// Hot-Reload Support
// ============================================================================

bool RuleManager::reloadIfModified(const std::string& filename) {
    try {
        auto ftime = std::filesystem::last_write_time(filename);
        // Convert file_time to system_clock for comparison
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - std::filesystem::file_time_type::clock::now() 
            + std::chrono::system_clock::now());
        
        if (sctp > last_loaded_time_) {
            std::cout << "[RuleManager] Rules file modified, reloading...\n";
            
            // Detect format by extension
            if (filename.size() >= 5 && 
                filename.substr(filename.size() - 5) == ".json") {
                return loadRulesJSON(filename);
            }
            return loadRules(filename);
        }
    } catch (const std::exception& e) {
        // File might not exist or be inaccessible — not an error
    }
    
    return false;
}

// ============================================================================
// Utilities
// ============================================================================

void RuleManager::clearAll() {
    {
        std::unique_lock<std::shared_mutex> lock(ip_mutex_);
        blocked_ips_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(app_mutex_);
        blocked_apps_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(domain_mutex_);
        blocked_domains_.clear();
        domain_patterns_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(port_mutex_);
        blocked_ports_.clear();
    }
    std::cout << "[RuleManager] All rules cleared" << std::endl;
}

RuleManager::RuleStats RuleManager::getStats() const {
    RuleStats stats;
    
    {
        std::shared_lock<std::shared_mutex> lock(ip_mutex_);
        stats.blocked_ips = blocked_ips_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(app_mutex_);
        stats.blocked_apps = blocked_apps_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(domain_mutex_);
        stats.blocked_domains = blocked_domains_.size() + domain_patterns_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        stats.blocked_ports = blocked_ports_.size();
    }
    
    return stats;
}

} // namespace DPI
