#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include "types.h"
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <optional>
#include <vector>
#include <fstream>
#include <chrono>

namespace DPI {

// ============================================================================
// Rule Manager - Manages blocking/filtering rules
// ============================================================================
// 
// Rules can be:
// 1. IP-based: Block specific source IPs
// 2. App-based: Block specific applications (detected via SNI)
// 3. Domain-based: Block specific domains
// 4. Port-based: Block specific destination ports
//
// Rules are thread-safe for concurrent access from FP threads.
// Supports both .ini and .json persistence formats.
// ============================================================================

class RuleManager {
public:
    RuleManager() = default;
    
    // ========== IP Blocking ==========
    
    void blockIP(uint32_t ip);
    void blockIP(const std::string& ip);
    void unblockIP(uint32_t ip);
    void unblockIP(const std::string& ip);
    bool isIPBlocked(uint32_t ip) const;
    std::vector<std::string> getBlockedIPs() const;
    
    // ========== Application Blocking ==========
    
    void blockApp(AppType app);
    void unblockApp(AppType app);
    bool isAppBlocked(AppType app) const;
    std::vector<AppType> getBlockedApps() const;
    
    // ========== Domain Blocking ==========
    
    void blockDomain(const std::string& domain);
    void unblockDomain(const std::string& domain);
    bool isDomainBlocked(const std::string& domain) const;
    std::vector<std::string> getBlockedDomains() const;
    
    // ========== Port Blocking ==========
    
    void blockPort(uint16_t port);
    void unblockPort(uint16_t port);
    bool isPortBlocked(uint16_t port) const;
    
    // ========== Combined Check ==========
    
    struct BlockReason {
        enum Type { IP, APP, DOMAIN_RULE, PORT } type;
        std::string detail;
    };
    
    std::optional<BlockReason> shouldBlock(
        uint32_t src_ip,
        uint16_t dst_port,
        AppType app,
        const std::string& domain) const;
    
    // ========== Rule Persistence (.ini format) ==========
    
    bool saveRules(const std::string& filename) const;
    bool loadRules(const std::string& filename);
    
    // ========== Rule Persistence (.json format) ==========
    
    bool saveRulesJSON(const std::string& filename) const;
    bool loadRulesJSON(const std::string& filename);
    
    // Check if rules file has been modified since last load and reload if so.
    // Used by the hot-reload thread in DPIEngine.
    bool reloadIfModified(const std::string& filename);
    
    // ========== Utilities ==========
    
    void clearAll();
    
    struct RuleStats {
        size_t blocked_ips;
        size_t blocked_apps;
        size_t blocked_domains;
        size_t blocked_ports;
    };
    
    RuleStats getStats() const;

private:
    // Thread-safe containers with read-write locks
    mutable std::shared_mutex ip_mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    
    mutable std::shared_mutex app_mutex_;
    std::unordered_set<AppType> blocked_apps_;
    
    mutable std::shared_mutex domain_mutex_;
    std::unordered_set<std::string> blocked_domains_;
    std::vector<std::string> domain_patterns_;  // For wildcard matching
    
    mutable std::shared_mutex port_mutex_;
    std::unordered_set<uint16_t> blocked_ports_;
    
    // Track last modification time for hot-reload
    std::chrono::system_clock::time_point last_loaded_time_;
    
    // Helper: Convert IP string to uint32
    static uint32_t parseIP(const std::string& ip);
    
    // Helper: Convert uint32 to IP string
    static std::string ipToString(uint32_t ip);
    
    // Helper: Check if domain matches pattern (supports wildcards)
    static bool domainMatchesPattern(const std::string& domain, const std::string& pattern);
    
    // Helper: Trim whitespace from a string
    static std::string trim(const std::string& s);
};

} // namespace DPI

#endif // RULE_MANAGER_H
