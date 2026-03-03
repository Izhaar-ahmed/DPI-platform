#include "dpi_engine.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace DPI {

// ============================================================================
// DPIEngine Implementation
// ============================================================================

DPIEngine::DPIEngine(const Config& config)
    : config_(config), output_queue_(10000) {
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    DPI ENGINE v1.0                            ║\n";
    std::cout << "║               Deep Packet Inspection System                   ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Configuration:                                                ║\n";
    std::cout << "║   Load Balancers:    " << std::setw(3) << config.num_load_balancers << "                                       ║\n";
    std::cout << "║   FPs per LB:        " << std::setw(3) << config.fps_per_lb << "                                       ║\n";
    std::cout << "║   Total FP threads:  " << std::setw(3) << (config.num_load_balancers * config.fps_per_lb) << "                                       ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

DPIEngine::~DPIEngine() {
    // Stop hot-reload thread
    reload_running_ = false;
    if (reload_thread_.joinable()) {
        reload_thread_.join();
    }
    stop();
}

bool DPIEngine::initialize() {
    // Create rule manager
    rule_manager_ = std::make_unique<RuleManager>();
    
    // Load rules if specified
    if (!config_.rules_file.empty()) {
        loadRules(config_.rules_file);
    }
    
    // Create output callback
    auto output_cb = [this](const PacketJob& job, PacketAction action) {
        handleOutput(job, action);
    };
    
    // Create FP manager (creates FP threads and their queues)
    int total_fps = config_.num_load_balancers * config_.fps_per_lb;
    fp_manager_ = std::make_unique<FPManager>(total_fps, rule_manager_.get(), output_cb);
    
    // Create LB manager (creates LB threads, connects to FP queues)
    lb_manager_ = std::make_unique<LBManager>(
        config_.num_load_balancers,
        config_.fps_per_lb,
        fp_manager_->getQueuePtrs()
    );
    
    // Create global connection table
    global_conn_table_ = std::make_unique<GlobalConnectionTable>(total_fps);
    for (int i = 0; i < total_fps; i++) {
        global_conn_table_->registerTracker(i, &fp_manager_->getFP(i).getConnectionTracker());
    }
    
    std::cout << "[DPIEngine] Initialized successfully\n";
    return true;
}

void DPIEngine::start() {
    if (running_) return;
    
    running_ = true;
    processing_complete_ = false;
    
    // Start output thread
    output_thread_ = std::thread(&DPIEngine::outputThreadFunc, this);
    
    // Start FP threads
    fp_manager_->startAll();
    
    // Start LB threads
    lb_manager_->startAll();
    
    // Start hot-reload thread if a rules file is configured
    if (!config_.rules_file.empty()) {
        reload_running_ = true;
        reload_thread_ = std::thread(&DPIEngine::reloadThreadFunc, this);
    }
    
    std::cout << "[DPIEngine] All threads started\n";
}

void DPIEngine::stop() {
    if (!running_) return;
    
    running_ = false;
    
    // Stop hot-reload thread
    reload_running_ = false;
    if (reload_thread_.joinable()) {
        reload_thread_.join();
    }
    
    // Stop LB threads first (they feed FPs)
    if (lb_manager_) {
        lb_manager_->stopAll();
    }
    
    // Stop FP threads
    if (fp_manager_) {
        fp_manager_->stopAll();
    }
    
    // Stop output thread
    output_queue_.shutdown();
    if (output_thread_.joinable()) {
        output_thread_.join();
    }
    
    std::cout << "[DPIEngine] All threads stopped\n";
}

// ============================================================================
// Pipeline Drain Fix
// ============================================================================
//
// The old code used a naive sleep_for(500ms) which caused packets to be
// lost when the pipeline was still processing. This is a correctness bug:
// under load, 500ms is nowhere near enough for all queues to drain.
//
// The correct shutdown sequence is:
//   1. Reader finishes → signal LB input queues that no more packets come
//   2. Wait for ALL LB input queues to drain → stop LB threads → join
//   3. Wait for ALL FP input queues to drain → stop FP threads → join
//   4. Wait for output queue to drain → stop output thread → join
//   5. Close output file
//
// Each stage waits until the queues are genuinely empty, with a poll
// interval and a hard timeout to prevent infinite hangs.
// ============================================================================

void DPIEngine::waitForCompletion() {
    // Step 1: Wait for reader to finish producing packets
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
    std::cout << "[DPIEngine] Reader finished, draining pipeline...\n";
    
    // Step 2: Signal LB queues to stop accepting new input, then wait
    //         for them to drain all remaining packets to FPs
    if (lb_manager_) {
        // Shutdown all LB input queues so they stop blocking on empty
        for (int i = 0; i < lb_manager_->getNumLBs(); i++) {
            lb_manager_->getLB(i).getInputQueue().shutdown();
        }
        
        // Wait for LB threads to finish processing remaining packets
        // Each LB will naturally exit its run() loop because:
        //   - The queue is shutdown (popWithTimeout returns nullopt)
        //   - running_ flag is checked in loop
        // We give a generous timeout and poll
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        for (int i = 0; i < lb_manager_->getNumLBs(); i++) {
            while (!lb_manager_->getLB(i).getInputQueue().empty()) {
                if (std::chrono::steady_clock::now() > deadline) {
                    std::cerr << "[DPIEngine] Warning: LB" << i 
                              << " queue drain timeout\n";
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        lb_manager_->stopAll();
    }
    std::cout << "[DPIEngine] LB threads drained and stopped\n";
    
    // Step 3: Wait for all FP queues to drain, then stop FP threads
    if (fp_manager_) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        for (int i = 0; i < fp_manager_->getNumFPs(); i++) {
            while (!fp_manager_->getFPQueue(i).empty()) {
                if (std::chrono::steady_clock::now() > deadline) {
                    std::cerr << "[DPIEngine] Warning: FP" << i 
                              << " queue drain timeout\n";
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        fp_manager_->stopAll();
    }
    std::cout << "[DPIEngine] FP threads drained and stopped\n";
    
    // Step 4: Wait for output queue to drain, then stop output thread
    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!output_queue_.empty()) {
            if (std::chrono::steady_clock::now() > deadline) {
                std::cerr << "[DPIEngine] Warning: output queue drain timeout\n";
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        output_queue_.shutdown();
        if (output_thread_.joinable()) {
            output_thread_.join();
        }
    }
    std::cout << "[DPIEngine] Output thread drained and stopped\n";
    
    // Step 5: Close output file
    if (output_file_.is_open()) {
        output_file_.close();
    }
    
    // Mark processing as complete
    processing_complete_ = true;
    running_ = false;
    
    std::cout << "[DPIEngine] Pipeline fully drained\n";
}

bool DPIEngine::processFile(const std::string& input_file,
                            const std::string& output_file) {
    
    std::cout << "\n[DPIEngine] Processing: " << input_file << "\n";
    std::cout << "[DPIEngine] Output to:  " << output_file << "\n\n";
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Initialize if not already done
    if (!rule_manager_) {
        if (!initialize()) {
            return false;
        }
    }
    
    // Open output file
    output_file_.open(output_file, std::ios::binary);
    if (!output_file_.is_open()) {
        std::cerr << "[DPIEngine] Error: Cannot open output file\n";
        return false;
    }
    
    // Start processing threads
    start();
    
    // Start reader thread
    reader_thread_ = std::thread(&DPIEngine::readerThreadFunc, this, input_file);
    
    // Wait for full pipeline drain (fixed version — no more naive sleep)
    waitForCompletion();
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();
    
    std::cout << "[DPIEngine] Processing completed in " << duration_ms << "ms\n";
    
    // Print final report
    std::cout << generateReport();
    std::cout << fp_manager_->generateClassificationReport();
    
    // Write JSON output files
    writeJSONOutput();
    
    return true;
}

void DPIEngine::readerThreadFunc(const std::string& input_file) {
    PacketAnalyzer::PcapReader reader;
    
    if (!reader.open(input_file)) {
        std::cerr << "[Reader] Error: Cannot open input file\n";
        return;
    }
    
    // Write PCAP header to output
    writeOutputHeader(reader.getGlobalHeader());
    
    PacketAnalyzer::RawPacket raw;
    PacketAnalyzer::ParsedPacket parsed;
    uint32_t packet_id = 0;
    
    std::cout << "[Reader] Starting packet processing...\n";
    
    while (reader.readNextPacket(raw)) {
        // Parse the packet
        if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) {
            continue;  // Skip unparseable packets
        }
        
        // Only process IP packets with TCP/UDP
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
            continue;
        }
        
        // Create packet job
        PacketJob job = createPacketJob(raw, parsed, packet_id++);
        
        // Update global stats
        stats_.total_packets++;
        stats_.total_bytes += raw.data.size();
        
        if (parsed.has_tcp) {
            stats_.tcp_packets++;
        } else if (parsed.has_udp) {
            stats_.udp_packets++;
        }
        
        // Send to appropriate LB based on hash
        LoadBalancer& lb = lb_manager_->getLBForPacket(job.tuple);
        lb.getInputQueue().push(std::move(job));
    }
    
    std::cout << "[Reader] Finished reading " << packet_id << " packets\n";
    reader.close();
}

PacketJob DPIEngine::createPacketJob(const PacketAnalyzer::RawPacket& raw,
                                      const PacketAnalyzer::ParsedPacket& parsed,
                                      uint32_t packet_id) {
    PacketJob job;
    job.packet_id = packet_id;
    job.ts_sec = raw.header.ts_sec;
    job.ts_usec = raw.header.ts_usec;
    
    // Set five-tuple - parse IP addresses from string back to uint32
    auto parseIP = [](const std::string& ip) -> uint32_t {
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
    };
    
    job.tuple.src_ip = parseIP(parsed.src_ip);
    job.tuple.dst_ip = parseIP(parsed.dest_ip);
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;
    
    // TCP flags
    job.tcp_flags = parsed.tcp_flags;
    
    // Copy packet data
    job.data = raw.data;
    
    // Calculate offsets
    job.eth_offset = 0;
    job.ip_offset = 14;  // Ethernet header is 14 bytes
    
    // IP header length
    if (job.data.size() > 14) {
        uint8_t ip_ihl = job.data[14] & 0x0F;
        size_t ip_header_len = ip_ihl * 4;
        job.transport_offset = 14 + ip_header_len;
        
        // Transport header length
        if (parsed.has_tcp && job.data.size() > job.transport_offset) {
            uint8_t tcp_data_offset = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
            size_t tcp_header_len = tcp_data_offset * 4;
            job.payload_offset = job.transport_offset + tcp_header_len;
        } else if (parsed.has_udp) {
            job.payload_offset = job.transport_offset + 8;  // UDP header is 8 bytes
        }
        
        if (job.payload_offset < job.data.size()) {
            job.payload_length = job.data.size() - job.payload_offset;
            job.payload_data = job.data.data() + job.payload_offset;
        }
    }
    
    return job;
}

void DPIEngine::outputThreadFunc() {
    // Keep running until the queue is BOTH shutdown AND empty.
    // This ensures all forwarded packets are written before exit.
    while (true) {
        auto job_opt = output_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (job_opt) {
            writeOutputPacket(*job_opt);
        } else if (output_queue_.isShutdown()) {
            // Queue is shutdown and empty — safe to exit
            break;
        }
    }
}

void DPIEngine::handleOutput(const PacketJob& job, PacketAction action) {
    if (action == PacketAction::DROP) {
        stats_.dropped_packets++;
        return;
    }
    
    stats_.forwarded_packets++;
    output_queue_.push(job);
}

bool DPIEngine::writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return false;
    
    output_file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return output_file_.good();
}

void DPIEngine::writeOutputPacket(const PacketJob& job) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return;
    
    // Write packet header
    PacketAnalyzer::PcapPacketHeader pkt_header;
    pkt_header.ts_sec = job.ts_sec;
    pkt_header.ts_usec = job.ts_usec;
    pkt_header.incl_len = job.data.size();
    pkt_header.orig_len = job.data.size();
    
    output_file_.write(reinterpret_cast<const char*>(&pkt_header), sizeof(pkt_header));
    output_file_.write(reinterpret_cast<const char*>(job.data.data()), job.data.size());
}

// ============================================================================
// Rule Management API
// ============================================================================

void DPIEngine::blockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->blockIP(ip);
    }
}

void DPIEngine::unblockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->unblockIP(ip);
    }
}

void DPIEngine::blockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->blockApp(app);
    }
}

void DPIEngine::blockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            blockApp(static_cast<AppType>(i));
            return;
        }
    }
    std::cerr << "[DPIEngine] Unknown app: " << app_name << "\n";
}

void DPIEngine::unblockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->unblockApp(app);
    }
}

void DPIEngine::unblockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            unblockApp(static_cast<AppType>(i));
            return;
        }
    }
}

void DPIEngine::blockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->blockDomain(domain);
    }
}

void DPIEngine::unblockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->unblockDomain(domain);
    }
}

bool DPIEngine::loadRules(const std::string& filename) {
    if (!rule_manager_) return false;
    
    // Detect format by file extension
    if (filename.size() >= 5 && 
        filename.substr(filename.size() - 5) == ".json") {
        return rule_manager_->loadRulesJSON(filename);
    }
    return rule_manager_->loadRules(filename);
}

bool DPIEngine::saveRules(const std::string& filename) {
    if (!rule_manager_) return false;
    
    if (filename.size() >= 5 && 
        filename.substr(filename.size() - 5) == ".json") {
        return rule_manager_->saveRulesJSON(filename);
    }
    return rule_manager_->saveRules(filename);
}

// ============================================================================
// Hot-Reload Thread
// ============================================================================
// Checks the rules file every 30 seconds for modifications and reloads
// if the file has been updated. This allows rules to be changed while
// the engine is running without a restart.

void DPIEngine::reloadThreadFunc() {
    while (reload_running_) {
        // Sleep for 30 seconds, checking every second if we should stop
        for (int i = 0; i < 30 && reload_running_; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        if (!reload_running_ || config_.rules_file.empty()) break;
        
        // Try to reload rules if the file has been modified
        if (rule_manager_) {
            rule_manager_->reloadIfModified(config_.rules_file);
        }
    }
}

// ============================================================================
// JSON Output
// ============================================================================
//
// Writes three JSON files to the output directory after processing:
//   stats.json     — totals, thread stats, timing
//   flows.json     — per-flow details with block_reason, connection_state
//   app_stats.json — per-app breakdown and detected SNIs
//
// Uses stdlib only. Atomic write via temp file + rename() to prevent
// corruption if the process is killed mid-write.

bool DPIEngine::atomicWrite(const std::string& filepath, const std::string& content) {
    std::string temp = filepath + ".tmp";
    
    std::ofstream f(temp);
    if (!f.is_open()) return false;
    
    f << content;
    f.close();
    
    if (!f.good()) {
        std::remove(temp.c_str());
        return false;
    }
    
    // Atomic rename — if the process dies between here and completion,
    // the old file (if any) remains intact
    if (std::rename(temp.c_str(), filepath.c_str()) != 0) {
        std::remove(temp.c_str());
        return false;
    }
    
    return true;
}

// Helper: escape a string for JSON output
static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

void DPIEngine::writeJSONOutput() {
    // Create output directory
    std::filesystem::create_directories(config_.output_dir);
    
    std::string stats_path = config_.output_dir + "/stats.json";
    std::string flows_path = config_.output_dir + "/flows.json";
    std::string app_stats_path = config_.output_dir + "/app_stats.json";
    
    writeStatsJSON(stats_path);
    writeFlowsJSON(flows_path);
    writeAppStatsJSON(app_stats_path);
    
    std::cout << "[DPIEngine] JSON output written to: " << config_.output_dir << "\n";
}

void DPIEngine::writeStatsJSON(const std::string& filepath) const {
    std::ostringstream j;
    j << "{\n";
    j << "  \"total_packets\": " << stats_.total_packets.load() << ",\n";
    j << "  \"total_bytes\": " << stats_.total_bytes.load() << ",\n";
    j << "  \"tcp_packets\": " << stats_.tcp_packets.load() << ",\n";
    j << "  \"udp_packets\": " << stats_.udp_packets.load() << ",\n";
    j << "  \"forwarded_packets\": " << stats_.forwarded_packets.load() << ",\n";
    j << "  \"dropped_packets\": " << stats_.dropped_packets.load() << ",\n";
    
    if (stats_.total_packets > 0) {
        double drop_rate = 100.0 * stats_.dropped_packets.load() / stats_.total_packets.load();
        j << "  \"drop_rate_percent\": " << std::fixed << std::setprecision(2) << drop_rate << ",\n";
    }
    
    // Thread stats
    if (lb_manager_) {
        auto lb_stats = lb_manager_->getAggregatedStats();
        j << "  \"lb_received\": " << lb_stats.total_received << ",\n";
        j << "  \"lb_dispatched\": " << lb_stats.total_dispatched << ",\n";
    }
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        j << "  \"fp_processed\": " << fp_stats.total_processed << ",\n";
        j << "  \"fp_forwarded\": " << fp_stats.total_forwarded << ",\n";
        j << "  \"fp_dropped\": " << fp_stats.total_dropped << ",\n";
        j << "  \"active_connections\": " << fp_stats.total_connections << ",\n";
    }
    
    j << "  \"num_load_balancers\": " << config_.num_load_balancers << ",\n";
    j << "  \"fps_per_lb\": " << config_.fps_per_lb << ",\n";
    j << "  \"total_fp_threads\": " << (config_.num_load_balancers * config_.fps_per_lb) << "\n";
    j << "}\n";
    
    atomicWrite(filepath, j.str());
}

void DPIEngine::writeFlowsJSON(const std::string& filepath) const {
    std::ostringstream j;
    j << "[\n";
    
    bool first = true;
    
    if (fp_manager_) {
        for (int i = 0; i < fp_manager_->getNumFPs(); i++) {
            fp_manager_->getFP(i).getConnectionTracker().forEach(
                [&](const Connection& conn) {
                    if (!first) j << ",\n";
                    first = false;
                    
                    auto formatIP = [](uint32_t ip) {
                        std::ostringstream s;
                        s << ((ip >> 0) & 0xFF) << "."
                          << ((ip >> 8) & 0xFF) << "."
                          << ((ip >> 16) & 0xFF) << "."
                          << ((ip >> 24) & 0xFF);
                        return s.str();
                    };
                    
                    std::string state_str;
                    switch (conn.state) {
                        case ConnectionState::NEW:         state_str = "NEW"; break;
                        case ConnectionState::ESTABLISHED: state_str = "ESTABLISHED"; break;
                        case ConnectionState::CLASSIFIED:  state_str = "CLASSIFIED"; break;
                        case ConnectionState::BLOCKED:     state_str = "BLOCKED"; break;
                        case ConnectionState::CLOSED:      state_str = "CLOSED"; break;
                    }
                    
                    j << "  {\n";
                    j << "    \"src_ip\": \"" << formatIP(conn.tuple.src_ip) << "\",\n";
                    j << "    \"dst_ip\": \"" << formatIP(conn.tuple.dst_ip) << "\",\n";
                    j << "    \"src_port\": " << conn.tuple.src_port << ",\n";
                    j << "    \"dst_port\": " << conn.tuple.dst_port << ",\n";
                    j << "    \"protocol\": \"" << (conn.tuple.protocol == 6 ? "TCP" : "UDP") << "\",\n";
                    j << "    \"app_type\": \"" << jsonEscape(appTypeToString(conn.app_type)) << "\",\n";
                    j << "    \"sni\": \"" << jsonEscape(conn.sni) << "\",\n";
                    j << "    \"connection_state\": \"" << state_str << "\",\n";
                    j << "    \"packets_out\": " << conn.packets_out << ",\n";
                    j << "    \"packets_in\": " << conn.packets_in << ",\n";
                    j << "    \"bytes_out\": " << conn.bytes_out << ",\n";
                    j << "    \"bytes_in\": " << conn.bytes_in << ",\n";
                    j << "    \"blocked\": " << (conn.state == ConnectionState::BLOCKED ? "true" : "false") << "\n";
                    j << "  }";
                }
            );
        }
    }
    
    j << "\n]\n";
    
    atomicWrite(filepath, j.str());
}

void DPIEngine::writeAppStatsJSON(const std::string& filepath) const {
    // Aggregate app distribution
    std::unordered_map<AppType, size_t> app_counts;
    std::vector<std::string> detected_snis;
    
    if (fp_manager_) {
        for (int i = 0; i < fp_manager_->getNumFPs(); i++) {
            fp_manager_->getFP(i).getConnectionTracker().forEach(
                [&](const Connection& conn) {
                    app_counts[conn.app_type]++;
                    if (!conn.sni.empty()) {
                        detected_snis.push_back(conn.sni);
                    }
                }
            );
        }
    }
    
    // Sort SNIs and deduplicate
    std::sort(detected_snis.begin(), detected_snis.end());
    detected_snis.erase(
        std::unique(detected_snis.begin(), detected_snis.end()),
        detected_snis.end()
    );
    
    // Sort apps by count
    std::vector<std::pair<AppType, size_t>> sorted_apps(
        app_counts.begin(), app_counts.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    size_t total = 0;
    for (const auto& p : sorted_apps) total += p.second;
    
    std::ostringstream j;
    j << "{\n";
    j << "  \"total_flows\": " << total << ",\n";
    j << "  \"apps\": [\n";
    
    for (size_t i = 0; i < sorted_apps.size(); i++) {
        double pct = total > 0 ? (100.0 * sorted_apps[i].second / total) : 0;
        j << "    {\n";
        j << "      \"app\": \"" << jsonEscape(appTypeToString(sorted_apps[i].first)) << "\",\n";
        j << "      \"flow_count\": " << sorted_apps[i].second << ",\n";
        j << "      \"percentage\": " << std::fixed << std::setprecision(1) << pct << "\n";
        j << "    }";
        if (i + 1 < sorted_apps.size()) j << ",";
        j << "\n";
    }
    
    j << "  ],\n";
    j << "  \"detected_snis\": [\n";
    
    for (size_t i = 0; i < detected_snis.size(); i++) {
        j << "    \"" << jsonEscape(detected_snis[i]) << "\"";
        if (i + 1 < detected_snis.size()) j << ",";
        j << "\n";
    }
    
    j << "  ]\n";
    j << "}\n";
    
    atomicWrite(filepath, j.str());
}

// ============================================================================
// Reporting
// ============================================================================

std::string DPIEngine::generateReport() const {
    std::ostringstream ss;
    
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                    DPI ENGINE STATISTICS                      ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    ss << "║ PACKET STATISTICS                                             ║\n";
    ss << "║   Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                        ║\n";
    ss << "║   Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                        ║\n";
    ss << "║   TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                        ║\n";
    ss << "║   UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                        ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ FILTERING STATISTICS                                          ║\n";
    ss << "║   Forwarded:          " << std::setw(12) << stats_.forwarded_packets.load() << "                        ║\n";
    ss << "║   Dropped/Blocked:    " << std::setw(12) << stats_.dropped_packets.load() << "                        ║\n";
    
    if (stats_.total_packets > 0) {
        double drop_rate = 100.0 * stats_.dropped_packets.load() / stats_.total_packets.load();
        ss << "║   Drop Rate:          " << std::setw(11) << std::fixed << std::setprecision(2) << drop_rate << "%                        ║\n";
    }
    
    if (lb_manager_) {
        auto lb_stats = lb_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ LOAD BALANCER STATISTICS                                      ║\n";
        ss << "║   LB Received:        " << std::setw(12) << lb_stats.total_received << "                        ║\n";
        ss << "║   LB Dispatched:      " << std::setw(12) << lb_stats.total_dispatched << "                        ║\n";
    }
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ FAST PATH STATISTICS                                          ║\n";
        ss << "║   FP Processed:       " << std::setw(12) << fp_stats.total_processed << "                        ║\n";
        ss << "║   FP Forwarded:       " << std::setw(12) << fp_stats.total_forwarded << "                        ║\n";
        ss << "║   FP Dropped:         " << std::setw(12) << fp_stats.total_dropped << "                        ║\n";
        ss << "║   Active Connections: " << std::setw(12) << fp_stats.total_connections << "                        ║\n";
    }
    
    if (rule_manager_) {
        auto rule_stats = rule_manager_->getStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ BLOCKING RULES                                                ║\n";
        ss << "║   Blocked IPs:        " << std::setw(12) << rule_stats.blocked_ips << "                        ║\n";
        ss << "║   Blocked Apps:       " << std::setw(12) << rule_stats.blocked_apps << "                        ║\n";
        ss << "║   Blocked Domains:    " << std::setw(12) << rule_stats.blocked_domains << "                        ║\n";
        ss << "║   Blocked Ports:      " << std::setw(12) << rule_stats.blocked_ports << "                        ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

std::string DPIEngine::generateClassificationReport() const {
    if (fp_manager_) {
        return fp_manager_->generateClassificationReport();
    }
    return "";
}

const DPIStats& DPIEngine::getStats() const {
    return stats_;
}

void DPIEngine::printStatus() const {
    std::cout << "\n--- Live Status ---\n";
    std::cout << "Packets: " << stats_.total_packets.load()
              << " | Forwarded: " << stats_.forwarded_packets.load()
              << " | Dropped: " << stats_.dropped_packets.load() << "\n";
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        std::cout << "Connections: " << fp_stats.total_connections << "\n";
    }
}

} // namespace DPI
