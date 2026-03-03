# CHANGES.md — DPI Engine Bug Fixes and Enhancements

All changes documented below were verified against the actual codebase before implementation.

---

## 1. CMakeLists.txt — Missing Build Targets

**What was broken:** The CMakeLists.txt only built a single `packet_analyzer` target from 3 source files (`main.cpp`, `pcap_reader.cpp`, `packet_parser.cpp`). The entire real DPI engine (`main_dpi.cpp`, `dpi_engine.cpp`, `fast_path.cpp`, `load_balancer.cpp`, `connection_tracker.cpp`, `rule_manager.cpp`) was never compiled.

**Why it mattered:** The real engine — the production-quality multi-threaded pipeline with load balancers, fast path processors, connection tracking, and rule-based blocking — could not be built. Only the prototype (`dpi_mt.cpp`) compiled.

**How it was fixed:** Rewrote CMakeLists.txt with three targets:
- `packet_analyzer` — the existing prototype (preserves backward compatibility)
- `dpi_engine` — the real engine with all pipeline components
- `dpi_simple` — a minimal standalone demo

Added: `CMAKE_EXPORT_COMPILE_COMMANDS ON`, AddressSanitizer support (`-DCMAKE_BUILD_TYPE=Asan`), `-pthread` linking.

**Note:** `rule_manager.cpp` is intentionally excluded from `packet_analyzer` because `dpi_mt.cpp` contains inline classes that would cause duplicate symbol errors.

**How to verify:**
```bash
cmake -B build && cmake --build build
ls build/packet_analyzer build/dpi_engine build/dpi_simple
./build/dpi_engine test_dpi.pcap output.pcap
```

---

## 2. Byte Order in packet_parser.cpp — Already Fixed

**What the prompt described:** `platform.h` has `PORTABLE_ntohs`/`PORTABLE_ntohl` but is never imported in `packet_parser.cpp`.

**What we found:** This was already fixed in the actual code. `packet_parser.cpp` line 2 has `#include "platform.h"`, lines 8-9 import `netToHost16`/`netToHost32`, and lines 12-13 define `ntohs`/`ntohl` wrapper macros. All network byte reads for IPs, ports, sequence numbers, and acknowledgment numbers use these macros correctly.

**No changes needed.** Verified correct output on `test_dpi.pcap`.

---

## 3. Pipeline Drain in dpi_engine.cpp — Race Condition

**What was broken:** `waitForCompletion()` used `sleep_for(500ms)` after the reader finished, then immediately signaled completion. Under any real load, 500ms is nowhere near enough for all queues (LB → FP → Output) to drain. Packets in the pipeline would be silently lost.

**Why it mattered:** This is a data loss bug. The output PCAP file would have fewer packets than expected, and the count would vary between runs because it depended on timing.

**How it was fixed:** Replaced naive sleep with proper sequential drain:
1. Wait for reader thread to finish → join it
2. Shutdown all LB input queues → poll until empty (10s timeout) → stop LB threads
3. Poll all FP input queues until empty (10s timeout) → stop FP threads
4. Poll output queue until empty (10s timeout) → stop output thread
5. Close output file

Each stage has a timeout to prevent infinite hangs in case of bugs.

**How to verify:** Run `./build/dpi_engine test_dpi.pcap out.pcap` three times. The output files should have identical packet counts every time.

---

## 4. Domain Suffix Matching in types.cpp — False Positives

**What was broken:** `sniToAppType()` used `sni.find("youtube")` which matches any string containing "youtube" as a substring. This means `youtubedownloader.com` would be classified as YouTube, `notgoogle.com` would be classified as Google, etc.

**Why it mattered:** In a production DPI system, misclassifying traffic leads to:
- Legitimate traffic being blocked (false positive)
- Traffic analytics being wrong
- Users complaining about service outages

**How it was fixed:** Replaced all `find()` calls with a proper `matchesDomain()` function that only matches:
- **Exact match:** `youtube.com` == `youtube.com` ✓
- **Subdomain match:** `www.youtube.com` ends with `.youtube.com` ✓
- **No substring match:** `youtubedownloader.com` → Unknown ✓

Also restructured the code to use a clean `APP_MAPPINGS` table instead of cascading if-else blocks. YouTube is checked before Google to prevent `googlevideo.com` (YouTube CDN) from being misclassified as Google.

**How to verify:**
- `www.youtube.com` → YouTube ✓
- `youtubedownloader.com` → HTTPS (Unknown app) ✓
- `googlevideo.com` → YouTube ✓
- `notgoogle.com` → HTTPS (Unknown app) ✓

---

## 5. JSON Rule Support — New Feature

**What was added:** `saveRulesJSON()`, `loadRulesJSON()`, and `reloadIfModified()` methods on `RuleManager`. The existing `.ini` format (`[BLOCKED_IPS]` sections) is fully preserved.

**JSON format:**
```json
{
  "blocked_ips": ["192.168.1.50"],
  "blocked_apps": ["YouTube", "TikTok"],
  "blocked_domains": ["tiktok.com", "*.ads.google.com"],
  "blocked_ports": [6881],
  "updated_at": "2024-01-15T10:00:00Z"
}
```

**Hot-reload:** A background thread in `dpi_engine.cpp` calls `reloadIfModified()` every 30 seconds. If the rules file has been modified since the last load, rules are automatically reloaded without restarting the engine.

**How to verify:**
```bash
./build/dpi_engine test_dpi.pcap out.pcap --rules rules.json
# Edit rules.json while engine is running — rules reload within 30s
```

---

## 6. JSON Output — New Feature

**What was added:** `--output-dir=` flag (default `./dpi_output/`). After processing, three JSON files are written atomically:

- `stats.json` — packet totals, thread stats, drop rate
- `flows.json` — per-flow details: 5-tuple, app type, SNI, connection state, blocked status
- `app_stats.json` — per-app breakdown with percentages, list of all detected SNIs

**Atomic writes:** Uses temp file + `rename()` to prevent corruption if the process dies mid-write.

**How to verify:**
```bash
./build/dpi_engine test_dpi.pcap out.pcap --output-dir=./test_output/
cat test_output/stats.json
cat test_output/flows.json
cat test_output/app_stats.json
```
