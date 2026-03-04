# INTERVIEW_PREP.md — NetAnalyzer Python Service

## Project Overview

NetAnalyzer is a Python-based network traffic analysis API service. It provides:
- **PCAP file analysis** via Scapy with SNI extraction and app classification
- **16-app classifier** using suffix matching (YouTube, Netflix, TikTok, etc.)
- **Rule-based blocking** for IPs, apps, domains, and ports
- **RESTful API** built with FastAPI with full Swagger documentation

Architecturally, it mirrors the C++ DPI engine but in a simpler, API-first design pattern suitable for interview discussion.

---

## Key Concepts

| Concept | Where | Why It Matters |
|---------|-------|----------------|
| SNI Extraction | `sni_extractor.py` | Identifies HTTPS sites without decryption |
| Suffix Matching | `classifier.py` | Prevents false positives vs. naive substring matching |
| Five-Tuple | `flow.py` | Standard way to identify network conversations |
| Atomic Writes | `rule_engine.py` | Prevents data corruption on crash |
| Pydantic Models | `models/` | Type safety + automatic API serialization |
| In-Memory Store | `flow_store.py` | Simple, fast, no database overhead |

---

## Interview Questions & Answers

### 1. What is SNI and why is it important for DPI?

**SNI (Server Name Indication)** is a TLS extension where the client tells the server which hostname it's connecting to — in plaintext. This happens during the TLS handshake, before encryption starts.

For DPI, SNI is critical because it lets us identify which website/app someone is accessing over HTTPS without decrypting the traffic. Without SNI, all HTTPS traffic would be opaque — we'd only see IP addresses, which can host multiple services.

In code: `sni_extractor.py` parses the TLS Client Hello message to find extension type 0x0000 and reads the hostname.

---

### 2. Why did the original C++ engine misclassify traffic?

The original `types.cpp` used `sni.find("youtube")` for matching, which is **substring matching**. This means:
- `youtubedownloader.com` → incorrectly classified as YouTube
- `notgoogle.com` → incorrectly classified as Google

We fixed it with **suffix matching**: check if the domain IS `youtube.com` or ENDS WITH `.youtube.com`. The fix is in both `types.cpp` (C++) and `classifier.py` (Python).

---

### 3. What is a five-tuple and why is it the key for flow tracking?

A five-tuple is `(src_ip, dst_ip, src_port, dst_port, protocol)`. It uniquely identifies a network conversation.

Every packet belongs to exactly one flow, determined by these 5 fields. We hash the five-tuple to generate a deterministic `flow_id`. We also sort the IP/port pairs so both directions map to the same flow — this is called **bidirectional flow identification**.

---

### 4. How does the rule engine decide what to block?

The `should_block()` method checks rules in priority order:
1. **IP rules** — most specific, checked first
2. **Port rules** — next (e.g., block torrent port 6881)
3. **App rules** — requires classification to have run first
4. **Domain rules** — supports exact match and `*.domain.com` wildcards

If any rule matches, the flow is marked as blocked with a reason string. The check returns immediately on first match (short-circuit evaluation).

---

### 5. Why do you use atomic writes for the rules file?

If the service crashes while writing `rules.json`, the file could be left in a partially written (corrupted) state. On restart, loading would fail and all rules would be lost.

**Atomic write pattern:**
1. Write to a temp file: `rules.json.tmp`
2. Call `os.replace(temp, target)` — this is a single OS operation
3. If we crash between step 1 and 2, the original file remains intact

This is the same pattern used in the C++ engine (`std::rename()`).

---

### 6. Why did you choose FastAPI over Flask?

- **Async-native**: FastAPI runs on ASGI (uvicorn), so I/O-bound operations like file uploads don't block other requests
- **Pydantic integration**: Models are automatically validated and serialized — less boilerplate
- **Auto-documentation**: Swagger UI at `/docs` is generated from type annotations
- **Performance**: FastAPI is significantly faster than Flask for API workloads

---

### 7. How does the PCAP analyzer pipeline work?

```
PCAP File → Scapy rdpcap() → Per-Packet Loop:
  1. Extract IP layer (skip non-IP)
  2. Extract TCP/UDP ports
  3. Generate flow_id from five-tuple
  4. Create/update Flow object
  5. If TCP + has payload → TLS check → SNI extraction → classification
  6. If UDP port 53 → mark as DNS
  7. After all packets: apply blocking rules to all flows
  8. Build app breakdown statistics
  9. Return AnalysisResult
```

The C++ engine does the same thing but across multiple threads with load balancing. The Python version is single-threaded because it's designed for API-driven analysis, not inline packet processing.

---

### 8. What is the C++ engine's pipeline drain bug and how did you fix it?

**Bug:** `waitForCompletion()` used `sleep_for(500ms)` after the reader finished. Under load, pipeline queues might still have packets. The output file would have a non-deterministic number of packets depending on timing.

**Fix:** Sequential drain with proper synchronization:
1. Join reader thread → no more input
2. Shutdown LB input queues → poll until empty → stop LB threads
3. Poll FP queues until empty → stop FP threads
4. Poll output queue until empty → stop output thread
5. Close output file

Each stage has a 10-second timeout to prevent infinite hangs.

---

### 9. How does the C++ engine distribute packets across threads?

The engine uses **consistent hashing** on the five-tuple:
1. Reader sends packet to `lb_queues[hash(5-tuple) % num_lbs]`
2. Each LB sends to `fp_queues[hash(5-tuple) % fps_per_lb]`

This ensures all packets from the same flow go to the same FP thread, which is critical for connection tracking and SNI extraction (you need to see the Client Hello packet to classify the entire flow).

---

### 10. Why is connection tracking per-thread and not global?

Each FP thread has its own `ConnectionTracker` because:
- **No locking needed**: each thread only accesses its own tracker
- **Cache locality**: data stays in L1/L2 cache of the core running that thread
- **Consistent hashing guarantees**: all packets for a flow go to the same FP

A `GlobalConnectionTable` aggregates stats at the end for reporting, but real-time classification happens locally.

---

### 11. How do you handle thread safety in the C++ rule manager?

`RuleManager` uses `std::shared_mutex` with read-write locking:
- **Read operations** (`shouldBlock`, `isIPBlocked`): `shared_lock` — multiple FP threads can check rules simultaneously
- **Write operations** (`blockIP`, `loadRules`): `unique_lock` — exclusive access

This is optimal because reads are far more frequent than writes (rules change rarely, but every packet checks rules).

---

### 12. What's the difference between the C++ and Python implementations?

| Aspect | C++ Engine | Python Service |
|--------|-----------|----------------|
| Use case | Inline packet processing | API-driven analysis |
| Threading | Multi-threaded pipeline | Single-threaded async |
| Packet source | Live PCAP files | Uploaded files via API |
| Performance | Millions of packets/sec | Thousands (analysis tool) |
| Rule format | .ini and .json | .json only |
| Output | PCAP file + JSON stats | JSON API responses |

They share: the same SNI extraction algorithm, suffix matching logic, rule evaluation order, and JSON rule format.

---

### 13. How would you scale the Python service for production?

1. **Multiple workers**: `uvicorn --workers 4` (one per CPU core)
2. **Message queue**: For large PCAPs, push analysis jobs to Celery/Redis
3. **Database**: Replace dict + JSON with PostgreSQL for persistence
4. **Caching**: Redis for frequently queried flows
5. **Load balancer**: Nginx/Traefik in front of multiple service instances
6. **Kubernetes**: Deploy as a pod with HPA based on CPU/request count

---

### 14. How does Docker improve deployment?

- **Reproducibility**: Same image runs identically on dev, CI, and production
- **Isolation**: C++ and Python services don't conflict on dependencies
- **Security**: Non-root users (uid 1001) limit attack surface
- **Multi-stage builds**: C++ Dockerfile compiles in ubuntu:22.04 but runtime image is minimal
- **Healthchecks**: Docker/K8s can automatically restart unhealthy services
- **Layer caching**: `requirements.txt` copied before source → pip install cached

---

### 15. How do you test a network analysis tool?

**Unit tests** (31 tests in our suite):
- TLS Client Hello construction → SNI extraction validation
- Suffix matching: positive/negative cases for all 17 apps
- Rule CRUD: block, unblock, invalid input, clear all
- Flow store: add, get, filter, not-found

**Integration tests:**
- Upload real PCAP → verify flows contain expected SNIs
- Block YouTube → verify YouTube flows marked `blocked: true`
- Health endpoint → 200 with service info

**Property-based testing** (future):
- Generate random five-tuples → verify bidirectional flow_id consistency
- Random domain strings → verify classifier never crashes
