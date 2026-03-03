"""
PCAP Analyzer — The main analysis pipeline using Scapy.

This is the Python equivalent of DPIEngine::processFile() in the C++ engine.
It reads a PCAP file, extracts flows, performs SNI extraction and traffic
classification, applies blocking rules, and produces an AnalysisResult.

Architecture comparison:
  C++ Engine: PcapReader → LoadBalancer → FastPath → OutputWriter (multi-threaded)
  Python:     Scapy rdpcap → sequential analysis (single-threaded, simpler)

The Python version is intentionally simpler — it's an API service that
analyzes uploaded PCAPs, not a high-performance inline packet processor.
"""

import hashlib
import time
from typing import Dict, Optional
from collections import defaultdict

from scapy.all import rdpcap, IP, TCP, UDP, Raw

from ..models.flow import FiveTuple, Flow
from ..models.analysis import AppBreakdown, AnalysisStats, AnalysisResult
from .sni_extractor import extract_sni, is_tls_client_hello
from .classifier import classify_domain
from .rule_engine import RuleEngine


def _make_flow_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> str:
    """
    Generate a deterministic flow ID from the five-tuple.
    Uses MD5 hash of the canonical form (sorted IPs) so that
    both directions of a flow map to the same ID.
    """
    # Sort by IP to ensure both directions produce the same hash
    if (src_ip, src_port) > (dst_ip, dst_port):
        key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
    else:
        key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"

    return hashlib.md5(key.encode()).hexdigest()[:12]


def analyze_pcap(file_path: str, rule_engine: RuleEngine) -> AnalysisResult:
    """
    Analyze a PCAP file and return structured results.

    Args:
        file_path: Path to the PCAP file on disk
        rule_engine: RuleEngine instance for checking blocking rules

    Returns:
        AnalysisResult with flows, stats, and app breakdown

    Raises:
        AnalysisError: If the file cannot be read or is not a valid PCAP
    """
    start_time = time.time()

    # Read all packets using Scapy
    packets = rdpcap(file_path)

    # Tracking structures
    flows: Dict[str, Flow] = {}
    total_packets = 0
    total_bytes = 0
    tcp_packets = 0
    udp_packets = 0

    for pkt in packets:
        total_packets += 1
        total_bytes += len(pkt)

        # We only analyze IP packets
        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Determine protocol and ports
        if pkt.haslayer(TCP):
            tcp_packets += 1
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            udp_packets += 1
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            continue  # Skip non-TCP/UDP

        # Generate flow ID
        flow_id = _make_flow_id(src_ip, dst_ip, src_port, dst_port, proto)

        # Create or update flow
        if flow_id not in flows:
            flows[flow_id] = Flow(
                flow_id=flow_id,
                five_tuple=FiveTuple(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                ),
                timestamp_start=float(pkt.time),
            )

        flow = flows[flow_id]

        # Update packet/byte counts
        # If the packet is from src→dst, count as sent; otherwise as recv
        if ip_layer.src == flow.five_tuple.src_ip:
            flow.packets_sent += 1
            flow.bytes_sent += len(pkt)
        else:
            flow.packets_recv += 1
            flow.bytes_recv += len(pkt)

        # Update end timestamp
        flow.timestamp_end = float(pkt.time)

        # Try SNI extraction on TLS Client Hello packets
        if proto == "TCP" and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if is_tls_client_hello(payload):
                sni = extract_sni(payload)
                if sni and not flow.sni:
                    flow.sni = sni
                    flow.app_type = classify_domain(sni)

        # Classify DNS traffic
        if proto == "UDP" and (dst_port == 53 or src_port == 53):
            flow.app_type = "DNS"

    # Apply blocking rules to all flows
    blocked_count = 0
    for flow in flows.values():
        block_result = rule_engine.should_block(
            src_ip=flow.five_tuple.src_ip,
            dst_port=flow.five_tuple.dst_port,
            app_type=flow.app_type,
            domain=flow.sni or "",
        )
        if block_result:
            flow.blocked = True
            flow.block_reason = f"{block_result[0]}: {block_result[1]}"
            blocked_count += 1

    # Build app breakdown
    app_counts: Dict[str, int] = defaultdict(int)
    for flow in flows.values():
        app_counts[flow.app_type] += 1

    total_flows = len(flows)
    app_breakdown = []
    for app_name, count in sorted(app_counts.items(), key=lambda x: -x[1]):
        pct = (count / total_flows * 100) if total_flows > 0 else 0
        app_breakdown.append(AppBreakdown(
            app_type=app_name,
            flow_count=count,
            percentage=round(pct, 1),
        ))

    # Collect unique SNIs
    detected_snis = sorted(set(
        flow.sni for flow in flows.values() if flow.sni
    ))

    classified = sum(1 for f in flows.values() if f.app_type != "Unknown")

    elapsed_ms = (time.time() - start_time) * 1000

    # Build final result
    stats = AnalysisStats(
        total_packets=total_packets,
        total_bytes=total_bytes,
        tcp_packets=tcp_packets,
        udp_packets=udp_packets,
        total_flows=total_flows,
        blocked_flows=blocked_count,
        classified_flows=classified,
        app_breakdown=app_breakdown,
        detected_snis=detected_snis,
    )

    return AnalysisResult(
        filename=file_path.split("/")[-1],
        stats=stats,
        flows=list(flows.values()),
        analysis_time_ms=round(elapsed_ms, 2),
    )
