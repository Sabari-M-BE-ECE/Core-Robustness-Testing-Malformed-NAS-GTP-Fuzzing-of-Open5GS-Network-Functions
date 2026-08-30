#!/usr/bin/env python3
"""
injector.py
-----------
Core robustness testing (Open5GS)

Replays a fuzzed pcap (produced by nas_fuzzer.py or gtp_fuzzer.py) at a
target Open5GS NF, one packet at a time, pacing the sends so that the
target's logs and Wireshark capture can be correlated back to a specific
manifest index afterwards.

Scope & simplifications (see README for the full explanation):
  * GTP-U traffic is sent as real UDP/2152 datagrams straight to the UPF -
    this matches the real N3 wire format, so gtp_fuzz.pcap can be replayed
    as-is.
  * NAS is normally carried inside NGAP over SCTP (port 38412) between the
    gNB and the AMF. Standing up a full NGAP/SCTP stack was out of scope
    for this lab slot, so nas_fuzz.pcap is replayed over UDP against a
    lightweight test listener (see the gnb-nas-shim note in the README)
    that unwraps the payload and forwards it to the AMF's NAS message
    handling code path. This still exercises the NAS IE parser, which is
    the component objective 2 asks us to test - it does not test the NGAP/
    SCTP layer itself.

Usage:
    python3 injector.py --pcap nas_fuzz.pcap --target 127.0.0.5 --port 38412 --delay 0.05
    python3 injector.py --pcap gtp_fuzz.pcap --target 127.0.0.7 --port 2152 --delay 0.05 --gtp
"""

import argparse
import csv
import socket
import time
import sys
from datetime import datetime

from scapy.all import rdpcap, Raw


def load_manifest(pcap_path: str):
    manifest_path = pcap_path + ".manifest.csv"
    rows = {}
    try:
        with open(manifest_path) as f:
            for row in csv.DictReader(f):
                rows[int(row["index"])] = row["mutator"]
    except FileNotFoundError:
        print(f"[!] No manifest found at {manifest_path} - proceeding without mutator labels")
    return rows


def main():
    ap = argparse.ArgumentParser(description="Replay fuzzed NAS/GTP-U pcap at an Open5GS NF")
    ap.add_argument("--pcap", required=True, help="pcap produced by nas_fuzzer.py or gtp_fuzzer.py")
    ap.add_argument("--target", required=True, help="target NF IP (AMF NAS-shim or UPF N3 address)")
    ap.add_argument("--port", type=int, required=True, help="target UDP port")
    ap.add_argument("--delay", type=float, default=0.1, help="seconds to sleep between injections")
    ap.add_argument("--timeout", type=float, default=0.5, help="socket recv timeout per packet")
    ap.add_argument("--log", default="injection_log.csv", help="CSV log of send results")
    args = ap.parse_args()

    packets = rdpcap(args.pcap)
    manifest = load_manifest(args.pcap)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)

    results = []
    print(f"[+] Loaded {len(packets)} packets from {args.pcap}")
    print(f"[+] Injecting toward {args.target}:{args.port} (delay={args.delay}s)")

    for idx, pkt in enumerate(packets):
        if Raw not in pkt:
            continue
        payload = bytes(pkt[Raw].load)
        mutator = manifest.get(idx, "unknown")
        ts_sent = datetime.utcnow().isoformat()

        outcome = "sent"
        response_len = None
        error_msg = ""

        try:
            sock.sendto(payload, (args.target, args.port))
            try:
                data, _ = sock.recvfrom(4096)
                response_len = len(data)
                outcome = "sent+response"
            except socket.timeout:
                outcome = "sent+no_response"
        except OSError as e:
            outcome = "send_failed"
            error_msg = str(e)

        print(f"[{idx:04d}] mutator={mutator:<24} len={len(payload):<4} -> {outcome} {error_msg}")
        results.append({
            "index": idx,
            "mutator": mutator,
            "payload_len": len(payload),
            "timestamp_utc": ts_sent,
            "outcome": outcome,
            "response_len": response_len,
            "error": error_msg,
        })
        time.sleep(args.delay)

    with open(args.log, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "index", "mutator", "payload_len", "timestamp_utc",
            "outcome", "response_len", "error"
        ])
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[+] Injection log written to {args.log}")
    print("[+] Cross-reference timestamps against NF logs / Wireshark capture "
          "(see log_monitor.py) to classify each mutator's effect.")


if __name__ == "__main__":
    main()
