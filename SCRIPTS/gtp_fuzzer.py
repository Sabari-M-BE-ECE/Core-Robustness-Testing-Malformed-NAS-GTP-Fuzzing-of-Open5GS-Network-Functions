#!/usr/bin/env python3
"""
gtp_fuzzer.py
-------------
Core robustness testing (Open5GS)

Crafts malformed GTP-U (GPRS Tunnelling Protocol - User plane, TS 29.281)
packets aimed at the UPF's N3/N9 interface (default port 2152/udp).

GTP-U header (basic, no extensions):
    Octet1: Version(3b) | PT(1b) | *(1b,spare) | E(1b) | S(1b) | PN(1b)
    Octet2: Message Type
    Octet3-4: Length (of payload, NOT including the mandatory 8-byte header)
    Octet5-8: TEID

Mutation strategies implemented:
    1. bad_version        - version bits set to reserved values (not 1)
    2. bad_message_type   - unknown / reserved message type (e.g. 0xFF)
    3. length_mismatch    - length field disagrees with actual payload size
    4. teid_flap          - TEID = 0x00000000 / 0xFFFFFFFF / random garbage
    5. ext_header_no_data - E flag set but no extension header actually follows
    6. seq_flag_no_seq    - S flag set but sequence-number field is truncated
    7. echo_request_storm - flood of GTP-U Echo Request (msg type 1) with bad TEID
    8. truncated_header   - packet shorter than the mandatory 8-byte header
    9. jumbo_payload      - length field claims far more data than is present
   10. bit_flip           - random bit flips across header + payload

Usage:
    python3 gtp_fuzzer.py --count 200 --out gtp_fuzz.pcap
"""

import argparse
import random
import struct
from scapy.all import Ether, IP, UDP, Raw, wrpcap

GTP_U_PORT = 2152

GTP_MSG_TYPES = {
    "EchoRequest": 1,
    "EchoResponse": 2,
    "ErrorIndication": 26,
    "SupportedExtensionHeadersNotification": 31,
    "EndMarker": 254,
    "GPDU": 255,
}


def build_gtp_header(version=1, pt=1, e=0, s=0, pn=0, msg_type=255,
                      length=0, teid=0x11223344) -> bytes:
    """Build a syntactically-correct 8-byte GTP-U mandatory header."""
    octet1 = (version & 0x07) << 5
    octet1 |= (pt & 0x01) << 4
    octet1 |= 0 << 3          # spare bit, always 0
    octet1 |= (e & 0x01) << 2
    octet1 |= (s & 0x01) << 1
    octet1 |= (pn & 0x01)
    header = struct.pack("!B", octet1)
    header += struct.pack("!B", msg_type)
    header += struct.pack("!H", length)
    header += struct.pack("!I", teid)
    return header


def base_gpdu_packet() -> bytes:
    """A valid-looking G-PDU (user data) packet: GTP header + a tiny fake
    IPv4/ICMP inner payload so length fields have something real to lie about."""
    inner_payload = bytes.fromhex(
        "4500001c0000000040011234c0a80101c0a80102"  # bogus IPv4 header (truncated on purpose, inner)
        "08004506000100010000"                        # bogus ICMP-ish tail
    )
    header = build_gtp_header(msg_type=GTP_MSG_TYPES["GPDU"], length=len(inner_payload))
    return header + inner_payload


def mutate_bad_version(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    reserved_version = random.choice([0, 2, 3, 4, 5, 6, 7])  # only version 1 is currently valid
    pdu[0] = (pdu[0] & 0x1F) | (reserved_version << 5)
    return bytes(pdu)


def mutate_bad_message_type(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    pdu[1] = random.choice([0x00, 0x03, 0x0A, 0x32, 0x64, 0xFA])  # reserved/unassigned types
    return bytes(pdu)


def mutate_length_mismatch(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    bad_len = random.choice([0x0000, 0xFFFF, 0x8000])
    pdu[2:4] = struct.pack("!H", bad_len)
    return bytes(pdu)


def mutate_teid_flap(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    bad_teid = random.choice([0x00000000, 0xFFFFFFFF, random.randint(0, 2**32 - 1)])
    pdu[4:8] = struct.pack("!I", bad_teid)
    return bytes(pdu)


def mutate_ext_header_no_data(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    pdu[0] |= 0x04  # set E flag, but don't add the extension header octet(s)
    return bytes(pdu)


def mutate_seq_flag_no_seq(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    pdu[0] |= 0x02  # set S flag
    return bytes(pdu[:8])  # ...then truncate right after the mandatory header


def mutate_echo_request_storm(_pdu: bytes) -> bytes:
    # ignores the base packet - builds a minimal, malformed Echo Request
    return build_gtp_header(msg_type=GTP_MSG_TYPES["EchoRequest"], length=0,
                             teid=random.choice([0x00000000, 0xFFFFFFFF]))


def mutate_truncated_header(pdu: bytes) -> bytes:
    cut = random.randint(1, 7)  # always < 8, i.e. shorter than mandatory header
    return pdu[:cut]


def mutate_jumbo_payload(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    pdu[2:4] = struct.pack("!H", 0xFFFE)  # claims ~64KB of payload that isn't there
    return bytes(pdu)


def mutate_bit_flip(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    n_flips = random.randint(1, 5)
    for _ in range(n_flips):
        if not pdu:
            break
        byte_idx = random.randrange(len(pdu))
        bit_idx = random.randrange(8)
        pdu[byte_idx] ^= (1 << bit_idx)
    return bytes(pdu)


MUTATORS = [
    mutate_bad_version,
    mutate_bad_message_type,
    mutate_length_mismatch,
    mutate_teid_flap,
    mutate_ext_header_no_data,
    mutate_seq_flag_no_seq,
    mutate_echo_request_storm,
    mutate_truncated_header,
    mutate_jumbo_payload,
    mutate_bit_flip,
]


def generate_corpus(count: int):
    base = base_gpdu_packet()
    for _ in range(count):
        mutator = random.choice(MUTATORS)
        mutated = mutator(base)
        yield mutator.__name__, mutated


def main():
    ap = argparse.ArgumentParser(description="Malformed GTP-U packet generator")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--out", default="gtp_fuzz.pcap")
    ap.add_argument("--upf-ip", default="127.0.0.7", help="UPF N3 test-endpoint IP")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    packets = []
    manifest = []
    for idx, (mutator_name, payload) in enumerate(generate_corpus(args.count)):
        pkt = Ether() / IP(dst=args.upf_ip) / UDP(dport=GTP_U_PORT, sport=random.randint(1024, 65535)) / Raw(load=payload)
        packets.append(pkt)
        manifest.append(f"{idx:04d},{mutator_name},{len(payload)}")

    wrpcap(args.out, packets)

    with open(args.out + ".manifest.csv", "w") as f:
        f.write("index,mutator,length_bytes\n")
        f.write("\n".join(manifest) + "\n")

    print(f"[+] Wrote {len(packets)} malformed GTP-U packets to {args.out}")
    print(f"[+] Manifest: {args.out}.manifest.csv")


if __name__ == "__main__":
    main()
