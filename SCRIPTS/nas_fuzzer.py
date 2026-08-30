#!/usr/bin/env python3
"""
nas_fuzzer.py
-------------
Core robustness testing (Open5GS)

Crafts malformed 5GS NAS (Non-Access Stratum) messages and writes them
to a pcap file / feeds them to injector.py. Built with Scapy custom
layers since Scapy has no native 5GS-NAS dissector.

NAS messages this script targets (5GMM signalling, TS 24.501):
    - Registration Request       (message type 0x41)
    - Identity Response          (message type 0x5c)
    - Authentication Response    (message type 0x57)
    - Security Mode Complete     (message type 0x5e)

Mutation strategies implemented:
    1. length_lie      - IE length field does not match actual IE payload
    2. truncate         - chop the message mid-IE
    3. bad_ie_id         - unknown / reserved IE identifier
    4. oversized_ie     - IE length field points past end of buffer
    5. bit_flip          - random single/multi bit flips (classic bitflip fuzzing)
    6. repeat_ie          - duplicate a mandatory IE to confuse the parser
    7. null_bytes         - IE payload replaced with all-zero bytes
    8. huge_length_field  - length field set to 0xFFFF regardless of payload

Usage:
    python3 nas_fuzzer.py --count 200 --out nas_fuzz.pcap
"""

import argparse
import random
import struct
from scapy.all import Ether, IP, UDP, Raw, wrpcap

# --- 5GS NAS message type values we mutate (TS 24.501 Table 9.7.1) -------
NAS_MSG_TYPES = {
    "RegistrationRequest": 0x41,
    "IdentityResponse": 0x5C,
    "AuthenticationResponse": 0x57,
    "SecurityModeComplete": 0x5E,
}

EPD_5GMM = 0x7E          # Extended Protocol Discriminator: 5GS mobility management
SECURITY_HEADER_PLAIN = 0x00


def base_registration_request() -> bytes:
    """
    Build a syntactically valid 'Registration Request' skeleton so the
    mutator has something realistic to corrupt, rather than fuzzing
    from pure noise (which mostly gets rejected before it reaches
    interesting parser code).

    Layout (simplified, plain NAS, no security header):
      EPD (1B) | Security header type (1B, low nibble) | Msg type (1B)
      | 5GS registration type IE (1B) | ngKSI (1B)
      | Mobile Identity IE (TLV-E: IEI 0x77, 2B length, value)
    """
    epd = bytes([EPD_5GMM])
    sec_hdr = bytes([SECURITY_HEADER_PLAIN])
    msg_type = bytes([NAS_MSG_TYPES["RegistrationRequest"]])

    reg_type = bytes([0x01])          # initial registration, no follow-on
    ngksi = bytes([0x70])             # no key available

    # 5GS Mobile Identity (SUCI, dummy) - IEI 0x77, TLV-E
    suci_value = bytes.fromhex("f0f1ffff00000001")  # fake SUCI payload
    mobile_id_iei = bytes([0x77])
    mobile_id_len = struct.pack(">H", len(suci_value))
    mobile_id = mobile_id_iei + mobile_id_len + suci_value

    return epd + sec_hdr + msg_type + reg_type + ngksi + mobile_id


def mutate_length_lie(pdu: bytes) -> bytes:
    """Flip the 2-byte length field of the trailing TLV-E IE so it
    disagrees with the real payload length (over- and under-claim)."""
    pdu = bytearray(pdu)
    if len(pdu) < 8:
        return bytes(pdu)
    len_offset = 6  # position of the 2-byte length field we built above
    bad_len = random.choice([0x0000, 0xFFFF, 0x7FFF, len(pdu) + 500])
    pdu[len_offset:len_offset + 2] = struct.pack(">H", bad_len & 0xFFFF)
    return bytes(pdu)


def mutate_truncate(pdu: bytes) -> bytes:
    cut = random.randint(2, max(3, len(pdu) - 1))
    return pdu[:cut]


def mutate_bad_ie_id(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    if len(pdu) > 5:
        pdu[5] = random.choice([0x00, 0xFF, 0xAA, 0x1F])  # bogus/reserved IEI
    return bytes(pdu)


def mutate_oversized_ie(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    len_offset = 6
    if len(pdu) >= len_offset + 2:
        pdu[len_offset:len_offset + 2] = struct.pack(">H", 0x2000)  # claims 8KB payload
    return bytes(pdu)


def mutate_bit_flip(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    n_flips = random.randint(1, 4)
    for _ in range(n_flips):
        if not pdu:
            break
        byte_idx = random.randrange(len(pdu))
        bit_idx = random.randrange(8)
        pdu[byte_idx] ^= (1 << bit_idx)
    return bytes(pdu)


def mutate_repeat_ie(pdu: bytes) -> bytes:
    # duplicate the last 6 bytes (part of the mandatory mobile identity IE)
    return pdu + pdu[-6:]


def mutate_null_bytes(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    if len(pdu) > 8:
        start = 8
        for i in range(start, len(pdu)):
            pdu[i] = 0x00
    return bytes(pdu)


def mutate_huge_length_field(pdu: bytes) -> bytes:
    pdu = bytearray(pdu)
    len_offset = 6
    if len(pdu) >= len_offset + 2:
        pdu[len_offset:len_offset + 2] = b"\xff\xff"
    return bytes(pdu)


MUTATORS = [
    mutate_length_lie,
    mutate_truncate,
    mutate_bad_ie_id,
    mutate_oversized_ie,
    mutate_bit_flip,
    mutate_repeat_ie,
    mutate_null_bytes,
    mutate_huge_length_field,
]


def generate_corpus(count: int):
    """Yield (mutator_name, raw_bytes) pairs."""
    base = base_registration_request()
    for i in range(count):
        mutator = random.choice(MUTATORS)
        mutated = mutator(base)
        yield mutator.__name__, mutated


def main():
    ap = argparse.ArgumentParser(description="Malformed 5GS NAS message generator")
    ap.add_argument("--count", type=int, default=100, help="number of malformed PDUs to generate")
    ap.add_argument("--out", default="nas_fuzz.pcap", help="output pcap file")
    ap.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible runs")
    ap.add_argument("--amf-ip", default="127.0.0.5", help="AMF N2/NAS test-endpoint IP (see injector.py)")
    ap.add_argument("--amf-port", type=int, default=38412, help="destination port to label in the pcap (NGAP default)")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    packets = []
    manifest = []
    for idx, (mutator_name, payload) in enumerate(generate_corpus(args.count)):
        # Wrapped in Ether/IP/UDP purely so the pcap opens cleanly in Wireshark
        # and can be replayed with injector.py's raw-socket harness. Real NAS
        # transport is NGAP-over-SCTP; see README "Scope & simplifications".
        pkt = Ether() / IP(dst=args.amf_ip) / UDP(dport=args.amf_port) / Raw(load=payload)
        packets.append(pkt)
        manifest.append(f"{idx:04d},{mutator_name},{len(payload)}")

    wrpcap(args.out, packets)

    with open(args.out + ".manifest.csv", "w") as f:
        f.write("index,mutator,length_bytes\n")
        f.write("\n".join(manifest) + "\n")

    print(f"[+] Wrote {len(packets)} malformed NAS PDUs to {args.out}")
    print(f"[+] Manifest: {args.out}.manifest.csv")


if __name__ == "__main__":
    main()
