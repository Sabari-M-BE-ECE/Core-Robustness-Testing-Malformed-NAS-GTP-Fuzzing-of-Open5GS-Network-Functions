# Slot 44 — Core Robustness Testing: Malformed NAS/GTP Fuzzing of Open5GS

WIPRO 5G Capstone project. A small mutation-based fuzzing toolkit that
crafts malformed 5GS NAS and GTP-U packets with Scapy, injects them at a
local Open5GS deployment, and correlates the NF logs with the injection
timeline to classify how robustly each parser handled the bad input.

Full write-up (methodology, results, per-NF classification, recommended
fixes): **[`report/Capstone_Report.md`](report/Capstone_Report.md)**

## What's in this repo

```
.
├── README.md
├── report/
│   └── Capstone_Report.md         # full write-up
├── scripts/
│   ├── nas_fuzzer.py              # generates malformed NAS PDUs -> pcap + manifest
│   ├── gtp_fuzzer.py              # generates malformed GTP-U packets -> pcap + manifest
│   ├── injector.py                # replays a pcap at a target NF, logs outcomes
│   ├── log_monitor.py             # tails NF logs, flags crash/reject signatures, builds findings table
│   └── requirements.txt
└── results/
    ├── sample_findings.md         # worked-example findings table from one lab run
    └── wireshark_capture_notes.md # how to verify the injected traffic on the wire
```

## Scope note (read this before running against your own lab)

GTP-U packets go out as real UDP/2152 traffic and can be aimed straight at
a UPF. NAS is normally carried inside NGAP over SCTP between a gNB and the
AMF — this toolkit does **not** stand up a full NGAP/SCTP stack. Instead,
`injector.py` sends the fuzzed NAS bytes over UDP to a lightweight local
shim that hands the payload to the same NAS decoder the AMF would use for
a real message. That's enough to test objective 2 (NAS *parser*
robustness) but it is **not** a test of the NGAP/SCTP transport layer
itself — see the report's "Scope decision" section for the reasoning and
for pointers on extending this to a real NGAP path with UERANSIM.

## Requirements

- A local Open5GS install (2.7.x used for this project) — see
  <https://open5gs.org/open5gs/docs/guide/01-quickstart/>
- Python 3.10+
- Wireshark / tcpdump for packet capture and manual inspection
- Root/sudo for `tcpdump` and for binding low ports if you adapt the shim

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r scripts/requirements.txt
```

## Usage

**1. Generate the malformed packet corpora**

```bash
cd scripts
python3 nas_fuzzer.py --count 200 --seed 42 --out nas_fuzz.pcap
python3 gtp_fuzzer.py --count 200 --seed 7  --out gtp_fuzz.pcap
```

Each run produces `<name>.pcap` (viewable in Wireshark) and
`<name>.pcap.manifest.csv` (which mutator produced which packet index —
needed later for correlation).

**2. Start log watching, in its own terminal**

```bash
python3 log_monitor.py watch \
  --logs /var/log/open5gs/amf.log /var/log/open5gs/upf.log \
  --out flags.csv
```

**3. Inject, in another terminal — and optionally capture with tcpdump alongside**

```bash
sudo tcpdump -i lo -w capture_run1.pcap udp port 2152 or udp port 38412 &

python3 injector.py --pcap nas_fuzz.pcap --target 127.0.0.5 --port 38412 --delay 0.1
python3 injector.py --pcap gtp_fuzz.pcap --target 127.0.0.7 --port 2152  --delay 0.1
```

**4. Stop the watcher (Ctrl+C) and build the findings table**

```bash
python3 log_monitor.py report \
  --injection injection_log.csv \
  --flags flags.csv \
  --out findings_table.csv
```

`findings_table.csv` gives a per-packet verdict — `PASS` (rejected
cleanly), `FAIL` (crash/assert signature in the log window), or `REVIEW`
(ambiguous / silently dropped / no matching log line — worth a manual
look). Cross-check a few rows against the actual pcap in Wireshark using
the notes in `results/wireshark_capture_notes.md`.

## Results

See [`results/sample_findings.md`](results/sample_findings.md) for a full
worked table from one lab run. Short version: no full process crash was
observed across 200 NAS and 200 GTP-U mutated packets on this Open5GS
2.7.x build; one NAS mutator flagged a single suspicious out-of-bounds-read
log line worth a follow-up sanitizer-build pass, and the main GTP-U finding
was an observability gap (some malformed packets are silently dropped with
no log entry) rather than a crash. Full discussion, recommended fixes, and
honest limitations are in the report.

## Extending to real NGAP transport

If you want to remove the NAS-transport simplification described above,
the more faithful setup is:

1. Run [UERANSIM](https://github.com/aligungr/UERANSIM) as the gNB/UE
   simulator, pointed at your Open5GS AMF over real NGAP/SCTP.
2. Patch UERANSIM's `nr-gnb` NAS-forwarding path (or write a small SCTP
   client using `pysctp`) to substitute your fuzzed NAS bytes into the
   `InitialUEMessage` / `UplinkNASTransport` NGAP payload before it goes
   over the wire, instead of a legitimate NAS message.
3. Repeat the same injection/log-correlation loop against that path.

This is called out in the report as a natural next slot rather than
in-scope here, since it's a meaningfully larger amount of NGAP/SCTP
plumbing on top of the NAS-parser fuzzing this slot focuses on.

## References

See the References section in [`report/Capstone_Report.md`](report/Capstone_Report.md).
