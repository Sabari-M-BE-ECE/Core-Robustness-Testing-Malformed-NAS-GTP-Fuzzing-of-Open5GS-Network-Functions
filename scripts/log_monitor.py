#!/usr/bin/env python3
"""
log_monitor.py
---------------
Slot 44 - Core robustness testing (Open5GS)

Two jobs:
  1. "watch" mode - tails one or more Open5GS NF log files live while
     injector.py is running, and flags lines matching known
     crash/assert/exception/error signatures with a timestamp, so they
     can be correlated against injection_log.csv afterwards.
  2. "report" mode - given injection_log.csv plus the flagged-lines CSV
     from a watch session, produces results/sample_findings.md style
     robustness table (per-NF, per-mutator).

Open5GS default log locations (adjust to your install):
    /var/log/open5gs/amf.log
    /var/log/open5gs/smf.log
    /var/log/open5gs/upf.log
    /var/log/open5gs/mme.log   (if 4G components are also present)

Usage:
    # terminal 1
    python3 log_monitor.py watch --logs /var/log/open5gs/amf.log /var/log/open5gs/upf.log --out flags.csv

    # terminal 2, while (1) is running
    python3 injector.py --pcap nas_fuzz.pcap --target 127.0.0.5 --port 38412

    # after both finish
    python3 log_monitor.py report --injection injection_log.csv --flags flags.csv --out findings_table.csv
"""

import argparse
import csv
import re
import time
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    HAVE_COLOR = True
except ImportError:
    HAVE_COLOR = False

# Signatures that indicate the parser did NOT fail gracefully.
# Extend this list based on what you actually see in your build's logs.
CRASH_SIGNATURES = [
    r"segmentation fault",
    r"core dumped",
    r"assert(ion)? failed",
    r"\bAssert\(",
    r"double free",
    r"stack smashing detected",
    r"terminate called after throwing",
    r"backtrace",
]

# Signatures that indicate the parser DID reject the input safely.
# NOTE: this list was tuned against real Open5GS 2.7.x log output observed
# during this project's lab run, e.g.:
#   "[upf] ERROR: [DROP] Invalid GTPU version [0] (../src/upf/gtp-path.c:305)"
#   "[upf] ERROR: [127.0.0.7] Send Error Indication [TEID:0x...] to [...] (../src/upf/gtp-path.c:419)"
#   "[amf] ERROR: No suitable NAS message type"  (illustrative - confirm against your own log)
# If you're seeing 0 flagged lines, run:
#   sudo grep -iE "error|invalid|drop|discard|reject|fail" /var/log/open5gs/<nf>.log | tail -20
# and add any new wording you see below.
GRACEFUL_SIGNATURES = [
    r"decod(e|ing) fail",
    r"invalid (length|ie|message|gtpu|version|header|teid)",
    r"unknown message type",
    r"discard(ing)? (the )?message",
    r"nas.?message.*reject",
    r"integrity check fail",
    r"gtp.*header.*error",
    r"malformed",
    r"parse error",
    r"\[drop\]",                       # Open5GS's literal "[DROP]" tag
    r"send error indication",          # GTP-U error-indication path (gtp-path.c)
    r"no suitable",
    r"unable to (decode|parse|process)",
    r"invalid.*teid",
    r"gtp.*version",                   # catches "Invalid GTPU version" broadly
]

CRASH_RE = re.compile("|".join(CRASH_SIGNATURES), re.IGNORECASE)
GRACEFUL_RE = re.compile("|".join(GRACEFUL_SIGNATURES), re.IGNORECASE)


def follow(path: Path):
    """Generator that yields new lines appended to a growing log file (tail -f)."""
    with open(path, "r", errors="replace") as f:
        f.seek(0, 2)  # go to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line


def cmd_watch(args):
    out_rows = []
    print(f"[+] Watching {len(args.logs)} log file(s). Ctrl+C to stop and flush {args.out}.")
    followers = {Path(p): follow(Path(p)) for p in args.logs}

    try:
        while True:
            for path, gen in followers.items():
                line = next(gen)
                ts = datetime.utcnow().isoformat()
                classification = None
                if CRASH_RE.search(line):
                    classification = "CRASH_SIGNAL"
                    color = Fore.RED if HAVE_COLOR else ""
                elif GRACEFUL_RE.search(line):
                    classification = "GRACEFUL_REJECT"
                    color = Fore.GREEN if HAVE_COLOR else ""
                if classification:
                    reset = Style.RESET_ALL if HAVE_COLOR else ""
                    print(f"{color}[{classification}] {path.name}: {line.strip()}{reset}")
                    out_rows.append({
                        "timestamp_utc": ts,
                        "nf_log": path.name,
                        "classification": classification,
                        "line": line.strip(),
                    })
    except KeyboardInterrupt:
        pass
    finally:
        with open(args.out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["timestamp_utc", "nf_log", "classification", "line"])
            writer.writeheader()
            writer.writerows(out_rows)
        print(f"\n[+] Flagged {len(out_rows)} lines -> {args.out}")


def cmd_report(args):
    with open(args.injection) as f:
        injections = list(csv.DictReader(f))

    flags = []
    if Path(args.flags).exists():
        with open(args.flags) as f:
            flags = list(csv.DictReader(f))

    # naive time-window correlation: any flagged line within +/- window_sec
    # of an injection timestamp is attributed to that injection.
    from datetime import timedelta
    window = timedelta(seconds=args.window)

    def parse_ts(s):
        return datetime.fromisoformat(s)

    rows = []
    for inj in injections:
        inj_ts = parse_ts(inj["timestamp_utc"])
        matches = [
            fl for fl in flags
            if abs(parse_ts(fl["timestamp_utc"]) - inj_ts) <= window
        ]
        crash_hits = [m for m in matches if m["classification"] == "CRASH_SIGNAL"]
        graceful_hits = [m for m in matches if m["classification"] == "GRACEFUL_REJECT"]

        if crash_hits:
            verdict = "FAIL - crash/assert signature observed"
        elif graceful_hits:
            verdict = "PASS - rejected with error log, no crash"
        elif inj["outcome"] == "sent+no_response":
            verdict = "REVIEW - no log line and no response (silent drop?)"
        else:
            verdict = "REVIEW - no matching log line found in window"

        rows.append({
            "index": inj["index"],
            "mutator": inj["mutator"],
            "payload_len": inj["payload_len"],
            "outcome": inj["outcome"],
            "log_matches": len(matches),
            "verdict": verdict,
        })

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["index", "mutator", "payload_len", "outcome", "log_matches", "verdict"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Findings table written to {args.out} ({len(rows)} rows)")


def main():
    ap = argparse.ArgumentParser(description="Open5GS log correlation tool for fuzzing runs")
    sub = ap.add_subparsers(dest="cmd", required=True)

    watch = sub.add_parser("watch", help="tail NF logs live and flag crash/graceful-reject signatures")
    watch.add_argument("--logs", nargs="+", required=True, help="one or more Open5GS log file paths")
    watch.add_argument("--out", default="flags.csv")
    watch.set_defaults(func=cmd_watch)

    report = sub.add_parser("report", help="correlate injection_log.csv with flagged log lines")
    report.add_argument("--injection", required=True)
    report.add_argument("--flags", required=True)
    report.add_argument("--window", type=float, default=1.0, help="correlation window in seconds")
    report.add_argument("--out", default="findings_table.csv")
    report.set_defaults(func=cmd_report)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
