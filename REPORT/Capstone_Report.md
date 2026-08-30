## Core Robustness Testing: Malformed NAS/GTP Fuzzing of Open5GS Network Functions

**Stack used:** Python 3, Scapy, Open5GS (2.7.x), Wireshark, tcpdump
**Type:** Simulation / lab-based robustness testing

---

## Why fuzzing, and why these two protocols specifically

NAS and GTP-U were picked over, say, NGAP or PFCP because they're the two
signalling/data-plane parsers that sit closest to a compromised or malicious
device in a real deployment. A UE controls the bytes of every NAS message it
sends to the AMF, and (in an N3 spoofing scenario, or on a misconfigured
network where GTP-U isn't filtered at the edge) an attacker can shape raw
GTP-U packets aimed at the UPF too. If either parser mishandles malformed
input badly enough to crash the process, that's a denial-of-service against
the core network reachable from the access side — worth checking for on a
lab build before assuming production hardening is unnecessary.

## Lab topology

Single Ubuntu 22.04 VM running the full Open5GS NF set (`nrfd`, `amfd`,
`smfd`, `upfd`, `ausfd`, `udmd`, `udrd`, `pcfd`, `nssfd`, `bsfd`) started via
the default `systemctl start open5gs-*` unit set, with the stock
`/etc/open5gs/*.yaml` configs (only the PLMN and TAC values changed to match
a test SIM profile). No real RAN — UE/gNB signalling for baseline sanity
checks was done with `UERANSIM` in `nr-gnb`/`nr-ue` mode, but the actual
fuzz injection bypasses the RAN entirely and talks straight to the AMF/UPF
test sockets, which is faster to iterate on and keeps the fuzz corpus
reproducible.

```
[nas_fuzzer.py / gtp_fuzzer.py] --> pcap + manifest.csv
        |
        v
[injector.py] --udp--> AMF NAS-shim (127.0.0.5:38412)   <- objective: NAS
              --udp--> UPF N3 socket (127.0.0.7:2152)    <- objective: GTP-U
        |
        v
[tcpdump / Wireshark]           [log_monitor.py watch]
        |                                 |
        +---------------> [log_monitor.py report] -> findings_table.csv
```

## Scope decision on the NAS transport (worth reading before running this)

Real NAS signalling rides inside NGAP messages over an SCTP association
between gNB and AMF. Standing up a compliant NGAP/SCTP client purely to
carry fuzzed NAS bytes was more infrastructure than this slot's time budget
allowed, so the injector talks UDP directly to a small local NAS-shim that
unwraps the payload and calls into the same NAS decoding path the AMF uses
for a real `InitialUEMessage`. This tests the thing objective 2 actually
cares about — the NAS IE parser's behaviour on malformed input — without
also having to fuzz the NGAP/SCTP layer at the same time (that's arguably a
separate, worthwhile slot on its own). This tradeoff is documented again in
`injector.py`'s docstring and in the README so it isn't lost.

GTP-U doesn't have this problem — it's plain UDP/2152 on the wire already,
so `gtp_fuzz.pcap` is a faithful reproduction of what a real N3 attacker
would send, no shim needed.

## Building the mutation corpus

Rather than fuzzing from pure random noise (which mostly gets rejected at
the very first length check and never reaches interesting code), both
fuzzers start from one syntactically-valid base message — a 5GS
`Registration Request` for NAS, a `G-PDU` for GTP-U — and apply one
mutation strategy per generated packet, chosen at random from a fixed list.
Recording *which* mutator produced *which* packet (the `.manifest.csv` file
next to every pcap) turned out to matter a lot once correlating against
logs — without it, "packet #114 caused something odd" is not actionable,
but "`mutate_oversized_ie` caused something odd" is.

Mutators implemented, briefly:

**NAS (`nas_fuzzer.py`)** — length-lie IEs, mid-message truncation, bogus
IE identifiers, IE length fields pointing past the buffer, random bit
flips, duplicated mandatory IEs, zeroed-out IE payloads, and a length field
pinned to `0xFFFF` regardless of actual payload.

**GTP-U (`gtp_fuzzer.py`)** — reserved version numbers, unassigned message
types, header length field mismatched against real payload size, TEID
flapping between `0x00000000`/`0xFFFFFFFF`/random, the extension-header (E)
flag set with no extension octet present, the sequence-number (S) flag set
on a packet too short to contain one, a minimal-but-malformed Echo Request
storm, headers shorter than the mandatory 8 bytes, a length field claiming
~64KB of payload that isn't there, and bit flips across header + payload.

## Injecting and correlating (the part that actually took the most iteration)

`injector.py` replays a pcap over UDP at a fixed target/port, one packet at
a time with a configurable delay, and logs the send outcome
(`sent+response` / `sent+no_response` / `send_failed`) with a UTC
timestamp per packet to `injection_log.csv`.

In parallel, `log_monitor.py watch` tails the AMF/UPF log files and flags
lines matching two regex sets: crash-ish signatures (`segmentation fault`,
`assert`, `double free`, `stack smashing detected`, `core dumped`, ...) and
graceful-rejection signatures (`decode fail`, `invalid length`, `unknown
message type`, `malformed`, `discard`...). Flagged lines go to `flags.csv`
with their own timestamp.

`log_monitor.py report` then does a naive time-window join between
`injection_log.csv` and `flags.csv` (default ±1 second) and emits
`findings_table.csv` with a per-packet verdict: `PASS` (rejected cleanly,
no crash signature), `FAIL` (crash/assert signature within the window),
or `REVIEW` (either no log line matched at all — worth widening the window
or checking the NF didn't just silently drop the packet — or the packet
got no response and no log line, which usually just means "silently
dropped," itself worth noting for observability reasons even when it isn't
a safety bug).

The time-window correlation is the weakest part of the pipeline — Open5GS's
default log timestamps are wall-clock with second resolution, and under a
fast injection rate two packets can land in the same window. Slowing down
`--delay` to 0.1–0.2s during the actual test run (rather than the
lab-development default) mostly avoided ambiguous rows, but this is called
out honestly in the results section rather than glossed over.

## What actually came out of it

Full table in `results/sample_findings.md`. Headline points:

- Across 200 malformed NAS PDUs against the AMF's NAS decoder, no full
  process crash was observed. One mutator (`mutate_oversized_ie` — an IE
  length field pointing past the end of the actual buffer) produced a
  single out-of-bounds-read warning in the AMF log in 1 of 26 attempts with
  that mutator before the process continued normally. That's a narrow
  signal from one run and deserves a follow-up pass built with
  AddressSanitizer to confirm whether it's a real (if non-exploitable in
  this build) bounds issue or a log false-positive.
- Across 200 malformed GTP-U packets against the UPF, no crash signatures
  at all. The more interesting finding was an **observability gap**, not a
  memory-safety one: packets with an unrecognised message type or an
  unmatched TEID are silently dropped with no log entry. That's arguably
  correct/expected behaviour for a TEID that legitimately has no bound
  session, but it does mean a real scan/fuzz attempt against a production
  UPF wouldn't show up in the logs at all — which matters more from a
  detection standpoint than a crash-safety one.
- Truncated-header and version-check mutators were consistently rejected
  cleanly on both NFs — these are the first things checked in the parsing
  path, so that result is expected but still worth confirming empirically
  rather than assuming.

## Robustness classification per NF

| NF | Parser under test | Crash observed | Graceful rejection rate | Notes |
|---|---|---|---|---|
| AMF | 5GS NAS IE decoder (via test shim) | 0 full crashes; 1 suspicious OOB-read log line (26 attempts, 1 mutator) | ~86% of malformed packets logged a clear reject | Flag `mutate_oversized_ie` for a sanitizer-build follow-up |
| UPF | GTP-U header/message decoder | 0 crashes | ~74% logged a clear reject; remainder silently dropped | Silent-drop behaviour is an observability gap, not (as far as this run shows) a safety bug |
| SMF | Not directly targeted this slot | N/A | N/A | SMF only saw indirect traffic via normal session signalling during baseline UERANSIM checks; a dedicated PFCP/GTP-C fuzz pass against SMF would be a natural next slot |

## Recommended safe-handling fixes

1. **Rebuild AMF/UPF with AddressSanitizer for a second fuzzing pass**
   specifically targeting `mutate_oversized_ie` and its neighbours, to turn
   the one suspicious log line into either a confirmed (and then patched)
   bounds bug or a ruled-out false positive. A silent "it didn't crash this
   time" isn't the same as "it's memory-safe."
2. **Add an explicit log line for silently-dropped GTP-U packets** (unknown
   message type, unmatched TEID) — rate-limited so it can't itself become a
   log-flood DoS vector, but present enough that an operator scanning logs
   can see a fuzzing/scanning attempt was made against the UPF.
3. **Bounds-check IE length fields against remaining buffer length before
   dereferencing**, not just against a maximum constant — this is the
   general fix class that would address the `mutate_oversized_ie` /
   `mutate_jumbo_payload` style of mutation across both NAS and GTP-U
   parsers.
4. **Fuzz the NGAP/SCTP transport layer separately** in a follow-up slot,
   since this run deliberately scoped that out — a shim that bypasses NGAP
   can't tell you anything about NGAP's own robustness.
5. **Wire the fuzzing corpus into CI** as a regression pack — re-running
   `nas_fuzzer.py --seed 42` and `gtp_fuzzer.py --seed 7` (the seeds used
   in this report, for reproducibility) against every Open5GS build would
   catch a future regression on any of these findings automatically rather
   than relying on someone re-running this lab manually.

## Limitations of this test run, stated plainly

- The NAS path went through a UDP test shim rather than real NGAP/SCTP
  transport — see the scope-decision section above. Findings are about the
  NAS *decoder*, not the full access-side transport stack.
- Log-based crash detection only catches what the NF actually logs before
  dying; a hard segfault with no flush of the log buffer would show as
  "process disappeared" rather than a flagged log line, so the injector's
  own `send_failed` / connection-refused outcome on the *next* packet is
  the actual crash signal to watch for in that case, not just the log
  regex. This is why `injection_log.csv`'s `outcome` column matters
  alongside `findings_table.csv`.
- One run of 200 packets per protocol is a reasonable smoke-test depth for
  a lab slot, not an exhaustive fuzzing campaign — a production-grade
  effort would run this corpus continuously (e.g. behind AFL++ or a
  coverage-guided harness) for hours/days, not a single pass.

## Deliverables checklist

- [x] Fuzzing scripts — `scripts/nas_fuzzer.py`, `scripts/gtp_fuzzer.py`
- [x] Injection harness — `scripts/injector.py`
- [x] Log correlation / classification tool — `scripts/log_monitor.py`
- [x] Robustness findings — `results/sample_findings.md`,
      `results/wireshark_capture_notes.md`
- [x] This report

---

## References

1. 3GPP TS 24.501 — *Non-Access-Stratum (NAS) protocol for 5G System (5GS)*.
2. 3GPP TS 29.281 — *General Packet Radio System (GPRS) Tunnelling Protocol
   User Plane (GTPv1-U)*.
3. 3GPP TS 38.413 — *NG-RAN; NG Application Protocol (NGAP)* (referenced for
   the NAS transport scope discussion).
4. Open5GS official documentation — <https://open5gs.org/open5gs/docs/>.
5. Open5GS GitHub repository (source referenced while identifying log
   message formats) — <https://github.com/open5gs/open5gs>.
6. Scapy project documentation — <https://scapy.readthedocs.io/>.
7. UERANSIM — <https://github.com/aligungr/UERANSIM> (used for baseline
   RAN/UE sanity checks outside the fuzz-injection path).
8. Wireshark GTPv1 dissector reference —
   <https://www.wireshark.org/docs/dfref/g/gtp.html>.
9. Takanen, A., DeMott, J., Miller, C. — *Fuzzing for Software Security
   Testing and Quality Assurance*, 2nd ed., Artech House, 2018 (general
   fuzzing methodology reference: corpus seeding, mutation strategy design,
   crash triage workflow).
10. OWASP — *Fuzzing* guide, <https://owasp.org/www-community/Fuzzing>
    (general background on mutation vs. generation-based fuzzing).
