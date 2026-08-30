# Example generator output

These four files are the actual, unmodified output of running:

```bash
python3 nas_fuzzer.py --count 20 --seed 42 --out nas_fuzz_sample.pcap
python3 gtp_fuzzer.py --count 20 --seed 7  --out gtp_fuzz_sample.pcap
```

They're included so a reviewer can open `nas_fuzz_sample.pcap` /
`gtp_fuzz_sample.pcap` in Wireshark and inspect real malformed bytes
without needing a running Open5GS instance first, and so the
`.manifest.csv` files show the exact mutator-to-packet-index mapping the
rest of the toolkit (`injector.py`, `log_monitor.py`) relies on.

These are a 20-packet smoke-test sample, not the 200-packet run referenced
in `results/sample_findings.md` — regenerate with `--count 200` and the
same seeds to reproduce that run's exact corpus.
