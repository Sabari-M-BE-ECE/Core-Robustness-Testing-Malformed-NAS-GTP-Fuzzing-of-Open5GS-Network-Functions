# Wireshark Capture Notes

## Capture setup

```bash
# on the Open5GS host, capture the loopback / test interface used by the lab
sudo tcpdump -i lo -w capture_run1.pcap udp port 2152 or udp port 38412
```

Run this in parallel with `injector.py`, then open `capture_run1.pcap` in
Wireshark alongside `injection_log.csv` to check timestamps line up.

## GTP-U packets

* Wireshark ships a native GTP-U dissector (`Decode As... -> GTPv1`), so
  malformed packets from `gtp_fuzz.pcap` show up nicely, and Wireshark's own
  dissector often flags the same malformed fields we intentionally injected
  (e.g. `[Malformed Packet]`, `Length field does not match`), which is a
  useful sanity check that the mutation actually landed on the wire as
  intended, independent of what the UPF itself logged.
* Filter used during review: `gtpv1 && (gtpv1.flags.v != 1 || gtp.length < 0)`
  surfaces the version and length mutators quickly.

## NAS packets

* Wireshark has no public 5GS-NAS dissector for arbitrary UDP traffic in
  this lab setup (it dissects NAS when it can see the surrounding NGAP/SCTP
  session, which this lab's UDP shim doesn't provide). Malformed NAS PDUs
  therefore show up as raw UDP payload in Wireshark.
* To inspect NAS bytes by hand: select a frame -> right-click the UDP
  payload -> "Decode As" is not useful here; instead export the payload
  bytes (`File > Export Packet Bytes`) and diff them against
  `nas_fuzz.pcap.manifest.csv` to confirm which mutator produced which
  on-wire bytes.
* If you want full NGAP/NAS dissection, the more faithful (but heavier)
  setup is to run a real gNB simulator (`UERANSIM`) and have it forward the
  NAS payload inside a real NGAP `InitialUEMessage` / `UplinkNASTransport`
  over SCTP to the AMF — see the README "Extending to real NGAP transport"
  section for pointers if you want to take this further.

## What to screenshot for the report

1. Wireshark main window with `capture_run1.pcap` open, GTP-U column showing
   a `[Malformed Packet]` marker next to a `mutate_length_mismatch` frame.
2. The AMF/UPF terminal (or `journalctl -u open5gs-amfd -f`) at the same
   timestamp, showing the corresponding reject/error log line.
3. `log_monitor.py watch` terminal output highlighting a `GRACEFUL_REJECT`
   line in green.
4. The final `findings_table.csv` opened in a spreadsheet or `column -t -s,`.
