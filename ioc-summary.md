# Malware Payload Analysis — Summary

> All indicators below are simulated. See [`iocs.json`](iocs.json) for the
> machine-readable version consumed by `scripts/malware_ioc_decoder.py`.

## Classification

The attachment `KYC Update Form.pdf.exe` uses a double-extension trick
(`.pdf.exe`) to appear as a harmless PDF in a truncated file listing. Based
on its simulated behavior profile, it is classified as a **Remote Access
Trojan (RAT) with an embedded keylogger module** — not a simple Trojan
downloader (which typically fetches a second-stage payload and exits) and
not a logic bomb (which lies dormant until a trigger condition, rather than
maintaining live remote control).

## Why not other categories?

| Category | Ruled out because |
|---|---|
| Logic bomb | No dormant trigger condition observed; payload beacons immediately and continuously. |
| Simple Trojan downloader | Payload does not fetch and exit — it persists and maintains an interactive C2 channel. |
| Worm | No self-propagation / network-scanning behavior observed. |
| Ransomware | No file encryption or ransom note behavior observed. |
| **RAT + keylogger (selected)** | Matches: persistence, periodic C2 beaconing, targeted keystroke capture, data exfiltration. |

## Attack-vector mapping

The RAT's keystroke/OTP-capture module is the direct technical link between
the malware stage and the financial-fraud stage: harvested OTPs are what
allow the attacker's fraud kit (see `evidence/financial-fraud/`) to
authorize unauthorized UPI transactions without the victim's knowledge.

## Recommended real-world tooling (not run here — see `tools/tools-list.md`)

- Static: `strings`, PEiD/`pefile`, VirusTotal file-hash lookup
- Dynamic/sandbox: Any.Run, Joe Sandbox, Cuckoo Sandbox (isolated VM only)
- Network: Wireshark/tshark on sandboxed traffic to confirm C2 beacon pattern
