# Operation Hydra

**Unraveling a Multi-Vector Cyber Crime Involving Phishing, Spoofing & Financial Fraud**

Assignment 2 — Unit 2: Types of Cyber Crimes

## ⚠️ Disclaimer

Every domain, IP address, email, transaction ID, file hash, and wallet address in
this repository is **simulated** for academic purposes. IP addresses use IANA
"documentation" ranges reserved by [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737)
(`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) and do not belong to any real
host. No real organization, domain, or individual is referenced. Any resemblance
to real infrastructure is coincidental.

## Summary

This repository documents a simulated investigation into "Operation Hydra," a
fictional multi-stage cyber-crime campaign combining:

1. Phishing & email/domain spoofing
2. Malware (RAT/keylogger) delivery via a weaponized attachment
3. Credential/OTP theft
4. Unauthorized UPI transactions
5. Money-mule layering and cryptocurrency laundering

The full legal-technical impact report is in [`report/`](report/).

## Repository Structure

```
operation-hydra/
├── README.md                     ← this file
├── AUTHORSHIP.md                 ← authorship declaration
├── report/
│   └── Operation-Hydra-Assignment2-Report.docx
├── evidence/
│   ├── phishing-emails/          ← simulated email header samples
│   ├── malware/                  ← IOCs and malware behavior notes
│   ├── financial-fraud/          ← transaction logs, mule account trace
│   └── whois/                    ← WHOIS lookup records for spoofed domain
├── scripts/
│   ├── spf_dkim_dmarc_check.py   ← checks SPF/DKIM/DMARC for a domain
│   ├── whois_lookup.py           ← WHOIS lookup wrapper
│   ├── ip_trace.py               ← IP geolocation / ASN / abuse lookup
│   └── malware_ioc_decoder.py    ← parses IOC json, flags MITRE ATT&CK-style behaviors
├── tools/
│   └── tools-list.md             ← tools used, with commands & justification
├── screenshots/                  ← tool output screenshots (see screenshots/README.md)
└── .github/workflows/ci.yml      ← markdown lint + directory structure check
```

## Setup Instructions

1. Clone the repo:
   ```bash
   git clone https://github.com/<your-username>/operation-hydra.git
   cd operation-hydra
   ```
2. Install script dependencies:
   ```bash
   pip install -r scripts/requirements.txt
   ```
3. Run any script in demo mode (uses bundled sample data, no network needed):
   ```bash
   python scripts/whois_lookup.py --domain nimbus-secure-verify.com --demo
   python scripts/spf_dkim_dmarc_check.py --domain nimbusfinserv.in --demo
   python scripts/ip_trace.py --ip 203.0.113.44 --demo
   python scripts/malware_ioc_decoder.py evidence/malware/iocs.json
   ```
   Omit `--demo` to perform a **live** lookup against a real domain/IP you are
   authorized to investigate (requires internet access and, for `ip_trace.py`,
   a free AbuseIPDB API key set as `ABUSEIPDB_API_KEY`).

## Evaluation Mapping

| Criterion | Where to find it |
|---|---|
| Cybercrime classification + legal framework (2.0) | `report/` §3 |
| Phishing/Spoofing technical analysis (2.0) | `evidence/phishing-emails/`, `evidence/whois/`, `scripts/spf_dkim_dmarc_check.py` |
| Malware/Trojan payload behavior analysis (2.0) | `evidence/malware/`, `scripts/malware_ioc_decoder.py` |
| Financial fraud simulation/tracing (2.0) | `evidence/financial-fraud/` |
| GitHub documentation, structure, CI compliance (1.0) | this README, `.github/workflows/ci.yml` |

## License

Academic use only. See [`LICENSE`](LICENSE).
