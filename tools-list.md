# Tools Used

| Tool | Purpose | Example command / usage | Justification |
|---|---|---|---|
| **MXToolbox** | SPF/DKIM/DMARC and blacklist lookup | Web UI: mxtoolbox.com/SuperTool.aspx | Fast, free baseline for email-authentication triage |
| **VirusTotal** | File hash, URL, and domain reputation | Web UI or `vt-cli file <hash>` | Aggregates 70+ AV/URL engines; standard first pass on any IOC |
| **AbuseIPDB** | IP abuse-report history and confidence score | `python scripts/ip_trace.py --ip <ip>` (uses AbuseIPDB API) | Crowdsourced abuse reports corroborate malicious hosting |
| **WHOIS** | Domain registration metadata | `python scripts/whois_lookup.py --domain <domain>` | Reveals registration age and privacy-proxy use — both spoofing indicators |
| **dnspython** | Raw DNS TXT record queries | `python scripts/spf_dkim_dmarc_check.py --domain <domain>` | Confirms SPF/DMARC policy directly from authoritative DNS |
| **Google Admin Toolbox Messageheader** | Parses raw email headers | Paste header into toolbox.googleapps.com/apps/messageheader/ | Simplifies reading Received/Authentication-Results chains |
| **Block explorer** (e.g. public BTC/ETH explorer) | Wallet transaction graph tracing | Web UI, search wallet address | Necessary to follow laundering hops on-chain |
| **Wireshark / tshark** | Network traffic capture and analysis (sandboxed) | `tshark -r capture.pcap -Y "http"` | Confirms malware C2 beacon pattern and destination |
| **Any.Run / Cuckoo Sandbox** | Dynamic malware analysis in an isolated VM | Upload sample via web UI | Safely observes real runtime behavior without risking the host |

All lookups in this repository were run in **`--demo` mode** using bundled
simulated data (see `scripts/`), so no real external service was queried
against a live target.
