#!/usr/bin/env python3
"""
whois_lookup.py — Operation Hydra evidence tool

Looks up WHOIS registration data for a domain and flags common
spoofed-domain indicators (recent registration, privacy proxy, etc).

Usage:
    python whois_lookup.py --domain nimbus-secure-verify.com --demo
    python whois_lookup.py --domain <real-domain>   # live lookup

--demo mode reproduces the record in evidence/whois/whois-nimbus-secure-verify.txt
without any network call, so it works offline / in CI.
"""
import argparse
import sys
from datetime import datetime, timedelta

DEMO_RECORD = {
    "domain_name": "NIMBUS-SECURE-VERIFY.COM",
    "registrar": "Fictional Registrar LLC",
    "creation_date": datetime(2026, 5, 28),
    "name_servers": ["NS1.BULLETPROOF-HOSTING-EXAMPLE.NET", "NS2.BULLETPROOF-HOSTING-EXAMPLE.NET"],
    "registrant_org": "REDACTED FOR PRIVACY (Privacy Proxy)",
}


def live_lookup(domain):
    try:
        import whois
    except ImportError:
        print("python-whois not installed. Run: pip install python-whois", file=sys.stderr)
        sys.exit(1)
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": w.creation_date if not isinstance(w.creation_date, list) else w.creation_date[0],
            "name_servers": w.name_servers,
            "registrant_org": w.org,
        }
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}", file=sys.stderr)
        sys.exit(1)


def flag_indicators(record):
    flags = []
    creation = record.get("creation_date")
    if isinstance(creation, datetime):
        age_days = (datetime.now() - creation).days
        if age_days < 30:
            flags.append(f"Domain registered only {age_days} day(s) ago — very short aging window.")
    org = (record.get("registrant_org") or "")
    if "redact" in org.lower() or "privacy" in org.lower():
        flags.append("Registrant identity hidden behind a privacy/proxy service.")
    return flags


def main():
    ap = argparse.ArgumentParser(description="WHOIS lookup with spoofed-domain heuristics.")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    record = DEMO_RECORD if args.demo else live_lookup(args.domain)

    print(f"\n=== WHOIS report for {args.domain} ===")
    for k, v in record.items():
        print(f"{k:16}: {v}")

    flags = flag_indicators(record)
    print("\n--- Heuristic flags ---")
    if flags:
        for f in flags:
            print(f"[!] {f}")
    else:
        print("No red flags detected by these heuristics.")


if __name__ == "__main__":
    main()
