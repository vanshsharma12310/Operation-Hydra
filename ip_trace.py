#!/usr/bin/env python3
"""
ip_trace.py — Operation Hydra evidence tool

Reports basic geolocation/ASN context for an IP and, if an AbuseIPDB API
key is supplied, its abuse-report score.

Usage:
    python ip_trace.py --ip 203.0.113.44 --demo
    ABUSEIPDB_API_KEY=xxxx python ip_trace.py --ip <real-ip>

--demo uses bundled sample data (RFC 5737 documentation-range IPs used
throughout this project) and makes no network calls.
"""
import argparse
import json
import os
import sys

DEMO_DATA = {
    "203.0.113.44": {
        "range": "203.0.113.0/24 (RFC 5737 TEST-NET-3, used as stand-in)",
        "asn_note": "Simulated 'bulletproof hosting' ASN",
        "abuse_score": 87,
        "reports": 14,
        "notes": "Source IP for phishing email sample-01 and sample-03.",
    },
    "198.51.100.23": {
        "range": "198.51.100.0/24 (RFC 5737 TEST-NET-2, used as stand-in)",
        "asn_note": "Simulated malware C2 hosting ASN",
        "abuse_score": 93,
        "reports": 21,
        "notes": "Malware C2 IP — see evidence/malware/iocs.json.",
    },
}


def live_lookup(ip):
    try:
        import requests
    except ImportError:
        print("requests not installed. Run: pip install requests", file=sys.stderr)
        sys.exit(1)

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        print("[!] No ABUSEIPDB_API_KEY set — skipping abuse-score lookup.", file=sys.stderr)
        return {"ip": ip, "abuse_score": None, "reports": None}

    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    return {
        "ip": ip,
        "abuse_score": data.get("abuseConfidenceScore"),
        "reports": data.get("totalReports"),
        "isp": data.get("isp"),
        "country": data.get("countryCode"),
    }


def main():
    ap = argparse.ArgumentParser(description="IP trace / abuse-reputation lookup.")
    ap.add_argument("--ip", required=True)
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    if args.demo:
        record = DEMO_DATA.get(args.ip, {"notes": "No demo data for this IP."})
    else:
        record = live_lookup(args.ip)

    print(f"\n=== IP trace report for {args.ip} ===")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
