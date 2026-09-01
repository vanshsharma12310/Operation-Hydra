#!/usr/bin/env python3
"""
spf_dkim_dmarc_check.py — Operation Hydra evidence tool

Checks a domain's SPF and DMARC TXT records (DKIM requires knowing the
selector, so this script reports on SPF/DMARC directly and explains how to
extend it for a known DKIM selector).

Usage:
    python spf_dkim_dmarc_check.py --domain nimbusfinserv.in
    python spf_dkim_dmarc_check.py --domain nimbusfinserv.in --demo

--demo uses bundled sample data and performs NO network lookups, so it
works offline / in CI. Omit --demo to perform a live DNS query (requires
internet access and dnspython: `pip install dnspython`).
"""
import argparse
import json
import sys

DEMO_RECORDS = {
    "nimbusfinserv.in": {
        "spf": "v=spf1 include:_spf.nimbusfinserv.in ip4:203.0.113.0/24 -all",
        "dmarc": "v=DMARC1; p=reject; rua=mailto:[email protected]",
    },
    "nimbus-secure-verify.com": {
        "spf": None,
        "dmarc": None,
    },
}


def live_lookup(domain):
    try:
        import dns.resolver
    except ImportError:
        print("dnspython not installed. Run: pip install dnspython", file=sys.stderr)
        sys.exit(1)

    result = {"spf": None, "dmarc": None}
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt.startswith("v=spf1"):
                result["spf"] = txt
    except Exception as e:
        print(f"[!] SPF lookup failed for {domain}: {e}", file=sys.stderr)

    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt.startswith("v=DMARC1"):
                result["dmarc"] = txt
    except Exception as e:
        print(f"[!] DMARC lookup failed for {domain}: {e}", file=sys.stderr)

    return result


def analyze(domain, records):
    print(f"\n=== SPF / DMARC report for {domain} ===")
    spf = records.get("spf")
    dmarc = records.get("dmarc")

    if spf:
        print(f"[SPF]   {spf}")
    else:
        print("[SPF]   No SPF record found — domain is more vulnerable to spoofing.")

    if dmarc:
        print(f"[DMARC] {dmarc}")
        if "p=reject" in dmarc:
            print("        Policy: REJECT (strong) — non-aligned mail should be dropped.")
        elif "p=quarantine" in dmarc:
            print("        Policy: QUARANTINE (moderate) — non-aligned mail goes to spam.")
        elif "p=none" in dmarc:
            print("        Policy: NONE (monitor only) — spoofed mail is NOT blocked by this policy.")
    else:
        print("[DMARC] No DMARC record found — spoofed 'From' headers using this domain "
              "will not be rejected or quarantined by receiving mail servers.")

    print("\nNote: DKIM requires a known selector (e.g. 'selector1._domainkey.<domain>').")
    print("If you have a raw email, extract the 'd=' and 's=' values from its")
    print("DKIM-Signature header and query: <selector>._domainkey.<domain> TXT")


def main():
    ap = argparse.ArgumentParser(description="Check SPF/DMARC records for spoofing evidence.")
    ap.add_argument("--domain", required=True, help="Domain to check")
    ap.add_argument("--demo", action="store_true", help="Use bundled sample data, no network")
    ap.add_argument("--json", action="store_true", help="Output raw JSON instead of a report")
    args = ap.parse_args()

    if args.demo:
        records = DEMO_RECORDS.get(args.domain, {"spf": None, "dmarc": None})
    else:
        records = live_lookup(args.domain)

    if args.json:
        print(json.dumps({"domain": args.domain, **records}, indent=2))
    else:
        analyze(args.domain, records)


if __name__ == "__main__":
    main()
