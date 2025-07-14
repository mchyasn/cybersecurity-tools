#!/usr/bin/env python3
"""
DNSReconX – Advanced DNS Recon Toolkit
Author: mchyasn
"""

import argparse
import asyncio
import json
import os
import logging
from datetime import datetime, timezone

import aiodns
import dns.query
import dns.resolver
import dns.zone

# ---------------------------------------------------------------------------
# Directories & Logging
# ---------------------------------------------------------------------------

OUTPUT_DIR = "scans"
LOG_DIR = "logs"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=f"{LOG_DIR}/debug.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "dev", "test", "api", "ns1", "ns2",
]

resolver_sync = dns.resolver.Resolver()
resolver_sync.timeout = 3
resolver_sync.lifetime = 5

# ---------------------------------------------------------------------------
# Async helpers
# ---------------------------------------------------------------------------

async def resolve_record(domain: str, rtype: str, resolver_async: aiodns.DNSResolver):
    try:
        result = await resolver_async.query(domain, rtype)
        return [str(r) for r in result]
    except Exception as exc:
        logging.warning(f"{rtype} query failed for {domain}: {exc}")
        return []

async def enumerate_records(domain: str):
    print(f"[+] Enumerating DNS records for {domain}...")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    resolver_async = aiodns.DNSResolver()
    tasks = [resolve_record(domain, r, resolver_async) for r in record_types]
    return dict(zip(record_types, await asyncio.gather(*tasks)))

async def brute_force(domain: str, wordlist):
    print(f"[+] Brute-forcing subdomains for {domain}...")
    resolver_async = aiodns.DNSResolver()
    tasks, subs = [], []
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        subs.append(fqdn)
        tasks.append(resolve_record(fqdn, "A", resolver_async))

    results = await asyncio.gather(*tasks)
    return [
        {"subdomain": fqdn, "A": ans}
        for fqdn, ans in zip(subs, results) if ans
    ]

# ---------------------------------------------------------------------------
# Sync helpers
# ---------------------------------------------------------------------------

def attempt_axfr(domain: str):
    print(f"[+] Attempting AXFR for {domain}...")
    try:
        ns_records = resolver_sync.resolve(domain, "NS")
        for ns in ns_records:
            ns_host = str(getattr(ns, "target", ns))
            logging.info(f"Attempting AXFR @ {ns_host}")
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_host, domain, timeout=5)
                )
                if zone:
                    print(f"[+] AXFR successful from {ns_host}")
                    return {n.to_text(): zone[n].to_text() for n in zone.nodes}
            except Exception as exc:
                logging.debug(f"AXFR failed @ {ns_host}: {exc}")
    except Exception as exc:
        logging.warning(f"NS resolution failed for {domain}: {exc}")
    print("[!] AXFR unsuccessful.")
    return {}

def detect_wildcard(domain: str):
    print(f"[+] Checking for wildcard DNS on {domain}...")
    fake = f"nonexistent-{int(datetime.now(timezone.utc).timestamp())}.{domain}"
    try:
        resolver_sync.resolve(fake, "A")
        print("[!] Wildcard DNS detected.")
        return True
    except dns.resolver.NXDOMAIN:
        print("[+] No wildcard DNS detected.")
        return False
    except Exception as exc:
        logging.warning(f"Wildcard test error on {domain}: {exc}")
        return False

def load_wordlist(path):
    if path and os.path.isfile(path):
        print(f"[+] Using custom wordlist: {path}")
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    return DEFAULT_WORDLIST

def write_output(data, domain):
    fname = f"{OUTPUT_DIR}/{domain.replace('.', '_')}_results.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logging.info(f"Results written to {fname}")
    print(f"[+] Results saved to {fname}")

# ---------------------------------------------------------------------------
# Event loop
# ---------------------------------------------------------------------------

def get_loop():
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DNSReconX – Advanced DNS Recon Toolkit"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--brute", action="store_true", help="Brute-force subdomains")
    parser.add_argument("--wordlist", help="Custom wordlist file path")
    parser.add_argument("--axfr", action="store_true", help="Attempt AXFR transfer")
    parser.add_argument("--wildcard", action="store_true", help="Check wildcard DNS")

    args = parser.parse_args()
    domain = args.domain.lower().strip()

    print(f"\n=== DNSReconX started for {domain} ===\n")

    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    loop = get_loop()
    result["records"] = loop.run_until_complete(enumerate_records(domain))

    if args.axfr:
        result["axfr"] = attempt_axfr(domain)
    if args.wildcard:
        result["wildcard"] = detect_wildcard(domain)
    if args.brute:
        wl = load_wordlist(args.wordlist)
        result["brute_force"] = loop.run_until_complete(brute_force(domain, wl))

    write_output(result, domain)

    print(f"\n[✔] Done. All logs saved in logs/debug.log\n")

if __name__ == "__main__":
    main()
