#!/usr/bin/env python3
import argparse
import asyncio
import aiodns
import aiohttp
import json
import os
import logging
from datetime import datetime

# Setup Logging
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/subdomain_sweeper.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# DNS Resolver
resolver = aiodns.DNSResolver()

# Asynchronous DNS check
async def resolve_subdomain(session, domain, subdomain, results):
    full_domain = f"{subdomain}.{domain}"
    try:
        await resolver.gethostbyname(full_domain, socket.AF_INET)
        results.append(full_domain)
        logging.info(f"Resolved: {full_domain}")
    except Exception as e:
        logging.debug(f"Failed: {full_domain} - {e}")

# Main async loop
async def sweep(domain, wordlist, output_file, concurrency):
    tasks = []
    results = []
    semaphore = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession():
        with open(wordlist, "r") as f:
            for line in f:
                sub = line.strip()
                if not sub:
                    continue
                async with semaphore:
                    tasks.append(resolve_subdomain(None, domain, sub, results))
        await asyncio.gather(*tasks)

    if output_file:
        os.makedirs("scans", exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {output_file}")
    else:
        for item in results:
            print(item)

# Argparse
def parse_args():
    parser = argparse.ArgumentParser(description="Asynchronous Subdomain Sweeper")
    parser.add_argument("-d", "--domain", required=True, help="Target root domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to subdomain wordlist")
    parser.add_argument("-o", "--output", help="Output file path (JSON format)")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Number of concurrent DNS requests")
    return parser.parse_args()

# Entry point
def main():
    args = parse_args()

    if not os.path.isfile(args.wordlist):
        logging.error(f"Wordlist not found: {args.wordlist}")
        print(f"[!] Wordlist file not found: {args.wordlist}")
        return

    print(f"[+] Starting subdomain sweep for: {args.domain}")
    asyncio.run(sweep(args.domain, args.wordlist, args.output, args.concurrency))

if __name__ == "__main__":
    main()
