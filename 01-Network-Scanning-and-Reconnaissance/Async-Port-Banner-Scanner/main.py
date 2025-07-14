#!/usr/bin/env python3

import argparse
import asyncio
import json
import os
import logging

# Prepare output folders
os.makedirs("logs", exist_ok=True)
os.makedirs("scans", exist_ok=True)

# Setup logging
logging.basicConfig(
    filename="logs/scan.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# Banner grabbing
async def grab_banner(ip, port):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=3
        )
        writer.write(b"\r\n")
        await writer.drain()
        banner = await asyncio.wait_for(reader.read(1024), timeout=2)
        writer.close()
        await writer.wait_closed()

        result = {
            "ip": ip,
            "port": port,
            "status": "open",
            "banner": banner.decode(errors="ignore").strip()
        }
        logging.info(f"[OPEN] {ip}:{port} — {result['banner']}")
        return result

    except Exception as e:
        logging.warning(f"[FAIL] {ip}:{port} — {e}")
        return {
            "ip": ip,
            "port": port,
            "status": "closed or filtered",
            "error": str(e)
        }

# Parse ports
def parse_ports(port_str):
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

# Async port scan
async def scan_host(ip, ports):
    tasks = [grab_banner(ip, port) for port in ports]
    return await asyncio.gather(*tasks)

# Save output to scans/
def save_results(data, out_file):
    with open(out_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Scan results saved to {out_file}")

# Main CLI
def main():
    parser = argparse.ArgumentParser(description="Async Port & Banner Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--ports", default="22,80,443", help="Ports (e.g. 80,443 or 1-1000)")
    parser.add_argument("-o", "--output", default="scans/scan_output.json", help="Output file path")

    args = parser.parse_args()
    ports = parse_ports(args.ports)

    print(f"[+] Scanning {args.target} on ports: {ports}")
    try:
        results = asyncio.run(scan_host(args.target, ports))
        save_results(results, args.output)
    except Exception as e:
        logging.error(f"[FATAL] {e}")
        print(f"[!] Fatal error occurred: {e}")

if __name__ == "__main__":
    main()
