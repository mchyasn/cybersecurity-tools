#!/usr/bin/env python3

import argparse
import asyncio
import ipaddress
import socket
import json
import logging
import time
from datetime import datetime
from typing import List

# Setup logging
log_file = f"logs/debug.log"
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Async TCP connection and banner grabber
async def scan_port(ip: str, port: int) -> dict:
    result = {"ip": ip, "port": port, "status": "closed"}
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=1.5)
        result["status"] = "open"

        try:
            writer.write(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            result["banner"] = banner.decode(errors="ignore").strip()
        except Exception as e:
            result["banner"] = f"Banner error: {str(e)}"
        finally:
            writer.close()
            await writer.wait_closed()
    except Exception as e:
        logging.debug(f"{ip}:{port} -> {e}")
    return result

# Generate list of IPs
def expand_targets(target: str) -> List[str]:
    try:
        if '/' in target:
            return [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        else:
            socket.gethostbyname(target)  # Validate hostname
            return [target]
    except Exception as e:
        logging.error(f"Invalid target: {target} - {e}")
        return []

# Main scanner
async def run_scanner(targets: List[str], ports: List[int]) -> List[dict]:
    tasks = []
    sem = asyncio.Semaphore(1000)  # Limit concurrency

    async def limited_scan(ip, port):
        async with sem:
            return await scan_port(ip, port)

    for ip in targets:
        for port in ports:
            tasks.append(limited_scan(ip, port))
    results = await asyncio.gather(*tasks)
    return [r for r in results if r["status"] == "open"]

def parse_ports(ports_arg: str) -> List[int]:
    ports = set()
    for part in ports_arg.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TurboScan: Async High-Speed Port & Banner Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP, hostname, or CIDR (e.g., 192.168.1.1, scanme.nmap.org, 10.0.0.0/24)")
    parser.add_argument("-p", "--ports", default="80,443,22", help="Ports (e.g., 22,80 or 1-1024)")
    parser.add_argument("-o", "--output", default=f"scans/turboscan_{int(time.time())}.json", help="Output file path (default: scans/...)")

    args = parser.parse_args()
    ip_list = expand_targets(args.target)
    port_list = parse_ports(args.ports)

    print(f"[+] Scanning {len(ip_list)} hosts on ports: {port_list}")
    start = time.time()
    results = asyncio.run(run_scanner(ip_list, port_list))
    duration = round(time.time() - start, 2)
    print(f"[+] Scan completed in {duration} seconds. {len(results)} open ports found.")

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results saved to {args.output}")
