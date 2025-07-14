#!/usr/bin/env python3

import argparse
import asyncio
import socket
import platform
import logging
import json
import re
from datetime import datetime

# Setup logging
logging.basicConfig(
    filename='logs/debug.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# OS fingerprinting based on TTL values
def detect_os_from_ttl(ttl):
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux/Unix"
    else:
        return "Unknown"

async def probe_port(ip, port, timeout=3):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # Attempt to read banner
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            banner = banner.decode(errors="ignore").strip()
        except:
            banner = ""

        sock = writer.get_extra_info("socket")
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        os_guess = detect_os_from_ttl(ttl)
        writer.close()
        await writer.wait_closed()
        return {
            "port": port,
            "status": "open",
            "os": os_guess,
            "banner": banner
        }
    except Exception as e:
        logging.warning(f"Port {port} closed or error: {e}")
        return {
            "port": port,
            "status": "closed",
            "error": str(e)
        }

async def smart_scan(ip, ports):
    tasks = [probe_port(ip, p) for p in ports]
    results = await asyncio.gather(*tasks)
    return results

def parse_ports(ports_input):
    if "-" in ports_input:
        start, end = map(int, ports_input.split("-"))
        return list(range(start, end + 1))
    else:
        return [int(p) for p in ports_input.split(",")]

def main():
    parser = argparse.ArgumentParser(description="SmartPortMap - Adaptive Port and Service Mapper")
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    parser.add_argument("-p", "--ports", default="21,22,23,25,53,80,110,135,139,143,443,445,3306,3389", help="Ports to scan (e.g., 22,80,443 or 20-25)")
    parser.add_argument("-o", "--output", default=None, help="Path to save results (JSON)")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
        ports = parse_ports(args.ports)
        logging.info(f"Scanning {ip} on ports: {ports}")
        print(f"[+] Starting smart scan on {ip}")
        results = asyncio.run(smart_scan(ip, ports))
        
        final_result = {
            "target": args.target,
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat(),
            "results": results
        }

        output_path = args.output or f"scans/smart_scan_{args.target}.json"
        with open(output_path, "w") as f:
            json.dump(final_result, f, indent=2)
        print(f"[+] Scan complete. Results saved to {output_path}")

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
