#!/usr/bin/env python3
# main.py

import argparse
import json
import logging
import os
import platform
import subprocess
from datetime import datetime
from typing import List

def setup_logger():
    os.makedirs("logs", exist_ok=True)
    log_path = f"logs/tracer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        filename=log_path,
        filemode='w',
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def parse_args():
    parser = argparse.ArgumentParser(description="NetPath-Tracer: Multi-target traceroute path visualizer.")
    parser.add_argument("-t", "--targets", nargs="+", required=True, help="List of IPs or domains to trace.")
    parser.add_argument("-o", "--output", default="scans/traceroutes.json", help="Path to save traceroute results.")
    parser.add_argument("--timeout", type=int, default=2, help="Timeout per hop (in seconds).")
    return parser.parse_args()

def run_traceroute(target: str, timeout: int) -> List[str]:
    system = platform.system().lower()
    command = []

    if system == "windows":
        command = ["tracert", "-d", target]
    elif system in ["linux", "darwin"]:
        command = ["traceroute", "-n", "-w", str(timeout), target]
    else:
        logging.error(f"Unsupported platform: {system}")
        return []

    logging.info(f"Running traceroute for {target}")
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode()
        return output.splitlines()
    except subprocess.CalledProcessError as e:
        logging.error(f"Traceroute failed for {target}: {e.output.decode()}")
        return []

def parse_hops(traceroute_output: List[str]) -> List[str]:
    hops = []
    for line in traceroute_output:
        if line.strip() == "":
            continue
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0].isdigit():
            for part in parts[1:]:
                if part.count('.') == 3 or part == '*':
                    hops.append(part)
                    break
    return hops

def main():
    setup_logger()
    args = parse_args()

    os.makedirs("scans", exist_ok=True)
    results = {}

    for target in args.targets:
        logging.info(f"Tracing {target}")
        trace_lines = run_traceroute(target, args.timeout)
        hops = parse_hops(trace_lines)
        results[target] = hops
        print(f"[+] {target}: {len(hops)} hops")

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
