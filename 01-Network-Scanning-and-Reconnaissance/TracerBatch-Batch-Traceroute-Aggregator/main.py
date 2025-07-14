#!/usr/bin/env python3
import argparse
import subprocess
import platform
import json
import logging
import os
from datetime import datetime

# Setup logging
log_path = "logs/debug.log"
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename=log_path,
    filemode="a",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def detect_os_command():
    if platform.system().lower() == "windows":
        return "tracert"
    return "traceroute"

def run_traceroute(target):
    command = detect_os_command()
    try:
        result = subprocess.run(
            [command, target],
            capture_output=True,
            text=True,
            timeout=30
        )
        logging.info(f"Traceroute for {target} completed.")
        return result.stdout
    except Exception as e:
        logging.error(f"Error running traceroute on {target}: {e}")
        return None

def parse_traceroute(output):
    hops = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(char.isdigit() for char in line) and "." in line:
            # Attempt to extract IP from line
            parts = line.split()
            for part in parts:
                if part.count('.') == 3:
                    hops.append(part)
                    break
    return hops

def main():
    parser = argparse.ArgumentParser(description="TracerBatch - Batch Traceroute Aggregator")
    parser.add_argument("-t", "--targets", nargs="+", required=True, help="List of target domains/IPs")
    parser.add_argument("-o", "--output", default="scans/traceroutes.json", help="Path to save JSON output")

    args = parser.parse_args()

    results = {}
    for target in args.targets:
        logging.info(f"Starting traceroute for: {target}")
        raw_output = run_traceroute(target)
        if raw_output:
            hops = parse_traceroute(raw_output)
            results[target] = hops
        else:
            results[target] = ["Error: Could not complete traceroute"]

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Traceroutes saved to {args.output}")

if __name__ == "__main__":
    main()
