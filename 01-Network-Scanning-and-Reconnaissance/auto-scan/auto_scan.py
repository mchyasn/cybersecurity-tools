#!/usr/bin/env python3

import os
import argparse
import datetime
import subprocess

def get_scan_flags(mode):
    presets = {
        "quick": ["-T4", "--top-ports", "100", "-sV"],
        "stealth": ["-sS", "-T2", "-Pn"],
        "full": ["-p-", "-T4", "-sV"],
        "custom": []  # will be handled manually
    }
    return presets.get(mode, presets["quick"])

def run_nmap(target, ports, output_path, scan_mode):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{target.replace('.', '_')}_{scan_mode}_{timestamp}.log"
    full_output_path = os.path.join(output_path, filename)

    scan_flags = get_scan_flags(scan_mode)
    base_cmd = ["nmap"] + scan_flags + ["-oN", full_output_path]

    if scan_mode == "custom" and ports:
        base_cmd += ["-p", ports]

    base_cmd.append(target)

    print(f"[+] Running Nmap scan: {scan_mode} on {target}")
    subprocess.run(base_cmd)

    print(f"[+] Scan saved to: {full_output_path}")

def main():
    parser = argparse.ArgumentParser(description="auto-scan: Fast Recon & Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    parser.add_argument("-m", "--mode", choices=["quick", "stealth", "full", "custom"], default="quick", help="Scan mode")
    parser.add_argument("-p", "--ports", help="Custom port range (only used with --mode custom)")
    parser.add_argument("-o", "--output", default="logs", help="Output directory")

    args = parser.parse_args()

    if not os.path.exists(args.output):
        os.makedirs(args.output)

    run_nmap(args.target, args.ports, args.output, args.mode)

if __name__ == "__main__":
    main()
