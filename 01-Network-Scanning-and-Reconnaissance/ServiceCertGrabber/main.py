#!/usr/bin/env python3
"""
ServiceCertGrabber - TLS Fingerprinter
=====================================
Grabs SSL/TLS certificates from target IP:port, extracts chain info,
computes JA3 fingerprint, and outputs structured JSON for threat intel.

Output is saved to scans/ with timestamped filename.
"""

import argparse
import ssl
import socket
import hashlib
import json
import logging
from pathlib import Path
from datetime import datetime, timezone

# Directories
log_path = Path("logs/debug.log")
log_path.parent.mkdir(parents=True, exist_ok=True)
scans_dir = Path("scans")
scans_dir.mkdir(parents=True, exist_ok=True)
configs_dir = Path("configs")
configs_dir.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    filename=log_path,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def get_cert_chain(host: str, port: int):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                certs = ssock.getpeercert(binary_form=True)
                der = ssock.getpeercert(True)
                chain = ssock.getpeercert()
                return der, chain
    except Exception as e:
        logging.error(f"Failed to retrieve certs from {host}:{port} - {e}")
        raise

def compute_ja3(ssl_sock):
    try:
        # This is a placeholder — JA3 requires parsing Client Hello.
        # Use tls-fingerprint libs for real JA3, or fill from pcap.
        return "JA3_PLACEHOLDER"
    except Exception as e:
        logging.warning(f"JA3 computation failed: {e}")
        return "UNKNOWN"

def save_output(host: str, port: int, data: dict):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = scans_dir / f"certgrab_{host}_{port}_{ts}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logging.info(f"Saved output to {out_file}")
    print(f"[+] Scan complete. Results saved to {out_file}")

def run_scan(host: str, port: int):
    logging.info(f"Scanning {host}:{port}")
    try:
        der, chain = get_cert_chain(host, port)
        ja3 = compute_ja3(None)

        result = {
            "target": f"{host}:{port}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ja3": ja3,
            "cert_info": {
                "subject": chain.get("subject", []),
                "issuer": chain.get("issuer", []),
                "notBefore": chain.get("notBefore", ""),
                "notAfter": chain.get("notAfter", "")
            }
        }

        logging.debug(f"Cert chain: {result}")
        save_output(host, port, result)

    except Exception as e:
        logging.error(f"Unhandled error during scan: {e}")
        print(f"[!] Scan failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS Cert & JA3 Fingerprinter")
    parser.add_argument("host", help="Target domain or IP")
    parser.add_argument("--port", type=int, default=443, help="TLS port (default: 443)")
    args = parser.parse_args()

    run_scan(args.host, args.port)
