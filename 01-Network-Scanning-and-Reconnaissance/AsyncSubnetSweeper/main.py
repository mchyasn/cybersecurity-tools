#!/usr/bin/env python3
"""
AsyncSubnetSweeper – Fast ICMP + TCP Ping Scanner (Protocol‑Compliant Edition)
==========================================================================
A high‑performance asynchronous subnet scanner that is **protocol‑compliant**, reads
its defaults from a validated **configs/config.yaml**, writes results in **JSON or CSV**
and still chains seamlessly into **SmartPortMap** for post‑discovery port scans.

Why this version?
-----------------
* **Protocol compliance** – Raw‑socket ICMP echoes and TCP connect pings on defined port.
* **Config‑first** – Centralise defaults and creds in YAML; cmd‑line flags override.
* **Structured output** – `--output json|csv` for machine‑readable pipelines.
* **SmartPortMap hook** – Discovered hosts → SmartPortMap without temp files.
* **Stealth & rate‑limit** – Jittered delay + token bucket to stay under IDS radar.

"""
from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import os
import random
import socket
import struct
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List

import yaml  # PyYAML
from pydantic import BaseModel, Field, ValidationError

###############################################################################
# Config validation                                                             
###############################################################################
class SweeperConfig(BaseModel):
    icmp_timeout: float = Field(1.0, ge=0.1, le=5.0)
    tcp_timeout: float = Field(0.8, ge=0.1, le=5.0)
    rate: int = Field(500, ge=10, le=10000)
    tcp_ping_port: int = Field(80, ge=1, le=65535)
    stealth: bool = False
    smartport_enabled: bool = True
    smartport_path: str = "./smart_port_map.py"

def load_config(path: Path) -> SweeperConfig:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return SweeperConfig(**raw)
    except (OSError, yaml.YAMLError) as e:
        print(f"[!] Failed to read config {path}: {e}. Using defaults.")
        return SweeperConfig()
    except ValidationError as ve:
        print(f"[!] Invalid config values: {ve}. Using defaults.")
        return SweeperConfig()

###############################################################################
# ICMP helpers                                                                 
###############################################################################
ICMP_ECHO_REQUEST = 8

def checksum(source: bytes) -> int:
    total = sum(struct.unpack("!%dH" % (len(source) // 2), source))
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return ~total & 0xFFFF

async def icmp_ping(host: str, timeout: float) -> bool:
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def _ping():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.settimeout(timeout)
                packet_id = os.getpid() & 0xFFFF
                header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, packet_id, 1)
                payload = b"async-sweeper"
                chck = checksum(header + payload)
                header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chck, packet_id, 1)
                sock.sendto(header + payload, (host, 1))
                sock.recvfrom(1024)
                loop.call_soon_threadsafe(future.set_result, True)
        except Exception:
            loop.call_soon_threadsafe(future.set_result, False)

    await loop.run_in_executor(None, _ping)
    return await future

###############################################################################
# TCP connect ping helper                                                      
###############################################################################
async def tcp_ping(host: str, port: int, timeout: float) -> bool:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, OSError):
        return False

###############################################################################
# Rate limiter                                                                 
###############################################################################
class TokenBucket:
    def __init__(self, rate: int):
        self.rate = rate
        self.tokens = rate
        self.ts = time.perf_counter()

    async def take(self):
        while self.tokens <= 0:
            await asyncio.sleep(0.01)
            self._refill()
        self.tokens -= 1

    def _refill(self):
        now = time.perf_counter()
        delta = now - self.ts
        self.tokens = min(self.rate, self.tokens + delta * self.rate)
        self.ts = now

###############################################################################
# Sweep logic                                                                 
###############################################################################
@dataclass
class HostResult:
    ip: str
    alive: bool
    method: str

async def probe_ip(ip: str, cfg: SweeperConfig, bucket: TokenBucket) -> HostResult:
    await bucket.take()
    if cfg.stealth:
        await asyncio.sleep(random.uniform(0, 0.2))

    if await icmp_ping(ip, cfg.icmp_timeout):
        return HostResult(ip, True, "icmp")
    elif await tcp_ping(ip, cfg.tcp_ping_port, cfg.tcp_timeout):
        return HostResult(ip, True, "tcp")
    else:
        return HostResult(ip, False, "none")

async def sweep_subnet(net: str, cfg: SweeperConfig) -> List[HostResult]:
    network = ipaddress.ip_network(net, strict=False)
    bucket = TokenBucket(cfg.rate)
    tasks = [probe_ip(str(ip), cfg, bucket) for ip in network.hosts()]
    return await asyncio.gather(*tasks)

###############################################################################
# SmartPortMap integration                                                    
###############################################################################
async def run_smart_port_map(live_hosts: List[str], cfg: SweeperConfig):
    if not cfg.smartport_enabled:
        return
    cmd = [sys.executable, cfg.smartport_path, *live_hosts]
    print("[+] Launching SmartPortMap:", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(*cmd)
    await proc.wait()

###############################################################################
# Output serialization                                                        
###############################################################################
def dump_results(results: List[HostResult], fmt: str):
    fmt = fmt.lower()
    cleaned = [asdict(r) for r in results if r.alive]
    if fmt == "json":
        print(json.dumps(cleaned, indent=2))
    elif fmt == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=["ip", "alive", "method"])
        writer.writeheader()
        writer.writerows(cleaned)
    else:
        raise ValueError("Unsupported output format: " + fmt)

###############################################################################
# CLI                                                                         
###############################################################################
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AsyncSubnetSweeper – ICMP/TCP Ping Scanner")
    p.add_argument("subnet", help="Target subnet, e.g. 192.168.1.0/24")
    p.add_argument("--config", default="configs/config.yaml", help="YAML config path")
    p.add_argument("--rate", type=int, help="Override probe rate (pkts/sec)")
    p.add_argument("--stealth", action="store_true", help="Enable jittered delays")
    p.add_argument("--output", default="json", choices=["json", "csv"], help="Output format")
    p.add_argument("--no-smartport", action="store_true", help="Disable SmartPortMap chaining")
    return p.parse_args()

###############################################################################
# Entrypoint                                                                  
###############################################################################
def main():
    args = parse_args()
    cfg = load_config(Path(args.config))

    if args.rate:
        cfg.rate = args.rate
    if args.stealth:
        cfg.stealth = True
    if args.no_smartport:
        cfg.smartport_enabled = False

    results = asyncio.run(sweep_subnet(args.subnet, cfg))
    dump_results(results, args.output)

    live_hosts = [r.ip for r in results if r.alive]
    print(f"[+] {len(live_hosts)} live hosts found out of {len(results)}")

    if live_hosts and cfg.smartport_enabled:
        asyncio.run(run_smart_port_map(live_hosts, cfg))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[!] Aborted by user")
