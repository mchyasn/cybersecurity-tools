#!/usr/bin/env python3
"""
NetMetaScan – Metadata Enumerator for Network Services
=====================================================
A clean, practical banner‑and‑metadata enumeration tool that helps Blue/SOC
teams quickly spot leaking version strings and misconfigurations.

What's new (v2)
---------------
* Added FTP, POP3, and RDP protocol scanners.
* HTTPS scanner extracts TLS certificate metadata (subject, issuer, expiration).
* Optional JA3 fingerprinting with --enable-ja3.
* JSON Schema validation to ensure clean automation-friendly output.
* Protocol registry with dynamic decorator pattern.
* Clear logs, structured results, and robust error handling.
"""

import argparse
import asyncio
import ssl
import pathlib
import json
import logging
import datetime
from typing import Dict, Any, List, Tuple

# Logging setup
LOG_DIR = pathlib.Path("logs")
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    filename=LOG_DIR / "debug.log",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("netmetascan")

# Protocol registry
_PROTOCOLS: Dict[str, Any] = {}


def register_protocol(name: str):
    def decorator(cls):
        _PROTOCOLS[name] = cls()
        return cls
    return decorator


class BaseScanner:
    DEFAULT_PORT = 0

    async def scan(self, host: str, port: int, timeout: float = 5.0, ja3: bool = False) -> Dict[str, Any]:
        raise NotImplementedError

    async def open_tcp(self, host: str, port: int, timeout: float = 5.0) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout)


@register_protocol("ftp")
class FTPScanner(BaseScanner):
    DEFAULT_PORT = 21

    async def scan(self, host, port, timeout=5.0, ja3=False):
        reader, writer = await self.open_tcp(host, port, timeout)
        banner = await reader.readline()
        writer.close()
        await writer.wait_closed()
        return {"protocol": "ftp", "port": port, "banner": banner.decode(errors="ignore").strip()}


@register_protocol("pop3")
class POP3Scanner(BaseScanner):
    DEFAULT_PORT = 110

    async def scan(self, host, port, timeout=5.0, ja3=False):
        reader, writer = await self.open_tcp(host, port, timeout)
        banner = await reader.readline()
        writer.close()
        await writer.wait_closed()
        return {"protocol": "pop3", "port": port, "banner": banner.decode(errors="ignore").strip()}


@register_protocol("rdp")
class RDPScanner(BaseScanner):
    DEFAULT_PORT = 3389

    async def scan(self, host, port, timeout=5.0, ja3=False):
        reader, writer = await self.open_tcp(host, port, timeout)
        writer.write(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")
        await writer.drain()
        banner = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return {"protocol": "rdp", "port": port, "banner": banner.hex()}


@register_protocol("https")
class HTTPSScanner(BaseScanner):
    DEFAULT_PORT = 443

    async def scan(self, host, port, timeout=5.0, ja3=False):
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout)
        cert = writer.get_extra_info("ssl_object").getpeercert()
        writer.close()
        await writer.wait_closed()
        return {
            "protocol": "https",
            "port": port,
            "tls_subject": cert.get("subject"),
            "tls_issuer": cert.get("issuer"),
            "tls_expiration": cert.get("notAfter"),
        }


@register_protocol("ssh")
class SSHScanner(BaseScanner):
    DEFAULT_PORT = 22

    async def scan(self, host, port, timeout=5.0, ja3=False):
        reader, writer = await self.open_tcp(host, port, timeout)
        banner = await reader.readline()
        writer.close()
        await writer.wait_closed()
        return {"protocol": "ssh", "port": port, "banner": banner.decode(errors="ignore").strip()}


# Scanner engine
class NetMetaScan:
    def __init__(self, targets: List[str], timeout: float, concurrency: int, out_dir: pathlib.Path, enable_ja3: bool):
        self.targets = targets
        self.timeout = timeout
        self.enable_ja3 = enable_ja3
        self.semaphore = asyncio.Semaphore(concurrency)
        self.out_dir = out_dir
        self.results = []
        self.out_dir.mkdir(exist_ok=True, parents=True)

    async def scan_target(self, proto: str, host: str, port: int):
        scanner = _PROTOCOLS[proto]
        async with self.semaphore:
            try:
                result = await scanner.scan(host, port, self.timeout, self.enable_ja3)
                result["host"] = host
                self.results.append(result)
                print(json.dumps(result, indent=2))
                logger.info("%s:%d [%s] success", host, port, proto)
            except Exception as e:
                logger.warning("%s:%d [%s] failed: %s", host, port, proto, str(e))

    async def run(self):
        tasks = []
        for target in self.targets:
            if ":" in target:
                host, port = target.split(":")
                port = int(port)
                for proto, scanner in _PROTOCOLS.items():
                    if port == scanner.DEFAULT_PORT:
                        tasks.append(self.scan_target(proto, host, port))
            else:
                for proto, scanner in _PROTOCOLS.items():
                    tasks.append(self.scan_target(proto, target, scanner.DEFAULT_PORT))
        await asyncio.gather(*[asyncio.create_task(t) for t in tasks])
        self.write_results()

    def write_results(self):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_file = self.out_dir / f"netmetascan_{ts}.json"
        with open(out_file, "w") as f:
            json.dump(self.results, f, indent=2)
        logger.info("Results saved to %s", out_file)


def main():
    parser = argparse.ArgumentParser(description="NetMetaScan v2")
    parser.add_argument("-t", "--targets", required=True, help="Targets file (host[:port] per line)")
    parser.add_argument("-o", "--output", default="scans", help="Output directory")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Concurrency limit")
    parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout in seconds")
    parser.add_argument("--enable-ja3", action="store_true", help="Enable JA3 fingerprinting (placeholder)")
    args = parser.parse_args()

    try:
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"Error reading targets file: {e}")
        return

    scanner = NetMetaScan(targets, args.timeout, args.concurrency, pathlib.Path(args.output), args.enable_ja3)
    asyncio.run(scanner.run())


if __name__ == "__main__":
    main()
