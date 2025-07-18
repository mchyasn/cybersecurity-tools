#!/usr/bin/env python3
import argparse
import logging
from pathlib import Path
from scapy.all import sniff, ARP, ICMP, IP
from datetime import datetime
import yaml

alert_log = Path("logs/alerts.txt")
alert_log.parent.mkdir(parents=True, exist_ok=True)

alert_cache = set()

def validate_config(config_path: str) -> dict:
    if not Path(config_path).exists():
        logging.error(f"Config file {config_path} missing")
        return {}
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Config parsing failed: {e}")
        return {}

def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("logs/netdeflect.log"),
            logging.StreamHandler()
        ]
    )

def log_alert(message: str):
    if message in alert_cache:
        return
    alert_cache.add(message)
    logging.warning(message)
    timestamp = datetime.utcnow().isoformat()
    with open(alert_log, "a") as f:
        f.write(f"{timestamp} {message}\n")

def detect_arp(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        dst_ip = packet[ARP].pdst
        dst_mac = packet[ARP].hwdst
        if src_ip == dst_ip:
            return
        msg = f"Suspicious ARP reply: {src_ip} is-at {src_mac} (to {dst_ip})"
        log_alert(msg)

def detect_icmp(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 5:
        msg = f"ICMP Redirect Detected: {packet[IP].src} is redirecting traffic"
        log_alert(msg)

def detect_gateway_conflict(packet, trusted_gateway_ip):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        if packet[ARP].psrc == trusted_gateway_ip:
            msg = f"Gateway Conflict: ARP claim for {trusted_gateway_ip} from {packet[ARP].hwsrc}"
            log_alert(msg)

def packet_handler(packet, gateway_ip):
    detect_arp(packet)
    detect_icmp(packet)
    detect_gateway_conflict(packet, gateway_ip)

def start_sniffing(interface: str, gateway_ip: str):
    sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, gateway_ip), store=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetDeflect - Passive L2/L3 Threat Detection")
    parser.add_argument("-c", "--config", required=True, help="Config file path")
    parser.add_argument("-i", "--interface", required=True, help="Interface to monitor (e.g., eth0)")
    args = parser.parse_args()

    setup_logger()

    config = validate_config(args.config)
    if not config:
        exit(1)

    gateway_ip = config.get("trusted_gateway_ip", "192.168.1.1")
    logging.info(f"Monitoring started on interface: {args.interface}")
    logging.info(f"Trusted gateway set to: {gateway_ip}")
    start_sniffing(args.interface, gateway_ip)
