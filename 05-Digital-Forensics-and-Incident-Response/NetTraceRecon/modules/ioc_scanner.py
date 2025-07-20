import re

def scan_payload_for_iocs(payload):
    iocs = []
    if b"password=" in payload or b"Authorization:" in payload:
        iocs.append("Credential Leakage")
    if b"suspiciousdomain.com" in payload:
        iocs.append("Suspicious Domain Access")
    return iocs
