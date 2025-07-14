#!/usr/bin/env python3

import argparse
import os
import socket
import datetime
from pathlib import Path
import requests

# Create logs directory
Path("logs").mkdir(parents=True, exist_ok=True)

def save_log(filename, content):
    path = f"logs/{filename}"
    with open(path, "w") as f:
        f.write(content)
    print(f"[+] Saved: {path}")

def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def whois_lookup(target):
    print(f"[+] Running WHOIS lookup on {target}...")
    try:
        output = os.popen(f"whois {target}").read()
        save_log(f"{target}_whois_{get_timestamp()}.log", output)
    except Exception as e:
        print(f"[-] WHOIS failed: {e}")

def dns_lookup(target):
    print(f"[+] Performing DNS lookup on {target}...")
    try:
        result = socket.gethostbyname_ex(target)
        save_log(f"{target}_dns_{get_timestamp()}.log", str(result))
    except Exception as e:
        print(f"[-] DNS lookup failed: {e}")

def crtsh_enum(domain):
    print(f"[+] Enumerating subdomains via crt.sh for {domain}...")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            subdomains = sorted(set(entry["name_value"] for entry in data))
            result = "\n".join(subdomains)
            save_log(f"{domain}_subdomains_{get_timestamp()}.log", result)
        else:
            print("[-] crt.sh did not return valid data.")
    except Exception as e:
        print(f"[-] Subdomain enumeration failed: {e}")

def email_breach_check(email):
    print(f"[+] Checking if {email} has been in a breach (simulated)...")
    simulated_breached_emails = ["admin@example.com", "test@pwned.com", "user123@yahoo.com"]
    if email.lower() in simulated_breached_emails:
        result = f"ALERT: {email} found in simulated breach list."
    else:
        result = f"SAFE: {email} not found in simulated breach list."
    save_log(f"{email}_breachcheck_{get_timestamp()}.log", result)

def ip_reputation_check(ip):
    print(f"[+] Checking reputation of IP: {ip} (simulated)...")
    bad_ips = ["45.33.32.156", "185.100.87.202", "103.123.85.50"]  # simulated malicious IPs
    if ip in bad_ips:
        result = f"ALERT: {ip} is listed in simulated malicious IP list."
    else:
        result = f"SAFE: {ip} is not found in malicious IP list."
    save_log(f"{ip}_reputation_{get_timestamp()}.log", result)

def main():
    parser = argparse.ArgumentParser(description="auto-osint: Basic OSINT collection tool")
    parser.add_argument("-t", "--target", required=True, help="Target domain, IP or email")
    args = parser.parse_args()

    target = args.target

    whois_lookup(target)
    dns_lookup(target)

    if "@" in target:
        email_breach_check(target)
    else:
        try:
            socket.inet_aton(target)
            ip_reputation_check(target)
        except socket.error:
            crtsh_enum(target)

if __name__ == "__main__":
    main()
