# Findings - auto-osint

## Test Target: netflix.com

- WHOIS output shows registrar and DNS servers.
- DNS resolution successful. Resolved to IP: 52.94.225.248
- Subdomain enumeration via crt.sh returned over 40 records, including:
  - api.netflix.com
  - jobs.netflix.com
  - cdn.netflix.com

## Test Target: admin@example.com

- Simulated breach check flagged this email in breached list.

## Test Target: 45.33.32.156

- Simulated malicious IP flagged by internal blacklist.
- AbuseIPDB shows historical abuse reports (checked manually).
