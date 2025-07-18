# NetDeflect - Technical Architecture

## Purpose

NetDeflect is a passive L2/L3 threat detection tool that listens for suspicious network activity such as ARP spoofing, ICMP redirects, and gateway impersonation. It is designed to assist blue team operations with live alerting.

---

## Detection Logic

- **ARP Spoofing Detection**
  - Monitors unsolicited ARP replies
  - Flags duplicate IP claims or mismatched MAC responses

- **ICMP Redirect Detection**
  - Listens for ICMP packets with type 5 (redirect)
  - Triggers alerts for potential MITM re-routing

- **Gateway Conflict**
  - Uses a trusted gateway IP from `config.yaml`
  - Flags conflicting MAC address claims for this IP

---

## Configuration File (`configs/config.yaml`)

```yaml
trusted_gateway_ip: "192.168.1.1"
