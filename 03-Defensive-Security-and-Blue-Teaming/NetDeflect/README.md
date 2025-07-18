# NetDeflect

## Description

NetDeflect is a passive L2/L3 network defense tool that detects suspicious activity such as ARP spoofing, ICMP redirects, and gateway MAC conflicts. It is designed for defensive teams to monitor local network segments for signs of MITM activity or rogue devices. The tool leverages raw packet inspection via Scapy and uses configurable settings to adapt to different network environments.

## Features

* ARP spoofing detection via unsolicited ARP replies
* ICMP redirect detection (type 5)
* Gateway impersonation conflict detection using config-defined trusted gateway IP
* Real-time alert logging and deduplication

## Installation

```bash
git clone https://github.com/yourrepo/NetDeflect.git && pip install -r requirements.txt  
```

## Usage

```bash
sudo python3 src/main.py --config configs/config.yaml --interface eth0  
```

## Configuration

See `configs/config.yaml` for settings.

## Screenshots

![Network Traffic Deflection Tool](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/03-Defensive-Security-and-Blue-Teaming/NetDeflect/screenshots/0.png)

## License

MIT

## Disclaimer

For authorized testing only.

## Author

mchyasn
