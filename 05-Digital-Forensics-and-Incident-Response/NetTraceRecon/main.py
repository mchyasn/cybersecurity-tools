import argparse
from modules.controller import run_analysis

def main():
    parser = argparse.ArgumentParser(description="NetTraceRecon - Network Forensics Parser")
    parser.add_argument("input", help="PCAP file or 'live' for live capture")
    parser.add_argument("--config", default="config/netrecon.yml", help="Path to config file")
    args = parser.parse_args()
    run_analysis(args.input, args.config)

if __name__ == "__main__":
    main()
