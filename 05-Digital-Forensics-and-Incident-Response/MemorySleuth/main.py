#!/usr/bin/env python3
"""
MemorySleuth - Memory Forensics Framework (Live & Dead Memory)

Author: mchyasn
"""

import argparse
from rich.console import Console
from modules.controller import run_analysis
from config.loader import load_config

console = Console()

def main():
    parser = argparse.ArgumentParser(description="MemorySleuth - RAM Forensics Tool")
    parser.add_argument("dump", help="Path to memory dump")
    parser.add_argument("--profile", help="Volatility3 profile", default=None)
    parser.add_argument("--config", help="Path to YAML config", default="config/sleuth.yml")
    args = parser.parse_args()

    config = load_config(args.config)
    run_analysis(args.dump, config, args.profile)

if __name__ == "__main__":
    main()
