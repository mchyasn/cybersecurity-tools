#!/usr/bin/env python3
"""
TimelineWeaver - Artifact Timeline Correlator

Author: mchyasn
"""

import argparse
from rich.console import Console
from config.loader import load_config
from modules.controller import run_timeline_build

console = Console()

def main():
    parser = argparse.ArgumentParser(description="TimelineWeaver - Forensic Artifact Correlator")
    parser.add_argument("input_dir", help="Path to folder containing extracted forensic artifacts")
    parser.add_argument("--config", default="config/weaver.yml", help="Path to YAML config")
    parser.add_argument("--output", default="timelines/output.csv", help="Path to output timeline file")
    args = parser.parse_args()

    config = load_config(args.config)
    run_timeline_build(args.input_dir, args.output, config)

if __name__ == "__main__":
    main()
