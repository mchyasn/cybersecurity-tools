#!/usr/bin/env python3
"""
ArtifactScope - Cross-Platform Artifact Extractor

Author: mchyasn
"""

import argparse
from rich.console import Console
from config.loader import load_config
from modules.extractor_core import run_extraction

console = Console()

def main():
    parser = argparse.ArgumentParser(description="ArtifactScope - DFIR Artifact Extractor")
    parser.add_argument("mode", choices=["triage", "bulk"], help="Run mode: triage (live) or bulk (offline)")
    parser.add_argument("path", help="Target root path or image mount")
    parser.add_argument("--config", default="config/scope.yml", help="YAML config for enabled modules")
    args = parser.parse_args()

    config = load_config(args.config)
    run_extraction(args.mode, args.path, config)

if __name__ == "__main__":
    main()
