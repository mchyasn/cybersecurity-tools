#!/usr/bin/env python3

import argparse
import yaml
import os
from modules import controller

def main():
    parser = argparse.ArgumentParser(description="FileDNA - Malware Hashing & Similarity Engine")
    parser.add_argument("sample_dir", help="Path to malware samples folder")
    parser.add_argument("--config", default="config/filedna.yml", help="Path to YAML config file")
    args = parser.parse_args()

    if not os.path.exists(args.sample_dir):
        print(f"Sample folder does not exist: {args.sample_dir}")
        return

    config = yaml.safe_load(open(args.config))
    controller.analyze_samples(args.sample_dir, config)

if __name__ == "__main__":
    main()
