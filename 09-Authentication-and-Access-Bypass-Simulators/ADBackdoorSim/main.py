#!/usr/bin/env python3
import argparse
import yaml
from modules.sid_history import SIDHistoryInjector
from modules.adminsdholder import AdminSDHolderAbuser
from modules.acl_persistence import ACLPersistor

def main():
    parser = argparse.ArgumentParser(description="ADBackdoorSim - Simulates AD auth backdoors")
    parser.add_argument("--config", required=True, help="Path to YAML config file")
    parser.add_argument("--method", choices=["sid", "sdholder", "acl"], required=True, help="Backdoor method")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    with open(args.config, "r") as f:
        config = yaml.safe_load(f)

    if args.method == "sid":
        injector = SIDHistoryInjector(config, verbose=args.verbose)
        injector.inject()
    elif args.method == "sdholder":
        abuser = AdminSDHolderAbuser(config, verbose=args.verbose)
        abuser.abuse()
    elif args.method == "acl":
        persistor = ACLPersistor(config, verbose=args.verbose)
        persistor.persist()
    else:
        print("[!] Unknown method selected")

if __name__ == "__main__":
    main()
