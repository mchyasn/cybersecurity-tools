#!/usr/bin/env python3
"""
SigmaToSuricata - main.py
Author: mchyasn
"""

import argparse
import os
from rule_loader import load_sigma_rules
from rule_translator import translate_sigma_to_suricata
from field_mapper import load_field_mappings
from conflict_resolver import resolve_conflicts
from rich import print

def main():
    parser = argparse.ArgumentParser(description="Sigma to Suricata rule converter")
    parser.add_argument("--input", required=True, help="Path to folder with Sigma rules")
    parser.add_argument("--output", required=True, help="Output file for Suricata rules")
    parser.add_argument("--mapping", required=True, help="Field mapping JSON file")
    args = parser.parse_args()

    # Load field mappings
    if not os.path.exists(args.mapping):
        print(f"[red][ERROR][/red] Mapping file not found: {args.mapping}")
        return
    field_mappings = load_field_mappings(args.mapping)

    # Load Sigma rules
    sigma_rules = load_sigma_rules(args.input)
    if not sigma_rules:
        print(f"[red][ERROR][/red] No Sigma rules found in: {args.input}")
        return

    # Translate and resolve conflicts
    translated_rules = []
    for rule in sigma_rules:
        translated = translate_sigma_to_suricata(rule, field_mappings)
        if translated:
            translated_rules.append(translated)

    final_rules = resolve_conflicts(translated_rules)

    # Write output
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        for rule in final_rules:
            f.write(rule.strip() + "\n\n")

    print(f"[green][+] Translation complete.[/green] Output saved to [bold]{args.output}[/bold]")

if __name__ == "__main__":
    main()
