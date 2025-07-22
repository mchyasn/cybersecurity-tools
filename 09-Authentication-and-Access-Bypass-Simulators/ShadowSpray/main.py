import argparse
import yaml
import os
from modules.sprayer import CredentialSprayer

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/target.yml", help="Target config YAML")
    parser.add_argument("--delay", type=int, default=0, help="Delay between attempts")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--output", default=None, help="Output file to save successful creds")
    parser.add_argument("--proxy-file", default=None, help="Proxy list file")
    parser.add_argument("--user-agents", default=None, help="User-Agent list file")
    args = parser.parse_args()

    # Load config YAML
    with open(args.config, "r") as f:
        targets = yaml.safe_load(f)

    users = []
    passwords = []

    for target in targets:
        users.extend(target.get("usernames", []))
        passwords.extend(target.get("passwords", []))

    sprayer = CredentialSprayer(
        targets=targets,
        users=users,
        passwords=passwords,
        delay=args.delay,
        verbose=args.verbose,
        output_file=args.output,
        proxy_file=args.proxy_file,
        user_agent_file=args.user_agents
    )

    sprayer.spray()

if __name__ == "__main__":
    main()
