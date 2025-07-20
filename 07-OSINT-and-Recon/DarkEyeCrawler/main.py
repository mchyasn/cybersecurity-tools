import argparse
from modules.scraper import scan_sources
from modules.alerts import send_alert

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DarkEyeCrawler - Dark Web & Leak Scraper")
    parser.add_argument("-k", "--keywords", required=True, help="Comma-separated keywords to search")
    parser.add_argument("--config", default="configs/config.yaml", help="Path to config YAML")
    args = parser.parse_args()

    results = scan_sources(args.keywords.split(","), args.config)
    for match in results:
        print(f"[!] Leak match: {match}")
        send_alert(match)
