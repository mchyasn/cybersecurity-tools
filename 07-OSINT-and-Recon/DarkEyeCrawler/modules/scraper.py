import requests, yaml
from bs4 import BeautifulSoup
from modules.github import github_leak_search

def scan_sources(keywords, config_path):
    with open(config_path) as f:
        config = yaml.safe_load(f)

    matches = []

    for url in config["sources"].get("paste_clones", []):
        try:
            r = requests.get(url, timeout=10)
            for keyword in keywords:
                if keyword.lower() in r.text.lower():
                    matches.append(f"Found {keyword} on {url}")
        except:
            continue

    if config["sources"].get("github_search", {}).get("enabled"):
        matches += github_leak_search(keywords)

    return matches
