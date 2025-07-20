import yaml
from modules.scrapers import github_search, twitter_search, pastebin_search

def collect_entities(input_value, config_path):
    with open(config_path) as f:
        config = yaml.safe_load(f)

    entities = {"input": input_value, "github": [], "twitter": [], "pastebin": []}

    if config["sources"].get("github"):
        entities["github"] = github_search(input_value)
    if not entities["github"]:
        entities["github"] = [f"github.com/fake_{input_value}"]

    if config["sources"].get("twitter"):
        entities["twitter"] = twitter_search(input_value)
    if not entities["twitter"]:
        entities["twitter"] = [f"twitter.com/fake_{input_value}"]

    if config["sources"].get("pastebin"):
        entities["pastebin"] = pastebin_search(input_value)
    if not entities["pastebin"]:
        entities["pastebin"] = [f"pastebin.com/u/fake_{input_value}"]

    return entities
