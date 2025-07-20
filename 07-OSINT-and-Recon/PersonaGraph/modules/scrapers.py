import requests
from bs4 import BeautifulSoup

def github_search(user):
    try:
        r = requests.get(f"https://github.com/{user}")
        return [f"github.com/{user}"] if r.status_code == 200 else []
    except: return []

def twitter_search(user):
    try:
        r = requests.get(f"https://nitter.net/{user}")
        return [f"twitter.com/{user}"] if "profile" in r.text.lower() else []
    except: return []

def pastebin_search(keyword):
    try:
        r = requests.get(f"https://pastebin.com/u/{keyword}")
        return [f"pastebin.com/u/{keyword}"] if "Pastebin" in r.text else []
    except: return []
