import requests

def github_leak_search(keywords):
    matches = []
    for kw in keywords:
        q = f"https://github.com/search?q={kw}"
        try:
            r = requests.get(q)
            if kw.lower() in r.text.lower():
                matches.append(f"Found {kw} on GitHub search")
        except:
            continue
    return matches
