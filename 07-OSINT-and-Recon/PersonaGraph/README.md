# PersonaGraph


## Description

**PersonaGraph** is a human-centric OSINT mapping tool that builds social graphs from public information tied to usernames, emails, or phone numbers. It collects data from online platforms such as GitHub, Twitter (via Nitter), and Pastebin, then correlates the results into an interactive network graph. Inspired by tools like SpiderFoot and Maltego, PersonaGraph focuses on identity resolution and link analysis in a minimal, visual-first design.

## Features

* Scrapes GitHub, Twitter (via Nitter), and Pastebin
* Accepts username, email, or phone as input
* Outputs interactive HTML-based social graph
* Lightweight and modular (no login or API keys required)
* Useful for recon, threat intelligence, and investigative OSINT

## Installation

```bash
git clone https://github.com/your/repo.git
cd PersonaGraph
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py -i <username|email|phone> -o output/graph.html
```

Example:

```bash
python3 main.py -i johnsmith -o output/graph.html
```

Then open the graph:

```bash
xdg-open output/graph.html  # or: start output/graph.html (Windows)
```

## Configuration

`configs/config.yaml`:

```yaml
sources:
  github: true
  twitter: true
  pastebin: true

keywords:
  context_words: ["cyber", "infosec", "hacker"]
```

* Enable or disable data sources
* Use keywords for future content filtering (e.g., tweets, bios)

## Screenshots

![PersonaGraph](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/07-OSINT-and-Recon/PersonaGraph/screenshots/0.png)
![PersonaGraph](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/07-OSINT-and-Recon/PersonaGraph/screenshots/1.png)

## License

MIT

## Disclaimer

🔥 For educational use only. Do not run without authorization.

## Author

\[mchyasn]
