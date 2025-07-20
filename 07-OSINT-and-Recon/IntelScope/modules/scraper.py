import requests
from bs4 import BeautifulSoup
import yaml

def scrape_company_profile(company, config_path):
    with open(config_path) as f:
        config = yaml.safe_load(f)

    data = {"company": company, "linkedin": [], "crunchbase": []}

    if config["sources"].get("linkedin_scrape"):
        url = f"https://www.bing.com/search?q=site:linkedin.com/in+%22{company}%22"
        try:
            r = requests.get(url)
            soup = BeautifulSoup(r.text, "html.parser")
            links = [a.text for a in soup.find_all("a") if "linkedin.com/in" in a.get("href", "")]
            data["linkedin"] = links[:10]
        except:
            pass

    if config["sources"].get("crunchbase_scrape"):
        # Simulated Crunchbase scraping
        data["crunchbase"] = [f"{company} - Sample Exec 1", f"{company} - Sample Exec 2"]

    return data
