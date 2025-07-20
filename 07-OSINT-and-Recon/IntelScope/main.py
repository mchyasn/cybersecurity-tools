import argparse
from modules.scraper import scrape_company_profile
from modules.extractor import extract_employees
from modules.writer import save_csv

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IntelScope - Company & Employee Recon Engine")
    parser.add_argument("-c", "--company", required=True, help="Company name or domain")
    parser.add_argument("-o", "--output", default="output/employees.csv", help="CSV output path")
    parser.add_argument("--config", default="configs/config.yaml", help="YAML config file")
    args = parser.parse_args()

    print(f"[+] Collecting data for: {args.company}")
    company_data = scrape_company_profile(args.company, args.config)
    print(f"[+] Scraped LinkedIn: {company_data.get('linkedin', [])}")
    print(f"[+] Scraped Crunchbase: {company_data.get('crunchbase', [])}")

    employees = extract_employees(company_data)
    print(f"[+] Parsed {len(employees)} employees")

    save_csv(employees, args.output)
    print(f"[+] Saved to: {args.output}")
