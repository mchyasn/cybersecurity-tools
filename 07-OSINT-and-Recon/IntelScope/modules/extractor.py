import re, yaml

def extract_employees(data):
    employees = []
    names = []

    for link in data.get("linkedin", []):
        name = link.split("/")[-1].replace("-", " ").title()
        names.append(name)

    for profile in data.get("crunchbase", []):
        name = profile.split("-")[-1].strip()
        names.append(name)

    with open("configs/config.yaml") as f:
        cfg = yaml.safe_load(f)

    domain = cfg["enrichment"]["default_domain"]
    fmt = cfg["enrichment"]["email_format"]

    for full in names:
        parts = full.lower().split()
        if len(parts) >= 2:
            email = fmt.format(first=parts[0], last=parts[-1], domain=domain)
            employees.append({"name": full, "email": email})
    return employees
