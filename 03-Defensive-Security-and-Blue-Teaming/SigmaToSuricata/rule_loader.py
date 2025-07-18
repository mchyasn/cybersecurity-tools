import os
import yaml

def load_sigma_rules(folder_path):
    rules = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            full_path = os.path.join(folder_path, filename)
            try:
                with open(full_path, "r") as f:
                    rule = yaml.safe_load(f)
                    rules.append(rule)
            except Exception as e:
                print(f"[!] Error loading {filename}: {e}")
    return rules
