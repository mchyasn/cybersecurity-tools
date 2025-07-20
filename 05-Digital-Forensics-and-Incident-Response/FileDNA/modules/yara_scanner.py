import yara
import os

def run_yara_scan(file_path, rule_paths):
    matches = []
    for rule in rule_paths:
        if not os.path.exists(rule): continue
        try:
            compiled = yara.compile(filepath=rule)
            results = compiled.match(filepath=file_path)
            if results:
                matches.extend([m.rule for m in results])
        except Exception:
            continue
    return ",".join(set(matches)) if matches else "None"
