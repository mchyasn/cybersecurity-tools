from utils import sanitize_sid

def translate_sigma_to_suricata(rule, field_mappings):
    try:
        detection = rule.get("detection", {})
        conditions = detection.get("condition", "")
        translated_parts = []

        for key, val in detection.items():
            if key == "condition":
                continue
            if not isinstance(val, dict):
                continue
            for field, pattern in val.items():
                suri_field = field_mappings.get(field, None)
                if not suri_field:
                    continue
                if isinstance(pattern, str):
                    translated_parts.append(f"{suri_field} content:\"{pattern}\";")

        msg = rule.get("title", "Sigma Rule").replace("\"", "")
        sid = sanitize_sid(rule.get("id", rule.get("logsource", {}).get("product", "1000000")))
        rule_text = f"alert http any any -> any any (msg:\"{msg}\"; {' '.join(translated_parts)} sid:{sid}; rev:1;)"
        return rule_text
    except Exception as e:
        print(f"[!] Failed to translate rule: {e}")
        return None
