import json

def load_field_mappings(mapping_file):
    try:
        with open(mapping_file, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load field mappings: {e}")
        return {}
