import unittest
import json
import os
from field_mapper import load_field_mappings

class TestFieldMapper(unittest.TestCase):
    def test_valid_json_mapping(self):
        os.makedirs("mappings", exist_ok=True)
        with open("mappings/sigma_to_suricata.json", "w") as f:
            json.dump({"user_agent": "http_user_agent"}, f)

        mappings = load_field_mappings("mappings/sigma_to_suricata.json")
        self.assertIn("user_agent", mappings)
        self.assertEqual(mappings["user_agent"], "http_user_agent")

if __name__ == '__main__':
    unittest.main()
