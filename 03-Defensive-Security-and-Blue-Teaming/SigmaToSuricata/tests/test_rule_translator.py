import unittest
from rule_translator import translate_sigma_to_suricata

class TestRuleTranslator(unittest.TestCase):
    def test_translate_simple_rule(self):
        rule = {
            "title": "Test Alert",
            "id": "1234567",
            "detection": {
                "sel": {
                    "user_agent": "malware"
                },
                "condition": "sel"
            }
        }
        mappings = {"user_agent": "http_user_agent"}
        result = translate_sigma_to_suricata(rule, mappings)
        self.assertIn("http_user_agent content:\"malware\"", result)
        self.assertIn("sid:1234567", result)

if __name__ == '__main__':
    unittest.main()
