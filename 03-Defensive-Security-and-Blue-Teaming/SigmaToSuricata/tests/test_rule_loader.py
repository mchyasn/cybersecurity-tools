import unittest
import os
from rule_loader import load_sigma_rules

class TestRuleLoader(unittest.TestCase):
    def test_load_valid_yaml(self):
        os.makedirs("rules", exist_ok=True)
        with open("rules/test_rule.yml", "w") as f:
            f.write("title: Test\nlogsource:\n  product: test\ndetection:\n  sel:\n    user_agent: test\n  condition: sel")

        rules = load_sigma_rules("rules")
        self.assertGreater(len(rules), 0)
        self.assertEqual(rules[0]["title"], "Test")

if __name__ == '__main__':
    unittest.main()
