import unittest
from conflict_resolver import resolve_conflicts

class TestConflictResolver(unittest.TestCase):
    def test_remove_duplicates(self):
        rule = "alert http any any -> any any (msg:\"Test\"; sid:1; rev:1;)"
        rules = [rule, rule, rule]
        unique = resolve_conflicts(rules)
        self.assertEqual(len(unique), 1)

if __name__ == '__main__':
    unittest.main()
