import unittest
from modules.controller import run_analysis

class TestController(unittest.TestCase):
    def test_run_analysis_invalid_path(self):
        config = {"run_volatility": False, "run_yara": False}
        result = run_analysis("nonexistent.raw", config, None)
        self.assertIsNone(result)
