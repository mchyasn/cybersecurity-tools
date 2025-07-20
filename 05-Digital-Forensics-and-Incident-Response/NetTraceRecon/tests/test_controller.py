import unittest
from modules.controller import run_analysis
import os

class TestNetTraceRecon(unittest.TestCase):
    def test_invalid_pcap_path(self):
        try:
            run_analysis("nonexistent.pcap", "config/netrecon.yml")
        except Exception as e:
            self.assertIn("No such file", str(e))

if __name__ == "__main__":
    unittest.main()
