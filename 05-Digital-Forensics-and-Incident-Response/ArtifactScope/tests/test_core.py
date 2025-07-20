import unittest
from modules.extractor_core import run_extraction
import os
import pandas as pd

class TestArtifactScope(unittest.TestCase):
    def test_extraction_empty_path(self):
        os.makedirs("test_target", exist_ok=True)
        config = {"extract_browser": True}
        run_extraction("bulk", "test_target", config)
        self.assertTrue(os.path.exists("output/artifactscope.csv"))
        df = pd.read_csv("output/artifactscope.csv")
        self.assertTrue(df.empty)

if __name__ == "__main__":
    unittest.main()
