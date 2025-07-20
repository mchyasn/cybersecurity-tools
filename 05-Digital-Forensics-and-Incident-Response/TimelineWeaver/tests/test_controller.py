import unittest
from modules.controller import run_timeline_build
import os
import pandas as pd

class TestTimelineWeaver(unittest.TestCase):
    def test_empty_evtx_folder(self):
        os.makedirs("test_artifacts/evtx", exist_ok=True)
        config = {"parse_evtx": True}
        run_timeline_build("test_artifacts", "timelines/test.csv", config)
        self.assertTrue(os.path.exists("timelines/test.csv"))
        df = pd.read_csv("timelines/test.csv")
        self.assertTrue(df.empty)

if __name__ == "__main__":
    unittest.main()
