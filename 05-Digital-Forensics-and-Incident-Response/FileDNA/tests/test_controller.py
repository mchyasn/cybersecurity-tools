import unittest
import os
import yaml
from modules import controller

class TestFileDNA(unittest.TestCase):
    def test_fake_sample(self):
        os.makedirs("samples", exist_ok=True)
        with open("samples/fake.exe", "wb") as f:
            f.write(b"ThisIsFakeMalware")

        config = yaml.safe_load(open("config/filedna.yml"))
        controller.analyze_samples("samples", config)

        self.assertTrue(os.path.exists(config["output_file"]))
        with open(config["output_file"]) as f:
            data = f.read()
            self.assertIn("DummyMalware", data)

if __name__ == "__main__":
    unittest.main()
