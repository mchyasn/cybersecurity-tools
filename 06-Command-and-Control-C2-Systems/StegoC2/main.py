import argparse
from server.operator import start_operator

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="StegoC2: C2 over Steganography")
    parser.add_argument("--config", default="configs/config.yaml", help="Path to config file")
    args = parser.parse_args()

    start_operator(args.config)
