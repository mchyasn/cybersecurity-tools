import argparse
from c2server.server import start_server

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroTraceC2 - Fileless C2 using LOLBins")
    parser.add_argument("--config", default="configs/config.yaml", help="Path to config YAML")
    args = parser.parse_args()
    start_server(args.config)
