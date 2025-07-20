import argparse
from loader.loader import launch_loader

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PolyMorphC2 - Polymorphic C2 Framework")
    parser.add_argument("--config", default="configs/config.yaml", help="Path to config file")
    args = parser.parse_args()
    launch_loader(args.config)
