import yaml

def load_targets(path):
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    return config["targets"]

