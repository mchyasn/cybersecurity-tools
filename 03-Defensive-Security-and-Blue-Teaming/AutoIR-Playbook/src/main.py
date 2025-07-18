#!/usr/bin/env python3
import argparse
import logging
import subprocess
import shutil
import yaml
from pathlib import Path

def validate_config(config_path: str) -> dict:
    if not Path(config_path).exists():
        logging.error(f"Config file {config_path} missing")
        return {}
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Failed to parse config: {e}")
        return {}

def load_playbook(path: str) -> list:
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Failed to load playbook: {e}")
        return []

def run_shell(cmd: str, dry_run: bool):
    if dry_run:
        logging.info(f"[DRY-RUN] Would execute: {cmd}")
        return
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        logging.info(f"[EXEC] {cmd}\n{result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e.stderr.strip()}")

def copy_file(src: str, dst: str, dry_run: bool):
    if not src or not dst:
        logging.error("Missing src or dst in copy step.")
        return
    if dry_run:
        logging.info(f"[DRY-RUN] Would copy {src} to {dst}")
        return
    try:
        shutil.copy(src, dst)
        logging.info(f"[COPY] {src} -> {dst}")
    except Exception as e:
        logging.error(f"Copy failed: {e}")

def delete_file(path: str, dry_run: bool):
    if not path:
        logging.error("Missing path in delete step.")
        return
    if dry_run:
        logging.info(f"[DRY-RUN] Would delete {path}")
        return
    try:
        Path(path).unlink()
        logging.info(f"[DELETE] {path}")
    except Exception as e:
        logging.error(f"Delete failed: {e}")

def tag_alert(msg: str, dry_run: bool):
    if not msg:
        logging.error("Missing message in tag step.")
        return
    if dry_run:
        logging.info(f"[DRY-RUN] Would tag alert: {msg}")
        return
    logging.info(f"[TAG] {msg}")

def execute_step(step: dict, dry_run: bool):
    action = step.get("action")
    if not action:
        logging.error("Missing 'action' field in step.")
        return

    if action == "shell":
        run_shell(step.get("cmd", ""), dry_run)
    elif action == "copy":
        copy_file(step.get("src", ""), step.get("dst", ""), dry_run)
    elif action == "delete":
        delete_file(step.get("path", ""), dry_run)
    elif action == "tag":
        tag_alert(step.get("message", ""), dry_run)
    else:
        logging.warning(f"Unknown action: {action}")

def run_playbook(playbook: list, dry_run: bool):
    for step in playbook:
        execute_step(step, dry_run)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoIR-Playbook - Incident Response Automation Framework")
    parser.add_argument("-c", "--config", required=True, help="Config file path")
    parser.add_argument("-p", "--playbook", required=True, help="YAML playbook to execute")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without executing")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("logs/autoir.log"),
            logging.StreamHandler()
        ]
    )

    config = validate_config(args.config)
    if not config:
        exit(1)

    # Example use: define default working directory or webhook URL
    logging.info(f"Config loaded: {config}")

    playbook = load_playbook(args.playbook)
    if not playbook:
        logging.error("No playbook steps loaded.")
        exit(1)

    logging.info("Executing playbook...")
    run_playbook(playbook, args.dry_run)
