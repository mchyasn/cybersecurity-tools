#!/usr/bin/env python3
import argparse
import logging
import subprocess
import time
import yaml
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')


def validate_config(config_path: str) -> dict:
    path = Path(config_path)
    if not path.exists():
        logging.error(f"Config file {config_path} missing")
        exit(1)
    with open(path, "r") as f:
        return yaml.safe_load(f)


def get_docker_command():
    try:
        subprocess.run(["docker-compose", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return ["docker-compose"]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ["docker", "compose"]


def deploy_honeypots():
    docker_cmd = get_docker_command()
    logging.info(f"Deploying honeypots using: {' '.join(docker_cmd)} up -d")
    subprocess.run(docker_cmd + ["up", "-d"], check=True)


def destroy_honeypots():
    docker_cmd = get_docker_command()
    logging.info(f"Stopping honeypots using: {' '.join(docker_cmd)} down")
    subprocess.run(docker_cmd + ["down"], check=True)


def monitor_logs_multi(log_dirs, alert_log, keywords):
    alert_log.parent.mkdir(parents=True, exist_ok=True)
    alert_log.touch(exist_ok=True)

    log_files = []
    for directory in log_dirs:
        if Path(directory).exists():
            for file in Path(directory).glob("**/*.log"):
                try:
                    f = open(file, "r")
                    f.seek(0, 2)
                    log_files.append((file, f))
                    logging.info(f"Monitoring {file}")
                except Exception as e:
                    logging.warning(f"Could not open {file}: {e}")

    if not log_files:
        logging.warning("No log files found to monitor.")
        return

    with alert_log.open("a") as alert_out:
        while True:
            for path, f in log_files:
                line = f.readline()
                if not line:
                    continue
                if any(keyword in line for keyword in keywords):
                    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
                    alert = f"[HONEYPOT][{ts}] {line.strip()}"
                    print(f"[ALERT] {alert}")
                    alert_out.write(alert + "\n")
                    alert_out.flush()
            time.sleep(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoHoneynet - Honeypot Deployment Framework")
    parser.add_argument("--config", "-c", required=True, help="Path to config.yaml")
    parser.add_argument("--deploy", action="store_true", help="Deploy honeypot stack")
    parser.add_argument("--destroy", action="store_true", help="Destroy honeypot stack")
    parser.add_argument("--monitor", action="store_true", help="Monitor honeypot log output")

    args = parser.parse_args()
    config = validate_config(args.config)

    log_path = Path(config.get("log_output", {}).get("path", "logs/honeypot_events.log"))

    if args.deploy:
        deploy_honeypots()
    elif args.destroy:
        destroy_honeypots()
    elif args.monitor:
        log_dirs = ["logs/cowrie", "logs/http"]
        keywords = config.get("alert_keywords", ["login", "GET /admin", "exploit", "root"])
        monitor_logs_multi(log_dirs, log_path, keywords)
    else:
        logging.warning("No action specified. Use --deploy, --destroy, or --monitor.")
