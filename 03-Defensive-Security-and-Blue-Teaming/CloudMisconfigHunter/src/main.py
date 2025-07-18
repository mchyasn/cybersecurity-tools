#!/usr/bin/env python3
import argparse
import logging
import yaml
import boto3
import requests
from pathlib import Path
from datetime import datetime

def validate_config(config_path: str) -> dict:
    if not Path(config_path).exists():
        logging.error(f"Config file {config_path} missing.")
        return {}
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Failed to parse config file: {e}")
        return {}

def write_alert(cloud: str, message: str):
    ts = datetime.utcnow().isoformat()
    out = f"[{cloud.upper()}][{ts}] {message}"
    logging.warning(out)
    with open("logs/alerts.txt", "a") as f:
        f.write(out + "\n")

def scan_aws(config: dict):
    logging.info("🔍 Starting AWS misconfiguration scan...")

    # Example 1: Check for public S3 bucket
    try:
        s3 = boto3.client("s3")
        buckets = s3.list_buckets()
        for bucket in buckets.get("Buckets", []):
            name = bucket["Name"]
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                if "AllUsers" in str(grant):
                    write_alert("aws", f"S3 Bucket '{name}' has public read permissions!")
    except Exception as e:
        write_alert("aws", f"S3 scan error: {e}")

    # Example 2: Check IAM credentials exposure
    try:
        iam = boto3.client("iam")
        users = iam.list_users()
        if len(users.get("Users", [])) > 50:
            write_alert("aws", f"High number of IAM users detected: {len(users['Users'])}")
    except Exception as e:
        write_alert("aws", f"IAM scan error: {e}")

def scan_gcp(config: dict):
    logging.info("🔍 Starting GCP misconfiguration scan...")

    # Example 1: Check for public Google Storage bucket
    sample_url = "https://storage.googleapis.com/" + config.get("gcp_bucket_check", "my-public-bucket")
    try:
        r = requests.get(sample_url)
        if r.status_code == 200 and "AccessDenied" not in r.text:
            write_alert("gcp", f"Bucket {sample_url} appears publicly accessible.")
    except Exception as e:
        write_alert("gcp", f"GCS scan error: {e}")

    # Example 2: Check for open API endpoint
    try:
        test_api = config.get("gcp_api_url", "https://my-gcp-app.appspot.com/api/test")
        r = requests.get(test_api)
        if r.status_code == 200:
            write_alert("gcp", f"GCP API endpoint {test_api} responded with 200 OK.")
    except Exception as e:
        write_alert("gcp", f"GCP API scan error: {e}")

def scan_azure(config: dict):
    logging.info("🔍 Starting Azure misconfiguration scan...")

    # Example 1: Azure Blob storage open access check
    container_url = config.get("azure_blob_url", "https://myazure.blob.core.windows.net/public/")
    try:
        r = requests.get(container_url)
        if r.status_code == 200:
            write_alert("azure", f"Azure Blob container appears public: {container_url}")
    except Exception as e:
        write_alert("azure", f"Azure blob scan error: {e}")

    # Example 2: Open Azure API check
    try:
        test_api = config.get("azure_api_url", "https://myapp.azurewebsites.net/api/info")
        r = requests.get(test_api)
        if r.status_code == 200:
            write_alert("azure", f"Azure API endpoint is open: {test_api}")
    except Exception as e:
        write_alert("azure", f"Azure API scan error: {e}")

def dispatch_scan(target: str, config: dict):
    if target == "aws":
        scan_aws(config)
    elif target == "gcp":
        scan_gcp(config)
    elif target == "azure":
        scan_azure(config)
    else:
        logging.error(f"Unknown cloud target: {target}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudMisconfigHunter - Multi-cloud Misconfiguration Scanner")
    parser.add_argument("-c", "--config", required=True, help="Path to config.yaml")
    parser.add_argument("-t", "--target", required=True, choices=["aws", "gcp", "azure"], help="Cloud target")
    args = parser.parse_args()

    Path("logs").mkdir(exist_ok=True)
    log_path = f"logs/{args.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler()
        ]
    )

    config = validate_config(args.config)
    if not config:
        exit(1)

    dispatch_scan(args.target, config)
