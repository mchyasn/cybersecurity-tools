import os
import csv
import logging
from modules.peinfo import extract_pe_metadata
from modules.hasher import compute_hashes
from modules.yara_scanner import run_yara_scan

logging.basicConfig(filename="logs/filedna.log", level=logging.INFO, format="[%(asctime)s] %(message)s")

def analyze_samples(sample_dir, config):
    os.makedirs("output", exist_ok=True)
    output_path = "output/filedna_report.csv"

    with open(output_path, "w", newline='') as csvfile:
        fieldnames = ["filename", "md5", "imphash", "ssdeep", "yara_match"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for fname in os.listdir(sample_dir):
            fpath = os.path.join(sample_dir, fname)
            if not os.path.isfile(fpath): continue

            logging.info(f"Analyzing {fname}")
            md5, imphash = extract_pe_metadata(fpath)
            ssdeep_hash = compute_hashes(fpath)
            yara_match = run_yara_scan(fpath, config.get("yara_rules", [])) if config.get("run_yara") else "N/A"

            writer.writerow({
                "filename": fname,
                "md5": md5,
                "imphash": imphash,
                "ssdeep": ssdeep_hash,
                "yara_match": yara_match
            })
