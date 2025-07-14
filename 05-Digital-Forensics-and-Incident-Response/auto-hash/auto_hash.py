import os
import hashlib
import argparse
from datetime import datetime

def calculate_hashes(file_path):
    hashes = {"MD5": None, "SHA1": None, "SHA256": None}
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            hashes["MD5"] = hashlib.md5(data).hexdigest()
            hashes["SHA1"] = hashlib.sha1(data).hexdigest()
            hashes["SHA256"] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        hashes["error"] = str(e)
    return hashes

def scan_directory(directory, output_file):
    results = []
    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            hashes = calculate_hashes(file_path)
            results.append((file_path, hashes))

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, "w") as f:
        f.write(f"# Auto-Hash Scan - {timestamp}\n\n")
        for file_path, hashes in results:
            f.write(f"{file_path}\n")
            for algo, value in hashes.items():
                f.write(f"  {algo}: {value}\n")
            f.write("\n")

    print(f"[+] Hashing complete. Results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auto-Hash: Generate hashes for files in a directory")
    parser.add_argument("-t", "--target", required=True, help="Path to file or folder to hash")
    parser.add_argument("-o", "--output", default="logs/hash_results.log", help="Output log file")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print("[-] Target path does not exist.")
        exit(1)

    scan_directory(args.target, args.output)
