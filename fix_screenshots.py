import os

# Base GitHub raw URL
base_url = "https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main"

# Mapping tool folders to their correct screenshot paths
tool_paths = {
    "auto-scan": [
        "01-Network-Scanning-and-Reconnaissance/auto-scan/screenshots/quick.png",
        "01-Network-Scanning-and-Reconnaissance/auto-scan/screenshots/full.png"
    ],
    "auto-headers": [
        "02-Vulnerability-Scanning-and-Exploitation/auto-headers/screenshots/0.png"
    ],
    "auto-hash": [
        "05-Digital-Forensics-and-Incident-Response/auto-hash/screenshots/0.png"
    ],
    "auto-osint": [
        "07-OSINT-and-Recon/auto-osint/screenshots/tool.png",
        "07-OSINT-and-Recon/auto-osint/screenshots/ip.png",
        "07-OSINT-and-Recon/auto-osint/screenshots/email.png"
    ],
    "autoYara": [
        "08-Malware-Analysis-and-Reverse-Engineering/autoYara/screenshots/0.png"
    ],
    "auto_decoder": [
        "10-AI-ML-in-Cybersecurity/auto_decoder/screenshots/0.png",
        "10-AI-ML-in-Cybersecurity/auto_decoder/screenshots/1.png"
    ],
    "auto-encode": [
        "10-AI-ML-in-Cybersecurity/auto-encode/screenshots/0.png"
    ]
}


def update_readme(tool, screenshots):
    for root, dirs, files in os.walk("."):
        if tool in root and "README.md" in files:
            readme_path = os.path.join(root, "README.md")

            with open(readme_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Remove existing screenshot lines
            new_lines = [line for line in lines if "![Screenshot]" not in line]

            # Add screenshots section
            new_lines.append("\n## Screenshots\n")
            for path in screenshots:
                new_lines.append(f"![Screenshot]({base_url}/{path})\n")

            # Save updated README
            with open(readme_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

            print(f"[✓] Updated: {readme_path}")


# Run it
print("[*] Updating screenshot URLs in all README files...\n")
for tool, paths in tool_paths.items():
    update_readme(tool, paths)
print("\n[✓] All done.")
