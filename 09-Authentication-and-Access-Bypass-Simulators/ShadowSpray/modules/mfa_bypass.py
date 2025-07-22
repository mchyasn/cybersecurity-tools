from colorama import Fore

def detect_and_bypass_mfa(target):
    print(Fore.MAGENTA + f"[*] Checking MFA for {target[\"name\"]}")
    if "okta" in target["login_url"]:
        print(Fore.YELLOW + "[~] Simulated weak MFA bypass for Okta.")
    elif "microsoft" in target["login_url"]:
        print(Fore.YELLOW + "[~] Simulated legacy auth for Microsoft 365.")
    else:
        print(Fore.YELLOW + "[~] No MFA detection logic implemented.")

