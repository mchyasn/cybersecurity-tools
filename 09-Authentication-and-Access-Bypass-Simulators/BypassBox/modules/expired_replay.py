from colorama import Fore
import requests

def replay_expired_token(url, token):
    try:
        headers = {"Authorization": f"Bearer {token}"}
        res = requests.get(url, headers=headers, timeout=5)
        print(Fore.YELLOW + f"[*] Status: {res.status_code}")
        print(Fore.CYAN + f"Response: {res.text[:100]}")
    except Exception as e:
        print(Fore.RED + f"[-] Request failed: {str(e)}")
