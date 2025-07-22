import requests
from colorama import Fore

def inject_cookie(url, cookie_name, crafted_value):
    try:
        cookies = {cookie_name: crafted_value}
        res = requests.get(url, cookies=cookies, timeout=5)
        print(Fore.YELLOW + f"[*] Sent cookie {cookie_name}={crafted_value}")
        print(Fore.CYAN + f"Status: {res.status_code}, Body: {res.text[:100]}")
    except Exception as e:
        print(Fore.RED + f"[-] Cookie injection failed: {str(e)}")
