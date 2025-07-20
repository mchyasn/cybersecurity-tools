import time, requests, random

def beacon_loop(interval, jitter):
    while True:
        delay = interval + (jitter * interval * random.uniform(-1, 1))
        try:
            r = requests.get("http://127.0.0.1:8000/beacon")
            print(f"[+] Beacon sent! Status: {r.status_code}")
        except Exception as e:
            print(f"[!] Beacon failed: {e}")
        time.sleep(delay)

if __name__ == "__main__":
    beacon_loop(10, 0.3)
