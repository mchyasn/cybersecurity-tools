import yaml, requests

def send_alert(msg):
    try:
        with open("configs/config.yaml") as f:
            cfg = yaml.safe_load(f)
        webhook = cfg["alerting"].get("slack_webhook")
        if webhook:
            requests.post(webhook, json={"text": msg})
    except:
        pass
