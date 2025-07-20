import requests

def upload_image(file_path, cdn_config):
    if cdn_config["mode"] == "discord":
        headers = {"Authorization": f"Bot {cdn_config['token']}"}
        data = {"payload_json": '{"content":"Image"}'}
        files = {"file": open(file_path, "rb")}
        r = requests.post(
            f"https://discord.com/api/v10/channels/{cdn_config['channel_id']}/messages",
            headers=headers,
            data=data,
            files=files
        )
        if r.status_code == 200:
            return r.json()["attachments"][0]["url"]
        else:
            return "ERROR"
    return "Unsupported CDN"
