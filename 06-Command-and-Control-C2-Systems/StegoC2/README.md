# StegoC2

## Description

**StegoC2** is a stealthy Command and Control (C2) framework that embeds payloads and commands into PNG images using LSB steganography. It delivers commands via image upload APIs (e.g., Discord, Imgur), simulating real-world covert communication techniques. This tool allows red teamers to simulate data-in-image covert operations while giving blue teams detection and forensic challenges.

## Features

* Embed commands invisibly into PNG files using LSB encoding
* REST API for queuing and delivering tasks
* Implant (agent) fetches stego images and executes embedded commands
* Supports CDN delivery via Discord Bot or mock APIs
* Modular structure for adding custom payload encoders/uploaders

## Installation

```bash
git clone https://github.com/your/repo.git
cd StegoC2
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

### Start the operator (C2 server):

```bash
python3 main.py --config configs/config.yaml
```

### Add a task via API:

```bash
curl -X POST http://localhost:5000/add_task \
  -H "Content-Type: application/json" \
  -d '{"task": "whoami"}'
```

### Run the implant:

```bash
python3 implant/agent.py
```

## Configuration

`configs/config.yaml`:

```yaml
stego:
  lsb_bit: 1
  max_payload_size: 2048

cdn:
  mode: "discord"  # or "imgur"
  token: "YOUR_DISCORD_BOT_TOKEN"
  channel_id: "DISCORD_CHANNEL_ID"
```

* `lsb_bit`: Number of least significant bits used for encoding
* `mode`: CDN delivery mode (currently supports `discord`)
* `token`: Discord bot token
* `channel_id`: Discord channel to post images

## Screenshots

![Steganographic C2 Server](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/06-Command-and-Control-C2-Systems/StegoC2/screenshots/0.png)
![Steganographic C2 Server](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/06-Command-and-Control-C2-Systems/StegoC2/screenshots/1.png)

## License

MIT

## Disclaimer

🔥 For educational use only. Do not run without authorization.

## Author

\[mchyasn]
