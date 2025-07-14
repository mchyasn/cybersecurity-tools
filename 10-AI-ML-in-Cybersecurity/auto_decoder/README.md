# auto-decoder

auto-decoder is a command-line Python tool that automatically detects and decodes encoded strings. It supports single or multi-layer decoding of formats such as base64, hex, URL encoding, ROT13, zlib+base64, and JWT.

## Features
.......
- Automatically detects the encoding format
- Supports deep decoding of multiple nested layers
- Accepts input from a file or string
- Logs all decoding steps to `logs/decode.log`
- Saves decoded outputs to `findings.md`
- Handles JWT tokens by decoding header and payload

## Usage

Run the tool using:

    python3 auto_decoder.py -s "<encoded_string>"
    python3 auto_decoder.py -f examples/encoded.txt
    python3 auto_decoder.py -f examples/deep_encoded.txt --deep

## Setup

    chmod +x setup.sh
    ./setup.sh

This will:

- Create the required folder structure
- Initialize `logs/decode.log` and `findings.md`
- Make `auto_decoder.py` executable

## Example

Create a double-encoded base64 string:

    echo "VEdGNVpYSmxaQ0J6WldOeVpYUT0=" > examples/deep_encoded.txt

Run the decoder:

    python3 auto_decoder.py -f examples/deep_encoded.txt --deep

Expected output:

    [+] Decoded 2 layers:

    Layer 1 (base64):
    TG5lZXJlZCBzZWNyZXQ=

    Layer 2 (base64):
    Layered secret

## Project Structure

    auto-decoder/
    ├── auto_decoder.py         # Main decoding logic
    ├── setup.sh                # Environment setup script
    ├── README.md               # Documentation
    ├── findings.md             # Decoding results output
    ├── logs/
    │   └── decode.log          # Tool execution log
    └── examples/
        └── encoded.txt         # Example input file

## Requirements

- Python 3.6 or higher
- No external dependencies required
  
## screenshot
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/auto_decoder/screenshots/0.png)
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/auto_decoder/screenshots/1.png)
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/auto_decoder/screenshots/11.png)
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/auto_decoder/screenshots/2.png)

## License

MIT License

## Contribution

Contributions are welcome. Suggestions, bug fixes, and improvements can be submitted via pull requests.


