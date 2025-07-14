# auto-encode

auto-encode is a command-line tool for chaining multiple encoding formats to obfuscate payloads or test layered encoding techniques. It supports encoding sequences such as base64 → hex → URL, and can process both string and file input.

## Features

- Encode text using:
  - base64
  - hex
  - URL encoding
  - ROT13
  - gzip + base64
- Chain multiple encoders in sequence
- Accept input from a string or file
- Save output and history to findings.md
- Logs encoding steps to logs/encode.log

## Usage

Encode a string:
```bash
python3 auto_encode.py -s "payload123" -e base64 hex url
```

Encode a file:
```bash
python3 auto_encode.py -f examples/input.txt -e base64 rot13
```

## Setup

```bash
chmod +x setup.sh
./setup.sh
```

## Output

Encoded results are:
- Printed to console
- Appended to `findings.md`
- Logged in `logs/encode.log`

## Project Structure

auto-encode/
├── auto_encode.py         # Main encoder tool
├── setup.sh               # Setup script
├── README.md              # Project documentation
├── findings.md            # Output record
├── logs/
│   └── encode.log         # Logs for encoding operations
└── examples/
    └── input.txt          # Sample input file

## Requirements

- Python 3.6+

## License

MIT License
