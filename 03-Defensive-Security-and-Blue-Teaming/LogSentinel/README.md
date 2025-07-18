# LogSentinel

**Author:** mchyasn
**Category:** Defensive Security / Blue Teaming
**Tool Type:** Real-Time Log Ingestion and Anomaly Detection Engine

---

## Overview

LogSentinel is a real-time log ingestion and anomaly detection engine built for SOC analysts, detection engineers, and defensive security practitioners. It monitors live log files, extracts structured features, applies modular anomaly detection logic, and exports alerts through multiple channels. The tool includes a live web dashboard for real-time visibility.

---

## Features

* Real-time log monitoring via file system events
* Modular log parsing with `--parser` flag (e.g., syslog)
* Pluggable detection models with `--detector` flag
* Alert export options:

  * Console
  * File (`scans/alerts.txt`)
  * Webhook (Slack-compatible)
* Web dashboard (Flask) at `http://localhost:8080`
* Persistent model storage in `models/`
* Clean architecture for future extension

---

## Folder Structure

```
LogSentinel/
├── main.py
├── requirements.txt
├── logs/                 # Input logs to monitor
├── scans/                # Output alert logs
├── models/               # Saved anomaly detection models
├── detectors/
│   ├── __init__.py
│   └── isoforest.py
├── parsers/
│   ├── __init__.py
│   └── syslog.py
├── web/
│   ├── __init__.py
│   └── dashboard.py
├── screenshots/          # (empty, for user screenshots)
```

---

## Installation

```bash
git clone https://github.com/yourrepo/LogSentinel.git
cd LogSentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

Basic example:

```bash
python3 main.py \
  --log logs/test.log \
  --parser syslog \
  --detector isoforest \
  --threshold 0.1
```

With file alerting:

```bash
python3 main.py \
  --log logs/test.log \
  --parser syslog \
  --detector isoforest \
  --threshold 0.1 \
  --alert-to file
```

With Slack/webhook alerting:

```bash
python3 main.py \
  --log logs/test.log \
  --parser syslog \
  --detector isoforest \
  --threshold 0.1 \
  --alert-to webhook \
  --webhook-url https://hooks.slack.com/services/XXXXX
```

---

## Dashboard

After launching the tool, open:

```
http://localhost:8080
```

You will see a live stream of the last 10 logs and the last 10 detected anomalies.
