#!/bin/bash
echo "[+] Setting up auto-decoder environment..."

mkdir -p logs examples

touch logs/decode.log
touch findings.md

chmod +x auto_decoder.py

echo "[+] Setup complete. Use ./auto_decoder.py -h to get started."
