#!/usr/bin/env python3

import base64, binascii, urllib.parse, codecs, zlib, json
import argparse, logging, os

# Setup logging
logging.basicConfig(filename='logs/decode.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def try_base64(s):
    try:
        decoded = base64.b64decode(s).decode('utf-8')
        return decoded, 'base64'
    except Exception:
        return None, None

def try_hex(s):
    try:
        decoded = bytes.fromhex(s).decode('utf-8')
        return decoded, 'hex'
    except Exception:
        return None, None

def try_url(s):
    try:
        return urllib.parse.unquote(s), 'url'
    except Exception:
        return None, None

def try_rot13(s):
    try:
        return codecs.decode(s, 'rot_13'), 'rot13'
    except Exception:
        return None, None

def try_zlib_base64(s):
    try:
        decoded = zlib.decompress(base64.b64decode(s)).decode('utf-8')
        return decoded, 'zlib+base64'
    except Exception:
        return None, None

def try_jwt(s):
    try:
        parts = s.split('.')
        if len(parts) != 3:
            return None, None
        header = base64.urlsafe_b64decode(parts[0] + "===").decode('utf-8')
        payload = base64.urlsafe_b64decode(parts[1] + "===").decode('utf-8')
        return f"JWT Header:\n{header}\n\nJWT Payload:\n{payload}", 'jwt'
    except Exception:
        return None, None

def decode_input(content):
    methods = [try_jwt, try_base64, try_hex, try_url, try_rot13, try_zlib_base64]
    for method in methods:
        method_name = method.__name__.replace('try_', '')
        logging.info(f"Trying method: {method_name}")
        result, name = method(content)
        if result:
            logging.info(f"Success: Decoded using {name}")
            logging.info(f"Output: {result[:100]}")  # Log first 100 chars
            return result, name
    logging.info("No decoding method succeeded.")
    return None, None

def deep_decode(content, max_depth=5):
    history = []
    current = content
    for i in range(max_depth):
        logging.info(f"[Layer {i+1}] Attempting decode...")
        result, method = decode_input(current)
        if result:
            logging.info(f"[Layer {i+1}] Success: {method}")
            history.append((method, result))
            current = result
        else:
            logging.info(f"[Layer {i+1}] Failed to decode. Stopping.")
            break
    return history


def main():
    parser = argparse.ArgumentParser(description='auto-decoder: Automatically decode strings')
    parser.add_argument('-s', '--string', help='Input string')
    parser.add_argument('-f', '--file', help='Input file')
    parser.add_argument('--deep', action='store_true', help='Enable deep multi-layer decoding')

    args = parser.parse_args()

    if args.string:
        content = args.string.strip()
    elif args.file:
        with open(args.file, 'r') as f:
            content = f.read().strip()
    else:
        print("[-] Please provide input with -s or -f.")
        return

    if args.deep:
        layers = deep_decode(content)
        if layers:
            print(f"[+] Decoded {len(layers)} layers:\n")
            with open('findings.md', 'a') as out:
                out.write("\n---\n[Deep Decode Result]\nOriginal Input:\n" + content + "\n")
                for i, (method, result) in enumerate(layers, 1):
                    print(f"Layer {i} ({method}):\n{result}\n")
                    out.write(f"\nLayer {i} - {method}:\n{result}\n")
        else:
            print("[-] Could not decode any layers.")
    else:
        decoded, method = decode_input(content)
        if decoded:
            print(f"[+] Decoded using {method}:\n{decoded}")
            with open('findings.md', 'a') as out:
                out.write(f"\n---\nInput:\n{content}\nMethod: {method}\nDecoded:\n{decoded}\n")
        else:
            print("[-] Could not decode input.")

if __name__ == '__main__':
    main()
