#!/usr/bin/env python3

import base64, binascii, urllib.parse, codecs, gzip
import argparse, logging, os
from io import BytesIO

# Setup logging
logging.basicConfig(filename='logs/encode.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def encode_base64(s):
    return base64.b64encode(s.encode()).decode()

def encode_hex(s):
    return binascii.hexlify(s.encode()).decode()

def encode_url(s):
    return urllib.parse.quote(s)

def encode_rot13(s):
    return codecs.encode(s, 'rot_13')

def encode_gzip_base64(s):
    out = BytesIO()
    with gzip.GzipFile(fileobj=out, mode='wb') as f:
        f.write(s.encode())
    return base64.b64encode(out.getvalue()).decode()

encoders = {
    'base64': encode_base64,
    'hex': encode_hex,
    'url': encode_url,
    'rot13': encode_rot13,
    'gzip+base64': encode_gzip_base64
}

def apply_chain(text, methods):
    result = text
    for method in methods:
        if method in encoders:
            logging.info(f"Applying: {method}")
            result = encoders[method](result)
        else:
            logging.warning(f"Unknown encoder: {method}")
    return result

def main():
    parser = argparse.ArgumentParser(description='auto-encode: Chain-based payload encoder')
    parser.add_argument('-s', '--string', help='Input string')
    parser.add_argument('-f', '--file', help='Input file')
    parser.add_argument('-e', '--encoders', nargs='+', required=True, help='Encoding sequence (e.g. base64 hex url)')
    args = parser.parse_args()

    if args.string:
        data = args.string.strip()
    elif args.file:
        with open(args.file, 'r') as f:
            data = f.read().strip()
    else:
        print("[-] Provide input with -s or -f.")
        return

    encoded = apply_chain(data, args.encoders)
    print("[+] Encoded result:\n", encoded)

    with open('findings.md', 'a') as out:
        out.write(f"\n---\nOriginal:\n{data}\nEncoders: {args.encoders}\nEncoded:\n{encoded}\n")

if __name__ == "__main__":
    main()
