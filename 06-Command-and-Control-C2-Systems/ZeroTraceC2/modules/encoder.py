import base64

def encode_base64(ps_code):
    encoded = base64.b64encode(ps_code.encode("utf-16le")).decode()
    return encoded
