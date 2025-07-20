from PIL import Image

def encode_payload_to_image(payload, out_path="output/payload.png"):
    img = Image.new("RGB", (300, 300), color="white")
    bin_payload = ''.join(format(ord(i), '08b') for i in payload) + '00000000'
    pixels = img.load()
    idx = 0

    for y in range(img.height):
        for x in range(img.width):
            if idx >= len(bin_payload):
                img.save(out_path)
                return out_path
            r, g, b = pixels[x, y]
            r = (r & ~1) | int(bin_payload[idx])
            pixels[x, y] = (r, g, b)
            idx += 1
    img.save(out_path)
    return out_path

def extract_payload_from_image(path):
    img = Image.open(path)
    pixels = img.load()
    bits = []
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            bits.append(str(r & 1))
    chars = [chr(int(''.join(bits[i:i+8]), 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars).split('\x00')[0]
