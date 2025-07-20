import os, random

def mutate_payload(payload):
    xor_key = random.randint(1, 255)
    mutated = bytes([b ^ xor_key for b in payload])
    return bytes([xor_key]) + mutated
