import pefile
import hashlib

def extract_pe_metadata(file_path):
    try:
        pe = pefile.PE(file_path, fast_load=True)
        imphash = pe.get_imphash()
    except Exception:
        imphash = "N/A"

    try:
        with open(file_path, "rb") as f:
            md5 = hashlib.md5(f.read()).hexdigest()
    except Exception:
        md5 = "N/A"

    return md5, imphash
