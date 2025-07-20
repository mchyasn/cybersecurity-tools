import ssdeep

def compute_hashes(file_path):
    try:
        return ssdeep.hash_from_file(file_path)
    except Exception:
        return "N/A"
