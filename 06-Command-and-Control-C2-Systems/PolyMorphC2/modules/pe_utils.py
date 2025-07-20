import pefile

def get_entry_point(path):
    pe = pefile.PE(path)
    return hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
