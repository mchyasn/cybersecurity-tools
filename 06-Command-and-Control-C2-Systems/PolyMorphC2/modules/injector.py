import ctypes

def inject_shellcode(shellcode, target_proc):
    print(f"[!] Simulated injection into {target_proc} with {len(shellcode)} bytes")
