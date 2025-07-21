import os
import yaml
from modules import token_utils
from colorama import init, Fore

init(autoreset=True)

def main():
    print(Fore.GREEN + "[+] TokenTrickster - Windows Token Abuse Simulator")
    with open("config/config.yml") as f:
        config = yaml.safe_load(f)

    while True:
        print(Fore.BLUE + "\n(1) List Token Info")
        print("(2) Simulate SYSTEM Impersonation")
        print("(3) Spawn cmd.exe with Current Token")
        print("(4) Exit")
        choice = input("> ").strip()

        if choice == "1":
            token_utils.list_tokens()
        elif choice == "2":
            token_utils.impersonate_system()
        elif choice == "3":
            if config.get("spawn"):
                token_utils.spawn_cmd_as_current_token()
            else:
                print(Fore.RED + "[-] Spawn disabled in config.")
        elif choice == "4":
            break
        else:
            print(Fore.RED + "Invalid option.")

if __name__ == "__main__":
    if os.name != "nt":
        print(Fore.RED + "[-] TokenTrickster must be run on Windows.")
    else:
        main()
