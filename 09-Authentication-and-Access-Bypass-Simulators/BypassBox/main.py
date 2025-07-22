import yaml
from colorama import init, Fore
from modules import none_alg, alg_confusion, expired_replay, session_fixation

init(autoreset=True)

def main():
    print(Fore.GREEN + "[+] BypassBox - Web Auth Bypass Simulator")

    with open("config/config.yml") as f:
        config = yaml.safe_load(f)

    while True:
        print(Fore.BLUE + "\n(1) JWT None Algorithm Bypass")
        print("(2) JWT Algorithm Confusion (RS256 -> HS256)")
        print("(3) Expired Token Replay")
        print("(4) Cookie Injection / Session Fixation")
        print("(5) Exit")
        choice = input("> ").strip()

        if choice == "1":
            none_alg.craft_none_alg_bypass(config["jwt_token"])
        elif choice == "2":
            fake_secret = input("Fake shared secret (e.g. test): ").strip()
            alg_confusion.confuse_algorithm(config["jwt_token"], fake_secret)
        elif choice == "3":
            expired_replay.replay_expired_token(config["target_url"], config["jwt_token"])
        elif choice == "4":
            value = input("Crafted cookie value: ").strip()
            session_fixation.inject_cookie(config["target_url"], config["cookie_name"], value)
        elif choice == "5":
            break
        else:
            print(Fore.RED + "Invalid choice.")

if __name__ == "__main__":
    main()
