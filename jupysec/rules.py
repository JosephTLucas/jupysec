import subprocess
from pathlib import Path
import itertools
import os
import sqlite3
import json
from jupysec.finding import Finding


class Rules:
    def __init__(self):
        paths = subprocess.run(["jupyter", "--paths"], capture_output=True).stdout
        paths = paths.decode().splitlines()
        paths = [x.lstrip() for x in paths]
        paths.append(
            subprocess.run(["ipython", "locate"], capture_output=True)
            .stdout.decode()
            .rstrip()
        )
        paths = set(filter(lambda x: x not in ["config:", "data:", "runtime:"], paths))
        files = [list(Path(p).rglob("*")) for p in paths]
        files = list(itertools.chain(*files))
        target_files = (
            "jupyter_server_config.py",
            "jupyter_notebook_config.py",
            "ipython_config.py",
            "jupyter_server_config.json",
            "jupyter_notebook_config.json",
        )
        self.files = list(filter(lambda x: x.name.endswith(target_files), files))
        self.servers = servers = (
            subprocess.run(["jupyter", "server", "list"], capture_output=True)
            .stderr.decode()
            .splitlines()[1:]
        )

    def get_findings(self):
        return (
            self.get_not_commented()
            + self.check_ipython_startup()
            + self.check_for_https()
            + self.check_for_token()
            + self.check_for_silent_history()
            + self.check_for_localhost()
        )

    def check_ipython_startup(self):
        category = "Code Execution"
        details = "Files in this startup directory provide code execution when Jupyter is initiated."
        remediation = "Ensure the contents of these files are not malicious.\
        https://ipython.org/ipython-doc/1/config/overview.html#startup-files"
        path = (
            subprocess.run(["ipython", "locate"], capture_output=True)
            .stdout.decode()
            .rstrip()
        )
        files = list(Path(path).rglob("*"))
        startup_files = [os.listdir(f) for f in files if "startup" in f.name]
        startup_files = list(itertools.chain(*startup_files))
        startup_files = list(filter(lambda x: x != "README", startup_files))
        
        return [Finding(category=category, source_doc=f, source_details=details, remedation=remediation) for f in startup_files]

    def get_not_commented(self):
        category = "Nonstandard Configuration"
        details = "Uncommented fields in configuration files may enable nonstandard and potentially malicious/vulnerable functionality."
        remediation = "Ensure these configuration values are intentional."
        findings = list()
        for file in self.files:
            with open(file, "r") as f:
                lines = f.read().splitlines()
            lines = filter(lambda x: len(x) > 0, lines)
            findings.append(list(filter(lambda x: x[0] not in ["#"], lines)))
        findings = list(itertools.chain(*findings))
        try:
            findings.remove('c = get_config()  #noqa')
        except ValueError:
            pass
        try:
            findings.remove('c = get_config()  # noqa')
        except ValueError:
            pass
        return [Finding(category=category, source_text=f, source_details=details, remediation=remediation) for f in findings]


    def check_for_token(self):
        category = "Authorization"
        details = "These servers do not require a token and may allow unauthorized access."
        remediation = "Either enable tokens or ensure you are using password authentication."
        servers = list(filter(lambda x: "token" not in x, self.servers))
        return [Finding(category=category, source_text=f, source_doc="jupyter server list", source_details=details, remediation=remediation) for f in servers]

    def check_for_https(self):
        category = "Encryption"
        details = (
            "These servers do not use HTTPS which could lead to MITM vulnerabilities."
        )
        remediation = "Enable HTTPS: https://jupyterhub.readthedocs.io/en/stable/getting-started/security-basics.html#enabling-ssl-encryption"
        servers = list(filter(lambda x: "https" not in x, self.servers))
        return [Finding(category=category, source_text=f, source_doc="jupyter server list", source_details=details, remediation=remediation) for f in servers]

    def check_for_localhost(self):
        category = "Access"
        details = "These servers are exposed to a non-localhost domain/ip. They may be accessible to others."
        remediation = "Test external accessibility and reduce it as much as possible."
        servers = list(filter(lambda x: "localhost" not in x, self.servers))
        return [Finding(category=category, source_text=f, source_doc="jupyter server list",source_details=details, remediation=remediation) for f in servers]

    def db_contains_silent(self, db):
        con = sqlite3.connect(db)
        cur = con.cursor()
        res = cur.execute(
            "SELECT * FROM history WHERE source LIKE '%execute_interactive%code%silent%=%True%'"
        )
        return len(res.fetchall()) > 0

    def check_for_silent_history(self):
        category = "Malicious Activity"
        details = "Some code may have been executed with `silent=True`, an indicator of malicious activity."
        remediation = "Treat this as an active security incident until all silently run commands are verified as non-malicious."
        path = (
            subprocess.run(["ipython", "locate"], capture_output=True)
            .stdout.decode()
            .rstrip()
        )
        files = list(Path(path).rglob("*"))
        dbs = [f for f in files if f.name == "history.sqlite"]
        dbs = list(filter(self.db_contains_silent, dbs))
        return [Finding(category=category, source_doc=f.name,source_details=details, remediation=remediation) for f in dbs]
