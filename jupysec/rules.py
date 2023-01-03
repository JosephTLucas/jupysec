import subprocess
from pathlib import Path
import itertools
import os
from collections import namedtuple

Finding = namedtuple('Finding', ['category', 'file', 'details'])

def check_ipython_startup():
    category = "Code Execution"
    details = "Files in this startup directory provide code execution when Jupyter is initiated. Ensure the contents of these files are not malicious."
    path = subprocess.run(["ipython", "locate"], capture_output=True).stdout.decode().rstrip()
    files = list(Path(path).rglob("*"))
    startup_files = [os.listdir(f) for f in files if "startup" in f.name]
    startup_files = list(itertools.chain(*startup_files))
    startup_files = list(filter(lambda x: x != "README", startup_files))
    return [Finding(category, f, details) for f in startup_files]

def get_not_commented(files):
    category = "Nonstandard Configuration"
    details = "Uncommented fields in configuration files may enable nonstandard and potentially malicious/vulnerable functionality. \
    Ensure these configuration values are intentional."
    findings = list()
    for file in files:
        with open(file, "r") as f:
            lines = f.read().splitlines()
        lines = filter(lambda x: len(x) > 0, lines)
        findings.append(list(filter(lambda x: x[0] not in ["#"], lines)))
    findings = list(itertools.chain(*findings))
    return [Finding(category, f, details) for f in findings]

def check_for_token():
    category = "Authorization"
    details = "These servers do not require a token and may allow unauthorized access."
    servers = subprocess.run(["jupyter", "server", "list"], capture_output=True).stderr.decode().splitlines()[1:]
    servers = list(filter(lambda x: "token" not in x, servers))
    return [Finding(category, f, details) for f in servers]

def check_for_https():
    category = "Encryption"
    details = "These servers do not HTTPS which could lead to MITM vulnerabilities."
    servers = subprocess.run(["jupyter", "server", "list"], capture_output=True).stderr.decode().splitlines()[1:]
    servers = list(filter(lambda x: "https" not in x, servers))
    return [Finding(category, f, details) for f in servers]