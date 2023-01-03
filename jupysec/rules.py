import subprocess
from pathlib import Path
import itertools
import os

def check_ipython_startup():
    path = subprocess.run(["ipython", "locate"], capture_output=True).stdout.decode().rstrip()
    files = list(Path(path).rglob("*"))
    startup_files = [os.listdir(f) for f in files if "startup" in f.name]
    startup_files = list(itertools.chain(*startup_files))
    return list(filter(lambda x: x != "README", startup_files))

def get_not_commented(files):
    findings = list()
    for file in files:
        with open(file, "r") as f:
            lines = f.read().splitlines()
        lines = filter(lambda x: len(x) > 0, lines)
        findings.append(list(filter(lambda x: x[0] not in ["#"], lines)))
    findings = list(itertools.chain(*findings))
    return findings

def check_for_token():
    servers = subprocess.run(["jupyter", "server", "list"], capture_output=True).stderr.decode().splitlines()[1:]
    return list(filter(lambda x: "token" not in x, servers))

def check_for_https():
    servers = subprocess.run(["jupyter", "server", "list"], capture_output=True).stderr.decode().splitlines()[1:]
    return list(filter(lambda x: "https" not in x, servers))