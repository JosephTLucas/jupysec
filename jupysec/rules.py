import subprocess
from pathlib import Path
import itertools
import os
import sqlite3
from jupysec.finding import Finding


class Rules:
    def __init__(self):
        """Makes subprocess calls to Jupyter CLI functions to collect data on paths and file contents"""
        self.locations = self._get_locations()
        self.uncommented = self._get_uncommented()
        self.servers = self._get_servers()

    def _get_locations(self):
        """Gets the path to the ipython directory"""
        locations = self._run_command(["ipython", "locate"])
        if locations.returncode == 0:
            locations = locations.stdout.decode().rstrip()
        else:
            locations = False
        return locations

    def _get_uncommented(self):
        """
        Finds uncommented lines of code in python configuration files.
        Returns a dict with the key is the uncommented line of code and the value is the file path.
        """
        paths = self._run_command(["jupyter", "--paths"])
        if paths.returncode == 0:
            paths = paths.stdout.decode().splitlines()
            paths = [x.lstrip() for x in paths]
            paths.append(self.locations)
            paths = set(
                filter(lambda x: x not in ["config:", "data:", "runtime:"], paths)
            )
            files = [list(Path(p).rglob("*")) for p in paths]
            files = list(itertools.chain(*files))
            target_py_files = (
                "jupyter_server_config.py",
                "jupyter_notebook_config.py",
                "ipython_config.py",
            )
            py_files = list(filter(lambda x: x.name.endswith(target_py_files), files))
            py_uncommented = list()
            for file in py_files:
                with open(file, "r") as f:
                    lines = f.read().splitlines()
                lines = filter(lambda x: len(x) > 0, lines)
                py_uncommented.append(
                    (
                        (list(filter(lambda x: x.lstrip()[0] not in ["#"], lines))),
                        file,
                    )
                )
            uncommented = dict()
            for lines, file in py_uncommented:
                for l in lines:
                    uncommented[l] = file
        else:
            uncommented = False
        return uncommented

    def _get_servers(self):
        """Returns a list of running server descriptors."""
        servers = self._run_command(["jupyter", "server", "list"])
        if servers.returncode == 0:
            servers = servers.stderr.decode().splitlines()[1:]
        else:
            servers = False

        return servers

    def _run_command(self, command):
        try:
            val = subprocess.run(command, capture_output=True)
        except FileNotFoundError:
            val = subprocess.CompletedProcess(args=command, returncode=1)
        return val

    def get_findings(self):
        findings = list()
        if self.locations:
            findings.append(self.check_ipython_startup())
            findings.append(self.check_for_silent_history())
        if self.servers:
            findings.append(self.check_for_token())
            findings.append(self.check_for_https())
            findings.append(self.check_for_localhost())
        if self.uncommented:
            findings.append(self.check_pyconfig_historymod())
            findings.append(self.check_pyconfig_codeexec())
            findings.append(self.check_pyconfig_securitysettings())
        findings = list(itertools.chain(*findings))
        return findings

    def check_ipython_startup(self):
        category = "Code Execution"
        details = "Files in this startup directory provide code execution when Jupyter is initiated."
        remediation = "Ensure the contents of these files are not malicious.\
        https://ipython.org/ipython-doc/1/config/overview.html#startup-files"
        files = list(Path(self.locations).rglob("*"))
        startup_files = [
            (os.listdir(f), f) for f in files if "startup" in f.name and f.is_dir()
        ]
        res = dict()
        for py_files, dir in startup_files:
            py_files = list(filter(lambda x: x != "README", py_files))
            for pf in py_files:
                res[pf] = dir

        return [
            Finding(
                category=category,
                source_text=file,
                source_doc=path,
                source_details=details,
                remediation=remediation,
            )
            for file, path in res.items()
        ]

    def check_for_token(self):
        category = "Authorization"
        details = (
            "These servers do not require a token and may allow unauthorized access."
        )
        remediation = (
            "Either enable tokens or ensure you are using password authentication."
        )
        servers = list(filter(lambda x: "token" not in x, self.servers))
        return [
            Finding(
                category=category,
                source_text=f,
                source_doc="jupyter server list",
                source_details=details,
                remediation=remediation,
            )
            for f in servers
        ]

    def check_for_https(self):
        category = "Encryption"
        details = (
            "These servers do not use HTTPS which could lead to MITM vulnerabilities."
        )
        remediation = "Enable HTTPS: https://jupyterhub.readthedocs.io/en/stable/getting-started/security-basics.html#enabling-ssl-encryption"
        servers = list(filter(lambda x: "https" not in x, self.servers))
        return [
            Finding(
                category=category,
                source_text=f,
                source_doc="jupyter server list",
                source_details=details,
                remediation=remediation,
            )
            for f in servers
        ]

    def check_for_localhost(self):
        category = "Access"
        details = "These servers are exposed to a non-localhost domain/ip. They may be accessible to others."
        remediation = "Test external accessibility and reduce it as much as possible."
        servers = list(filter(lambda x: "localhost" not in x, self.servers))
        return [
            Finding(
                category=category,
                source_text=f,
                source_doc="jupyter server list",
                source_details=details,
                remediation=remediation,
            )
            for f in servers
        ]

    def check_for_silent_history(self):
        category = "Malicious Activity"
        details = "Some code may have been executed with `silent=True`, an indicator of malicious activity."
        remediation = "Treat this as an active security incident until all silently run commands are verified as non-malicious."

        def _db_contains_silent(db):
            con = sqlite3.connect(db)
            cur = con.cursor()
            res = cur.execute(
                "SELECT * FROM history WHERE source LIKE '%execute_interactive%code%silent%=%True%'"
            )
            return res.fetchall()

        files = list(Path(self.locations).rglob("*"))
        dbs = [(_db_contains_silent(f), f) for f in files if f.name == "history.sqlite"]
        dbs = list(filter(lambda x: len(x[0]) > 0, dbs))
        return [
            Finding(
                category=category,
                source_text=f[0][0][2], #indexing into the db fields to extract the command text
                source_doc=f[1],
                source_details=details,
                remediation=remediation,
            )
            for f in dbs
        ]

    def check_pyconfig_codeexec(self):
        category = "Nonstandard Configuration"
        details = "These uncommented fields in configuration files enable non-obvious code execution.\
             Threat actors may use them for persistence or to modify your environment without your knowledge."
        remediation = "Ensure these configuration values are intentional. If you don't recognize them, alert your incident response team."
        findings = [
            (line, path)
            for line, path in self.uncommented.items()
            if line.startswith(
                (
                    "c.InteractiveShellApp.code_to_run",
                    "c.InteractiveShellApp.exec_PYTHONSTARTUP",
                    "c.InteractiveShellApp.exec_files",
                    "c.InteractiveShellApp.exec_lines",
                    "c.InteractiveShellApp.extensions",
                    "c.InteractiveShellApp.extra_extensions",
                    "c.InteractiveShellApp.file_to_run",
                    "c.InteractiveShellApp.ignore_cwd",
                    "c.InteractiveShellApp.module_to_run",
                    "c.BaseIPythonApplication.extra_config_file",
                    "c.BaseIPythonApplication.profile",
                    "c.TerminalIPythonApp.code_to_run",
                    "c.TerminalIPythonApp.exec_PYTHONSTARTUP",
                    "c.TerminalIPythonApp.exec_files",
                    "c.TerminalIPythonApp.exec_lines",
                    "c.TerminalIPythonApp.extensions",
                    "c.TerminalIPythonApp.extra_config_file",
                    "c.TerminalIPythonApp.extra_extensions",
                    "c.TerminalIPythonApp.file_to_run",
                    "c.TerminalIPythonApp.force_interact",
                    "c.TerminalIPythonApp.ignore_cwd",
                    "c.TerminalIPythonApp.ipython_dir",
                    "c.TerminalIPythonApp.module_to_run",
                    "c.TerminalIPythonApp.profile",
                    "c.JupyterApp.config_file",
                    "c.JupyterApp.config_file_name",
                    "c.ServerApp.browser",
                    "c.ServerApp.config_file",
                    "c.ServerApp.config_file_name",
                    "c.ServerApp.jpserver_extensions",
                    "c.Session.packer",
                    "c.ContentsManager.post_save_hook",
                    "c.ContentsManager.pre_save_hook",
                    "c.FileContentsManager.delete_to_trash",
                    "c.FileContentsManager.post_save_hook",
                    "c.FileContentsManager.pre_save_hook",
                )
            )
        ]
        return [
            Finding(
                category=category,
                source_text=line,
                source_doc=path,
                source_details=details,
                remediation=remediation,
            )
            for line, path in findings
        ]

    def check_pyconfig_historymod(self):
        category = "Nonstandard Configuration"
        details = "These uncommented fields in configuration files enable modification of history functions.\
             Threat actors may use these to hide or obfuscate their actions. Unmodified history is an important incident response artifact."
        remediation = "Ensure these configuration values are intentional. If you don't recognize them, alert your incident response team."
        findings = [
            (line, path)
            for line, path in self.uncommented.items()
            if line.startswith(
                (
                    "c.InteractiveShell.history_length",
                    "c.InteractiveShell.history_load_length",
                    "c.TerminalInteractiveShell.history_length",
                    "c.TerminalInteractiveShell.history_load_length",
                    "c.HistoryAccessor.connection_options",
                    "c.HistoryAccessor.enabled",
                    "c.HistoryAccessor.hist_file",
                    "c.HistoryManager.connection_options",
                    "c.HistoryManager.db_cache_size",
                    "c.HistoryManager.db_log_output",
                    "c.HistoryManager.enabled",
                    "c.HistoryManager.hist_file",
                    "c.InteractiveShell.history_load_length",
                )
            )
        ]
        return [
            Finding(
                category=category,
                source_text=line,
                source_doc=path,
                source_details=details,
                remediation=remediation,
            )
            for line, path in findings
        ]

    def check_pyconfig_securitysettings(self):
        category = "Nonstandard Configuration"
        details = "These uncommented fields in configuration files are related to security settings.\
             Threat actors may use these to circumvent secure defaults."
        remediation = "Ensure these configuration values are intentional. If you don't recognize them, alert your incident response team."
        findings = [
            (line, path)
            for line, path in self.uncommented.items()
            if line.startswith(
                (
                    "c.JupyterApp.answer_yes",
                    "c.ServerApp.allow_origin",
                    "c.ServerApp.allow_origin_pat",
                    "c.ServerApp.allow_remote_access",
                    "c.ServerApp.allow_root",
                    "c.ServerApp.answer_yes",
                    "c.ServerApp.authenticate_prometheus",
                    "c.ServerApp.autoreload",
                    "c.ServerApp.cookie_secret",
                    "c.ServerApp.cookie_secret_file",
                    "c.ServerApp.custom_display_url",
                    "c.ServerApp.default_url",
                    "c.ServerApp.disable_check_xsrf",
                    "c.ServerApp.extra_static_paths",
                    "c.ServerApp.extra_template_paths",
                    "c.ServerApp.file_to_run",
                    "c.ServerApp.identity_provider_class",
                    "c.ServerApp.ip",
                    "c.ServerApp.local_hostnames",
                    "c.ServerApp.login_handler_class",
                    "c.ServerApp.max_body_size",
                    "c.ServerApp.max_buffer_size",
                    "c.ServerApp.trust_xheaders",
                    "c.ServerApp.use_redirect_file",
                    "c.KernelManager.connection_file",
                    "c.KernelManager.control_port",
                    "c.KernelManager.hb_port",
                    "c.KernelManager.iopub_port",
                    "c.KernelManager.ip",
                    "c.KernelManager.shell_port",
                    "c.KernelManager.stdin_port",
                    "c.Session.check_pid",
                    "c.GatewayClient.validate_cert",
                )
            )
        ]
        return [
            Finding(
                category=category,
                source_text=line,
                source_doc=path,
                source_details=details,
                remediation=remediation,
            )
            for line, path in findings
        ]
