# jupysec

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/JosephTLucas/jupysec/main?urlpath=lab)

![logo](jupysec.png)

_JupyterLab Security Utilities_

Security utilities for Jupyter environments. This extension evaluates the security posture of the environment by comparing configuration values with best practices.

This extension is under active development and pre-alpha release.

## Function

![demo](demo.gif)

Run the extension to generate an HTML report of the security configuration of your Jupyter instance and other Jupyter instances on your host.

Configurations will be compared against [these rules](https://github.com/JosephTLucas/jupysec/blob/dev/jupysec/rules.py).

These rules currently evaluate:

- Whether there are any executables in your ipython startup directories
- What lines of your configuration are nonstandard with known malicious uses
- Whether your servers require tokens for authentication
- Whether your server and client are communicating over HTTPS
- Whether you are serving Jupyter to a broader domain than just localhost
- If silent commands have been run against your kernels

Some of these categories may have false-positives depending on your environment and use-case. However, users should monitor their environments and be aware of their security posture and any changes.

Matches against [the rules](https://github.com/JosephTLucas/jupysec/blob/dev/jupysec/rules.py) are referred to as "Findings" and displayed in the Report Card.

![report card](report.png)

## Requirements

- JupyterLab >= 3.0

## Getting Started

To install the extension, execute:

```bash
pip install jupysec
```
After starting jupyterlab, your launcher window should now have a "Security" section with a widget for generating your findings. This will launch and index page with a list of all findings, color-coded by category. Click into findings for more details.

## Uninstall

To remove the extension, execute:

```bash
pip uninstall jupysec
```

## Troubleshoot

If you are seeing the frontend extension, but it is not working, check
that the server extension is enabled:

```bash
jupyter server extension list
```

If the server extension is installed and enabled, but you are not seeing
the frontend extension, check the frontend extension is installed:

```bash
jupyter labextension list
```