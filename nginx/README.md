# NGINX Installer

Minimal scripts for building NGINX from source with hardened defaults.

## Quick start

```bash
# Bash installer
sudo ./nginx_installer.sh install
sudo ./nginx_installer.sh verify
sudo ./nginx_installer.sh remove

# PowerShell installer
sudo pwsh ./nginx_installer.ps1 install
sudo pwsh ./nginx_installer.ps1 verify
sudo pwsh ./nginx_installer.ps1 remove
```

## Optional toggles

Set environment variables in-line to change behaviour:

```bash
ENABLE_HEADERS_MORE=0 sudo pwsh ./nginx_installer.ps1 install
ENABLE_ZSTD=0 sudo pwsh ./nginx_installer.ps1 install
CONFIRM=no sudo pwsh ./nginx_installer.ps1 install
```

Templates live under `config/` if you need to edit versions, configs, or HTML.

