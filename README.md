# Scripts

Installer scripts for tools and software I use regularly. Tailored to my preferences, but easy to adapt.

## Usage

```bash
git clone --recurse-submodules https://github.com/Stensel8/scripts.git
cd scripts
```

Bash:
```bash
./<tool>_installer.sh
```

PowerShell:
```powershell
pwsh ./<tool>_installer.ps1
```

## Scripts

| Directory | File(s) | Platform | Notes |
|-----------|---------|----------|-------|
| `ansible/` | `ansible_installer.sh` | Linux | Builds Python from source, installs Ansible in venv |
| `docker/` | `docker_installer.sh` | Linux | Official Docker repositories |
| `kubernetes/` | `kubernetes_installer.sh` | Linux | kubectl + optional Minikube |
| `nginx/` | `nginx_installer.sh`, `nginx_installer.ps1` | Linux | Custom build: OpenSSL 3.x, HTTP/2, HTTP/3, zstd, headers-more, ACME |
| `openssh/` | `openssh_installer.sh` | Linux | Hardened config, Ed25519-only, post-quantum KEX (ML-KEM) |
| `podman/` | `podman_installer.sh` | Linux | Distribution repositories |
| `terraform/` | `terraform_installer.sh` | Linux | HashiCorp repositories |
| `TLS-tools/` | `TLS-checker.ps1` | Cross-platform | Tests TLS versions, HTTP versions, QUIC, HSTS, compression |
| `TLS-tools/` | `testssl.sh` (submodule) | Linux | Comprehensive TLS/SSL scanner by Dirk Wetter — pinned at v3.2.3 |
| `windows/` | `Enable-WinRM.ps1` | Windows | Configures WinRM for remote management |
| `windows/` | `Get-InstalledSoftware.ps1` | Windows | Lists installed software from registry |
| `windows/` | `configure-Windows-VM.ps1` | Windows | Disables unnecessary services for VMs |
| `windows/` | `Install-VagrantVMware.ps1` | Windows | Installs Vagrant + VMware Workstation |
| `windows/` | `Install Dell-Command_Update.ps1` | Windows | Installs Dell Command Update via winget |
| `windows/` | `Install HPIA.ps1` | Windows | Installs HP Image Assistant via winget |

## Automation

Dependency checks run weekly via GitHub Actions. When updates are detected, a PR is created automatically.

Script validation runs on every push: ShellCheck for Bash, PSScriptAnalyzer for PowerShell.

## Notes

- `testssl.sh` is included as a Git submodule. Run `git submodule update --init` if it's missing after cloning.
- NGINX updates require manual checksum verification: `.github/scripts/update-nginx-checksums.sh`
- Some scripts were partially written with GitHub Copilot assistance.
