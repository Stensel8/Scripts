# Scripts Repository

Quick installer scripts for my most used tools. Run directly from GitHub or download and modify as needed.

Most scripts are changed to fit my own needs, but can always be easily modified for your own use.

## Bash

### NGINX
```bash
# Install
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/nginx/nginx_installer.sh | sudo env CONFIRM=yes bash -s install

# Remove
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/nginx/nginx_installer.sh | sudo env CONFIRM=yes bash -s remove
```

### OpenSSH
```bash
# Install
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/openssh/openssh_installer.sh | sudo env CONFIRM=yes bash -s install

# Remove
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/openssh/openssh_installer.sh | sudo env CONFIRM=yes bash -s remove
```

### Docker
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/docker/docker_installer.sh | sudo bash
```

### Podman
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/podman/podman_installer.sh | sudo bash
```

### Ansible
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/ansible/ansible_installer.sh | sudo bash
```

### Terraform
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/terraform/terraform_installer.sh | sudo bash
```

### Kubernetes
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/kubernetes/kubernetes_installer.sh | sudo bash
```

## PowerShell

### Configure Windows VM
```powershell
irm https://raw.githubusercontent.com/Stensel8/scripts/main/windows/configure-Windows-VM.ps1 | iex
```

### Enable WinRM
```powershell
irm https://raw.githubusercontent.com/Stensel8/scripts/main/windows/Enable-WinRM.ps1 | iex
```

### TLS Checker
```powershell
irm https://raw.githubusercontent.com/Stensel8/scripts/main/TLS-tools/TLS-checker.ps1 | iex
```
