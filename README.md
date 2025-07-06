# Scripts Repository

## About This Repository

This repository contains a collection of enhanced and complex installer scripts that I use internally for automation (also with Terraform and Ansible). These scripts help me quickly deploy and switch between different versions of NGINX (as well as Docker, Ansible, Terraform, and Kubernetes) on various systems. The idea is to have a simple, one-command installation that can easily be updated or switched between versions when needed.

---

## How to Run a Script

### Run Directly
To run a script directly without saving it, use the following command in a terminal.

Choose between the **main** branch (stable) or **testing** branch (latest features) depending on your needs.

---

# MAIN BRANCH (STABLE - RECOMMENDED)

**Use the main branch for production environments and stable deployments.**

## Shell Scripts (.sh) - Main Branch


### nginx_installer.sh

This script installs a custom compiled NGINX with OpenSSL 3.5.1 for improved HTTP/3 and QUIC support. The build includes performance optimizations.

### nginx_installer.sh - Install
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/.sh/nginx_installer.sh \
  | sudo env CONFIRM=yes bash -s install
```
### nginx_installer.sh - Verify
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/.sh/nginx_installer.sh \
  | sudo env CONFIRM=yes bash -s verify
```
### nginx_installer.sh - Remove
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/.sh/nginx_installer.sh \
  | sudo env CONFIRM=yes bash -s remove
```

**Features:**
- NGINX 1.29.0
- OpenSSL 3.5.1 with enhanced QUIC support
- HTTP/3 module enabled
- Full feature set including mail, stream, and all standard modules

**Note:** The script will detect existing NGINX installations and offer to remove them before installing the custom build.

### openssl+openssh_installer.sh - Install
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/.sh/openssl+openssh_installer.sh \
  | sudo env CONFIRM=yes bash -s install
```
### openssl+openssh_installer.sh - Verify
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/.sh/openssl+openssh_installer.sh \
  | sudo env CONFIRM=yes bash -s verify
```
### openssl+openssh_installer.sh - Remove
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/.sh/openssl+openssh_installer.sh \
  | sudo env CONFIRM=yes bash -s remove
```
**Features:**
- OpenSSL 3.5.1
- OpenSSH 10.0 with enhanced security features
- Improved cryptographic algorithm support
- Hardened security configurations by default
- Complete with all standard modules and extensions

**Note:** The script checks for existing OpenSSL and OpenSSH installations and will prompt before replacing them to avoid disrupting your system configuration.

### docker_installer.sh
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/.sh/docker_installer.sh | sudo bash
```

### ansible_installer.sh
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/.sh/ansible_installer.sh | sudo bash
```

### terraform_installer.sh
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/.sh/terraform_installer.sh | sudo bash
```

### kubernetes_installer.sh
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/main/.sh/kubernetes_installer.sh | sudo bash
```

## PowerShell Scripts (.ps1) - Main Branch

### Enable-WinRM.ps1
**Features:** Configures Windows Remote Management (WinRM) for PowerShell remoting with security considerations
```ps1
irm https://raw.githubusercontent.com/Stensel8/scripts/main/.ps1/Enable-WinRM.ps1 | iex
```

### configure-Windows-VM.ps1
**Features:** Optimizes Windows VMs by disabling unnecessary services and features (tested on Windows 11 and Server 2025)
```ps1
irm https://raw.githubusercontent.com/Stensel8/scripts/main/.ps1/configure-Windows-VM.ps1 | iex
```

### install-vmware-workstation-with-vagrant.ps1
**Features:** Automated setup for VMware Workstation with Vagrant integration and Go development environment
```ps1
irm https://raw.githubusercontent.com/Stensel8/scripts/main/.ps1/install-vmware-workstation-with-vagrant.ps1 | iex
```

### TLS-checker.ps1
**Features:** Comprehensive TLS & HTTP feature tester with compression, TLS versions, HTTP versions, QUIC, and HSTS testing
```ps1
irm https://raw.githubusercontent.com/Stensel8/scripts/main/.ps1/TLS-checker.ps1 | iex
```

---


# TESTING BRANCH (LATEST FEATURES)

**Use the testing branch to access the latest features and improvements.**  
**Note:** Testing branch may be less stable and is recommended for development environments.

## Shell Scripts (.sh) - Testing Branch

### nginx_installer.sh (Testing)
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/testing/.sh/nginx_installer.sh \
  | sudo env CONFIRM=yes bash -s install
```
#### Verify
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/testing/.sh/nginx_installer.sh \
  | sudo env CONFIRM=yes bash -s verify
```
#### Remove
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/testing/.sh/nginx_installer.sh \
  | sudo env CONFIRM=yes bash -s remove
```

### openssl+openssh_installer.sh (Testing)
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/testing/.sh/openssl+openssh_installer.sh \
  | sudo env CONFIRM=yes bash -s install
```
#### Verify
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/testing/.sh/openssl+openssh_installer.sh \
  | sudo env CONFIRM=yes bash -s verify
```
#### Remove
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/testing/.sh/openssl+openssh_installer.sh \
  | sudo env CONFIRM=yes bash -s remove
```

### docker_installer.sh (Testing)
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/testing/.sh/docker_installer.sh | sudo bash
```

### ansible_installer.sh (Testing)
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/testing/.sh/ansible_installer.sh | sudo bash
```

### terraform_installer.sh (Testing)
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/testing/.sh/terraform_installer.sh | sudo bash
```

### kubernetes_installer.sh (Testing)
```bash
curl -fsSL https://raw.githubusercontent.com/Stensel8/scripts/testing/.sh/kubernetes_installer.sh | sudo bash
```

## PowerShell Scripts (.ps1) - Testing Branch

### Enable-WinRM.ps1 (Testing)
**Features:** Configures Windows Remote Management (WinRM) for PowerShell remoting with security considerations
```ps1
irm https://raw.githubusercontent.com/Stensel8/scripts/testing/.ps1/Enable-WinRM.ps1 | iex
```

### configure-Windows-VM.ps1 (Testing)
**Features:** Optimizes Windows VMs by disabling unnecessary services and features (tested on Windows 11 and Server 2025)
```ps1
irm https://raw.githubusercontent.com/Stensel8/scripts/testing/.ps1/configure-Windows-VM.ps1 | iex
```

### install-vmware-workstation-with-vagrant.ps1 (Testing)
**Features:** Automated setup for VMware Workstation with Vagrant integration and Go development environment
```ps1
irm https://raw.githubusercontent.com/Stensel8/scripts/testing/.ps1/install-vmware-workstation-with-vagrant.ps1 | iex
```

### TLS-checker.ps1 (Testing)
**Features:** Comprehensive TLS & HTTP feature tester with compression, TLS versions, HTTP versions, QUIC, and HSTS testing
```ps1
irm https://raw.githubusercontent.com/Stensel8/scripts/testing/.ps1/TLS-checker.ps1 | iex
```
