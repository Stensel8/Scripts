# Contributing to Scripts Repository

Thank you for your interest in contributing to this repository! This guide will help you understand how to maintain and update the installer scripts.

## Automated Dependency Management

This repository uses several automated tools to help keep dependencies up-to-date:

### 1. Dependabot (`.github/dependabot.yml`)
Automatically monitors and creates PRs for:
- GitHub Actions updates
- Docker image updates

**Action required:** Review and merge Dependabot PRs after testing.

### 2. Dependency Version Checker (`.github/workflows/check-dependencies.yml`)
Runs weekly to check for updates to hardcoded versions in installer scripts.

**Action required:** When issues are created, follow the update instructions to manually update version numbers and SHA256 checksums.

### 3. Script Validator (`.github/workflows/validate-scripts.yml`)
Runs on all PRs and commits to validate:
- Bash script syntax and quality (ShellCheck)
- PowerShell script syntax and quality (PSScriptAnalyzer)
- Potential security issues

**Action required:** Fix any validation errors before merging.

## Updating Installer Scripts

### General Process

1. **Check for updates**: Automated workflows will create issues when updates are available
2. **Update version numbers**: Edit the relevant `*_VERSION` variables in the script
3. **Calculate new checksums**: Download the new version and calculate SHA256
4. **Update checksums**: Replace old SHA256 values with new ones
5. **Test**: Run the script on a clean system to verify it works
6. **Commit**: Push changes and ensure CI passes
7. **Close issue**: Close the automated dependency issue

### Example: Updating NGINX

```bash
# 1. Edit nginx/nginx_installer.sh
# Update these lines:
NGINX_VERSION="1.29.8"  # Change version
NGINX_SHA256="new_sha256_here"  # Update checksum

# 2. Calculate new SHA256 (if needed)
wget https://github.com/nginx/nginx/releases/download/release-1.29.8/nginx-1.29.8.tar.gz
sha256sum nginx-1.29.8.tar.gz

# 3. Test the script
sudo ./nginx/nginx_installer.sh install

# 4. Verify installation
nginx -v
nginx -V  # Check modules

# 5. Commit changes
git add nginx/nginx_installer.sh
git commit -m "deps: update NGINX to 1.29.8"
git push
```

### Example: Updating Ansible/Python

```bash
# 1. Edit ansible/ansible_installer.sh
# Update these variables:
BUILD_PYTHON_VERSION="${BUILD_PYTHON_VERSION:-3.14.3}"

# 2. Also update pip install line if Ansible version changed
# Look for: pip install ansible==13.4.0

# 3. Test installation
sudo ./ansible/ansible_installer.sh

# 4. Verify
ansible --version

# 5. Commit
git add ansible/ansible_installer.sh
git commit -m "deps: update Python to 3.14.3 and Ansible to 13.4.0"
git push
```

## Testing Guidelines

### Before Committing
1. **Syntax check**: Ensure scripts pass syntax validation
   ```bash
   bash -n script_name.sh
   shellcheck script_name.sh
   ```

2. **Test installation**: Run on a clean system (VM/container recommended)
   ```bash
   # Use a fresh Ubuntu/RHEL VM or container
   docker run -it --rm ubuntu:latest
   # Or
   docker run -it --rm fedora:latest
   ```

3. **Verify functionality**: After installation, test that the software works
   ```bash
   # Example for nginx
   nginx -v
   nginx -t
   systemctl status nginx
   ```

### After Committing
- Check that GitHub Actions workflows pass
- Review any warnings from ShellCheck or PSScriptAnalyzer
- Ensure no security scan warnings

## Script Structure Guidelines

### Version Configuration
Always keep version numbers at the top of scripts in clearly marked sections:

```bash
# ============================================================================
# Version Configuration
# ============================================================================

NGINX_VERSION="1.29.7"
NGINX_SHA256="673f8fb8c0961c44fbd9410d6161831453609b44063d3f2948253fc2b5692139"
```

### Error Handling
Use proper error handling:

```bash
set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Or
set -e
set -o pipefail
```

### Logging
Include informative logging:

```bash
info()    { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; exit 1; }
```

## Common Tasks

### Adding a New Installer Script

1. Create the script in an appropriate directory
2. Follow existing naming convention: `<tool>_installer.sh`
3. Include version configuration section at the top
4. Add error handling and logging
5. Test thoroughly on clean systems
6. Update README.md to mention the new script
7. Consider adding version checks to `.github/workflows/check-dependencies.yml`

### Adding Dependency Checks for New Scripts

Edit `.github/workflows/check-dependencies.yml`:

```yaml
check-newtool-deps:
  name: Check NewTool Dependencies
  runs-on: ubuntu-latest
  steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Check NewTool version
      id: newtool
      run: |
        CURRENT_VERSION=$(grep -oP 'NEWTOOL_VERSION="\K[^"]+' newtool/newtool_installer.sh)
        # ... rest of check logic
```

## Security Considerations

1. **Never commit credentials**: Use environment variables or prompt for sensitive data
2. **Verify checksums**: Always verify SHA256 checksums for downloaded files
3. **Use HTTPS**: Only download from HTTPS URLs
4. **Validate inputs**: Check user inputs before using them
5. **Run as root carefully**: Only request root when necessary

## Getting Help

- **Issues**: Create an issue if you encounter problems
- **Discussions**: Use GitHub Discussions for questions
- **Automated Checks**: Let the CI/CD workflows guide you

## Code of Conduct

- Be respectful and constructive
- Test your changes thoroughly
- Document significant changes
- Follow existing code style and conventions
