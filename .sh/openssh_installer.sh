#!/usr/bin/env bash
#########################################################################
# OpenSSH Hardened Configuration Installer
# 
# This script installs OpenSSH from the system package manager and
# applies hardened security configurations compatible with modern
# systems and security best practices.
# 
# OpenSSH official website: https://www.openssh.com/
# OpenSSH releases: https://github.com/openssh/openssh-portable/releases
# 
# Features:
# - Installs OpenSSH server from package manager
# - Applies security-hardened SSH configuration
# - Generates strong host keys (ED25519 and RSA 3072-bit)
# - Removes weak legacy keys
# - Configures modern cryptographic algorithms
# - Provides service management instructions
#########################################################################

# Safer error handling
set -euo pipefail

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m' # No Color
readonly BOLD='\033[1m'

# Configuration
readonly BACKUP_DIR="/root/ssh-backup-$(date +%Y%m%d-%H%M%S)"
readonly CONFIG_FILE="/etc/ssh/sshd_config"
readonly ORIGINAL_CONFIG="${CONFIG_FILE}.original"
readonly LOG_DIR="/tmp/openssh-logs-$$"

# Create directories
mkdir -p "$LOG_DIR"

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_step() { echo -e "${PURPLE}[→]${NC} ${BOLD}$1${NC}"; }

# Cleanup function
cleanup() {
    if [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ]; then
        rm -rf "$LOG_DIR"
    fi
}
trap cleanup EXIT INT TERM

# Check for root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo -e "Usage: sudo $0"
        exit 1
    fi
}

# Print header
print_header() {
    echo
    echo -e "${BOLD}OpenSSH Hardened Configuration Installer${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Installing OpenSSH server with hardened security configuration"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
}

# Detect package manager and install OpenSSH
install_openssh() {
    log_step "Installing OpenSSH server"
    
    if command -v apt-get &>/dev/null; then
        log_info "Detected Debian/Ubuntu system"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq &>"$LOG_DIR/apt-update.log"
        apt-get install -y openssh-server hostname clear &>"$LOG_DIR/apt-install.log"
    elif command -v dnf &>/dev/null; then
        log_info "Detected Fedora/RHEL system"
        dnf install -y openssh-server hostname clear &>"$LOG_DIR/dnf-install.log"
    elif command -v yum &>/dev/null; then
        log_info "Detected CentOS/RHEL system"
        yum install -y openssh-server hostname clear &>"$LOG_DIR/yum-install.log"
    else
        log_error "Unsupported package manager. This script requires apt, dnf, or yum."
        exit 1
    fi
    
    log_success "OpenSSH server installed"
}

# Create backup of existing configuration
backup_config() {
    log_step "Creating configuration backup"
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup SSH configuration directory
    if [ -d "/etc/ssh" ]; then
        cp -a /etc/ssh "$BACKUP_DIR/"
        log_info "SSH configuration backed up to $BACKUP_DIR"
    fi
    
    # Save original config if not already saved
    if [ -f "$CONFIG_FILE" ] && [ ! -f "$ORIGINAL_CONFIG" ]; then
        cp "$CONFIG_FILE" "$ORIGINAL_CONFIG"
        log_info "Original configuration saved as $ORIGINAL_CONFIG"
    fi
    
    # Save current SSH service status
    systemctl is-active sshd &>/dev/null && echo "sshd was active" > "$BACKUP_DIR/service_status.txt" || echo "sshd was inactive" > "$BACKUP_DIR/service_status.txt"
    
    log_success "Configuration backup completed"
}

# Generate strong host keys
generate_host_keys() {
    log_step "Generating secure host keys"
    
    # Generate ED25519 key (modern, secure)
    if [ ! -f "/etc/ssh/ssh_host_ed25519_key" ]; then
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' -q
        log_info "Generated ED25519 host key"
    fi
    
    # Generate RSA 3072-bit key (compatible, secure)
    if [ ! -f "/etc/ssh/ssh_host_rsa_key" ]; then
        ssh-keygen -t rsa -b 3072 -f /etc/ssh/ssh_host_rsa_key -N '' -q
    else
        # Check if existing RSA key is less than 3072 bits
        local key_bits=$(ssh-keygen -lf /etc/ssh/ssh_host_rsa_key | awk '{print $1}')
        if [ "$key_bits" -lt 3072 ]; then
            log_warn "Existing RSA key is only $key_bits bits, regenerating with 3072 bits"
            rm -f /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key.pub
            ssh-keygen -t rsa -b 3072 -f /etc/ssh/ssh_host_rsa_key -N '' -q
        fi
    fi
    log_info "Generated/verified RSA 3072-bit host key"
    
    # Remove weak legacy keys
    for key_type in dsa ecdsa; do
        if [ -f "/etc/ssh/ssh_host_${key_type}_key" ]; then
            rm -f "/etc/ssh/ssh_host_${key_type}_key" "/etc/ssh/ssh_host_${key_type}_key.pub"
            log_info "Removed weak $key_type host key"
        fi
    done
    
    # Set proper permissions
    chmod 600 /etc/ssh/ssh_host_*_key
    chmod 644 /etc/ssh/ssh_host_*_key.pub
    
    log_success "Host keys configured securely"
}

# Apply hardened SSH configuration
configure_ssh() {
    log_step "Applying hardened SSH configuration"
    
    # Find SFTP subsystem path
    local sftp_path
    if [ -f "/usr/lib/openssh/sftp-server" ]; then
        sftp_path="/usr/lib/openssh/sftp-server"
    elif [ -f "/usr/libexec/sftp-server" ]; then
        sftp_path="/usr/libexec/sftp-server"
    else
        sftp_path="/usr/lib/ssh/sftp-server"
    fi
    
    # Create hardened SSH configuration
    cat > "$CONFIG_FILE" << EOF
# Hardened OpenSSH Configuration
# Compatible with modern systems and security best practices

# Network settings
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# Host keys (only strong algorithms)
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication settings
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Password authentication (can be disabled for key-only access)
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# PAM authentication
UsePAM yes

# Connection settings
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes

# Strong cryptographic settings
Protocol 2
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Security hardening
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
PermitTunnel no
PrintMotd yes
PrintLastLog yes
Compression no
UseDNS no

# Logging
SyslogFacility AUTH
LogLevel INFO

# SFTP subsystem
Subsystem sftp $sftp_path

# Banner (optional)
# Banner /etc/issue.net
EOF
    
    # Set proper permissions
    chmod 644 "$CONFIG_FILE"
    
    log_success "Hardened SSH configuration applied"
}

# Configure firewall (if available)
configure_firewall() {
    log_step "Configuring firewall for SSH"
    
    # Try to configure firewall if available
    if command -v ufw &>/dev/null; then
        ufw allow ssh &>/dev/null || true
        log_info "UFW firewall configured for SSH"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-service=ssh &>/dev/null || true
        firewall-cmd --reload &>/dev/null || true
        log_info "Firewalld configured for SSH"
    else
        log_warn "No firewall detected. Ensure SSH port 22 is accessible"
    fi
    
    log_success "Firewall configuration completed"
}

# Test SSH configuration
test_configuration() {
    log_step "Testing SSH configuration"
    
    # Test configuration syntax
    if sshd -t 2>/dev/null; then
        log_success "SSH configuration syntax is valid"
    else
        log_error "SSH configuration has syntax errors"
        log_info "Running configuration test with verbose output:"
        sshd -t
        return 1
    fi
    
    # Check if SSH service can start
    if systemctl is-active --quiet sshd; then
        log_info "SSH service is already running"
    else
        if systemctl start sshd; then
            log_success "SSH service started successfully"
        else
            log_error "Failed to start SSH service"
            return 1
        fi
    fi
    
    log_success "SSH configuration test passed"
}

# Show installation summary
show_summary() {
    echo
    echo -e "${BOLD}Installation Summary${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if command -v sshd &>/dev/null; then
        local ssh_version=$(sshd -V 2>&1 | head -1 | grep -o 'OpenSSH_[^ ]*' || echo "Unknown")
        echo -e "${GREEN}✓${NC} OpenSSH server installed: $ssh_version"
        echo -e "${GREEN}✓${NC} Hardened security configuration applied"
        echo -e "${GREEN}✓${NC} Strong host keys generated (ED25519 + RSA 3072)"
        echo -e "${GREEN}✓${NC} Weak legacy keys removed"
        
        if systemctl is-active --quiet sshd; then
            echo -e "${GREEN}✓${NC} SSH service is running"
        else
            echo -e "${YELLOW}!${NC} SSH service is not running"
        fi
    else
        echo -e "${RED}✗${NC} OpenSSH installation may have failed"
    fi
    
    echo
    echo -e "${BOLD}Service Management${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Start SSH:      ${BLUE}sudo systemctl start sshd${NC}"
    echo -e "Stop SSH:       ${BLUE}sudo systemctl stop sshd${NC}"
    echo -e "Restart SSH:    ${BLUE}sudo systemctl restart sshd${NC}"
    echo -e "Enable SSH:     ${BLUE}sudo systemctl enable sshd${NC}"
    echo -e "Status:         ${BLUE}sudo systemctl status sshd${NC}"
    echo -e "Test config:    ${BLUE}sudo sshd -t${NC}"
    echo
    echo -e "${BOLD}Connection Information${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "SSH Port:       ${BLUE}22${NC}"
    echo -e "Config file:    ${BLUE}$CONFIG_FILE${NC}"
    echo -e "Host keys:      ${BLUE}/etc/ssh/ssh_host_*_key${NC}"
    echo -e "Backup:         ${BLUE}$BACKUP_DIR${NC}"
    
    # Show server IP addresses
    echo -e "Server IPs:     ${BLUE}$(hostname -I | tr ' ' '\n' | head -3 | tr '\n' ' ')${NC}"
    echo
    echo -e "${BOLD}Security Notes${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "• Root login is ${RED}disabled${NC} for security"
    echo -e "• Password authentication is ${GREEN}enabled${NC} (can be disabled)"
    echo -e "• Strong cryptographic algorithms enforced"
    echo -e "• Connection limits: 3 auth tries, 2 max sessions"
    echo -e "• Forwarding disabled for security"
    echo
    echo -e "${YELLOW}Connect with:${NC} ${BLUE}ssh username@$(hostname -I | awk '{print $1}')${NC}"
    echo
}

# Install OpenSSH with hardened configuration
install() {
    log_info "Starting OpenSSH hardened installation"
    
    # Safety check for SSH sessions
    if [[ -n "${SSH_CONNECTION:-}" ]] && [[ "${FORCE_SSH_INSTALL:-}" != "1" ]]; then
        log_error "Running in SSH session! This will modify SSH configuration."
        log_warn "If you have console access, run: FORCE_SSH_INSTALL=1 $0 install"
        log_warn "Or use 'screen' or 'tmux' to maintain session during restart"
        exit 1
    fi
    
    # Confirm installation
    if [[ "${CONFIRM:-}" != "yes" ]]; then
        if [[ -t 0 ]]; then
            # Interactive mode
            read -rp "Proceed with OpenSSH hardened installation? This will modify SSH configuration. [y/N] " answer
            [[ "${answer,,}" != "y" ]] && { log_error "Installation cancelled"; exit 0; }
        else
            # Non-interactive mode (piped)
            log_error "Non-interactive mode detected. Use: curl ... | CONFIRM=yes sudo bash -s install"
            exit 0
        fi
    fi
    
    check_root
    print_header
    
    backup_config
    install_openssh
    generate_host_keys
    configure_ssh
    configure_firewall
    test_configuration
    
    # Enable and start SSH service
    systemctl enable sshd
    systemctl restart sshd
    
    show_summary
    
    log_success "OpenSSH hardened installation completed successfully!"
}

# Remove OpenSSH and restore original configuration
remove() {
    log_info "Removing OpenSSH installation..."
    
    # Confirm removal
    if [[ "${CONFIRM:-}" != "yes" ]]; then
        if [[ -t 0 ]]; then
            # Interactive mode
            read -rp "Remove OpenSSH server? This will uninstall OpenSSH and restore original config. [y/N] " answer
            [[ "${answer,,}" != "y" ]] && { log_error "Removal cancelled"; exit 0; }
        else
            # Non-interactive mode (piped)
            log_error "Non-interactive mode detected. Use: curl ... | CONFIRM=yes sudo bash -s remove"
            exit 0
        fi
    fi
    
    # Stop SSH service
    if systemctl is-active --quiet sshd; then
        log_info "Stopping SSH service..."
        systemctl stop sshd
    fi
    
    # Disable SSH service
    if systemctl is-enabled --quiet sshd; then
        log_info "Disabling SSH service..."
        systemctl disable sshd
    fi
    
    # Restore original configuration if it exists
    if [ -f "$ORIGINAL_CONFIG" ]; then
        cp "$ORIGINAL_CONFIG" "$CONFIG_FILE"
        log_info "Original SSH configuration restored"
    fi
    
    # Remove OpenSSH server package
    if command -v apt-get &>/dev/null; then
        apt-get remove -y openssh-server &>"$LOG_DIR/apt-remove.log"
        apt-get autoremove -y &>"$LOG_DIR/apt-autoremove.log"
    elif command -v dnf &>/dev/null; then
        dnf remove -y openssh-server &>"$LOG_DIR/dnf-remove.log"
    elif command -v yum &>/dev/null; then
        yum remove -y openssh-server &>"$LOG_DIR/yum-remove.log"
    fi
    
    log_success "OpenSSH server removed"
    log_warn "SSH service has been stopped and disabled"
    log_info "Configuration backup remains in: $BACKUP_DIR"
}

# Verify OpenSSH installation and configuration
verify() {
    log_info "Verifying OpenSSH installation..."
    
    local issues=0
    
    # Check if OpenSSH is installed
    if command -v sshd &>/dev/null; then
        local ssh_version=$(sshd -V 2>&1 | head -1 | grep -o 'OpenSSH_[^ ]*' || echo "Unknown")
        log_success "OpenSSH server installed: $ssh_version"
    else
        log_error "OpenSSH server not found"
        ((issues++))
    fi
    
    # Check configuration file
    if [ -f "$CONFIG_FILE" ]; then
        log_success "SSH configuration file exists: $CONFIG_FILE"
        
        # Test configuration
        if sshd -t 2>/dev/null; then
            log_success "SSH configuration syntax is valid"
        else
            log_error "SSH configuration has syntax errors"
            ((issues++))
        fi
    else
        log_error "SSH configuration file not found"
        ((issues++))
    fi
    
    # Check service status
    if systemctl is-active --quiet sshd; then
        log_success "SSH service is running"
    else
        log_warn "SSH service is not running"
    fi
    
    if systemctl is-enabled --quiet sshd; then
        log_success "SSH service is enabled"
    else
        log_warn "SSH service is not enabled"
    fi
    
    # Check host keys
    local key_count=0
    for key in /etc/ssh/ssh_host_*_key; do
        if [ -f "$key" ]; then
            local key_type=$(echo "$key" | sed 's/.*ssh_host_\(.*\)_key/\1/')
            local key_info=$(ssh-keygen -lf "$key" 2>/dev/null || echo "Invalid key")
            log_success "Host key ($key_type): $key_info"
            ((key_count++))
        fi
    done
    
    if [ "$key_count" -gt 0 ]; then
        log_success "Host keys are configured"
    else
        log_error "No host keys found"
        ((issues++))
    fi
    
    # Check listening ports
    if command -v ss &>/dev/null; then
        local ssh_ports=$(ss -tlnp | grep :22 | wc -l)
        if [ "$ssh_ports" -gt 0 ]; then
            log_success "SSH is listening on port 22"
        else
            log_warn "SSH is not listening on port 22"
        fi
    fi
    
    # Check directories and permissions
    local dirs=("/etc/ssh" "/var/log")
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_success "Directory exists: $dir"
        else
            log_error "Directory missing: $dir"
            ((issues++))
        fi
    done
    
    echo
    if [[ $issues -eq 0 ]]; then
        log_success "OpenSSH installation verification passed!"
        return 0
    else
        log_error "OpenSSH installation verification failed with $issues issues"
        return 1
    fi
}

# Main function
main() {
    case "${1:-help}" in
        install)
            install
            ;;
        remove)
            check_root
            remove
            ;;
        verify)
            verify
            ;;
        *)
            echo
            echo -e "${BOLD}OpenSSH Hardened Configuration Installer${NC}"
            echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "Usage: $0 {install|remove|verify}"
            echo
            echo "  install - Install OpenSSH server with hardened configuration"
            echo "  remove  - Remove OpenSSH server and restore original configuration"
            echo "  verify  - Check OpenSSH installation and configuration status"
            echo
            echo "Environment variables:"
            echo "  CONFIRM=yes         - Skip installation confirmation"
            echo "  FORCE_SSH_INSTALL=1 - Allow installation over SSH (risky!)"
            echo
            echo "Examples:"
            echo "  $0 install                    # Interactive installation"
            echo "  CONFIRM=yes $0 install       # Non-interactive installation"
            echo "  $0 verify                     # Check installation"
            echo "  $0 remove                     # Remove installation"
            echo
            echo "Features:"
            echo "  • Installs OpenSSH from system package manager"
            echo "  • Applies hardened security configuration"
            echo "  • Generates strong host keys (ED25519 + RSA 3072)"
            echo "  • Removes weak legacy keys"
            echo "  • Disables insecure features and protocols"
            echo "  • Compatible with modern SSH clients"
            echo
            ;;
    esac
}

# Run main function
main "$@"
