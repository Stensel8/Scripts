#!/usr/bin/env bash
#########################################################################
# OpenSSH Hardened Configuration Installer
#
# Installs OpenSSH and applies a maximally hardened configuration.
# Designed for modern systems where password authentication over SSH
# is considered obsolete and insecure.
#
# Philosophy:
#   SSH keys are the only acceptable authentication method for remote
#   access. Passwords belong exclusively in sudo as a second layer,
#   never as SSH authentication.
#
#   Recommendation: store your SSH private keys in Bitwarden (SSH Agent
#   feature) or another password manager. This gives you:
#     - Encrypted key storage
#     - Cross-device key sync
#     - Audit log of key usage
#     - Easy revocation
#
#   External access: PKI auth only, FUTURE crypto policy (Fedora/RHEL)
#   Internal access: PKI auth only, sudo for privilege escalation
#
# OpenSSH official website: https://www.openssh.com/
#########################################################################

set -euo pipefail

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

readonly BACKUP_DIR="/root/ssh-backup-$(date +%Y%m%d-%H%M%S)"
readonly CONFIG_FILE="/etc/ssh/sshd_config"
readonly ORIGINAL_CONFIG="${CONFIG_FILE}.original"
readonly LOG_DIR="/tmp/openssh-logs-$$"

detect_ssh_service() {
    if systemctl list-unit-files | grep -q "^ssh\.service"; then
        echo "ssh"
    elif systemctl list-unit-files | grep -q "^sshd\.service"; then
        echo "sshd"
    else
        command -v apt-get &>/dev/null && echo "ssh" || echo "sshd"
    fi
}

readonly SSH_SERVICE=$(detect_ssh_service)
mkdir -p "$LOG_DIR"

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1" >&2; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_step()    { echo -e "${PURPLE}[→]${NC} ${BOLD}$1${NC}"; }

cleanup() {
    [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ] && rm -rf "$LOG_DIR"
}
trap cleanup EXIT INT TERM

check_root() {
    [ "$EUID" -eq 0 ] || { log_error "Run as root: sudo $0"; exit 1; }
}

print_header() {
    echo
    echo -e "${BOLD}OpenSSH Hardened Configuration Installer${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Ed25519-only · No password auth · FUTURE crypto policy compatible"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
}

install_openssh() {
    log_step "Installing OpenSSH server"
    if command -v apt-get &>/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq &>"$LOG_DIR/apt-update.log"
        apt-get install -y openssh-server &>"$LOG_DIR/apt-install.log"
    elif command -v dnf &>/dev/null; then
        dnf install -y openssh-server &>"$LOG_DIR/dnf-install.log"
    elif command -v yum &>/dev/null; then
        yum install -y openssh-server &>"$LOG_DIR/yum-install.log"
    else
        log_error "Unsupported package manager (requires apt, dnf, or yum)"
        exit 1
    fi
    log_success "OpenSSH server installed"
}

backup_config() {
    log_step "Backing up existing configuration"
    mkdir -p "$BACKUP_DIR"
    [ -d "/etc/ssh" ] && cp -a /etc/ssh "$BACKUP_DIR/"
    [ -f "$CONFIG_FILE" ] && [ ! -f "$ORIGINAL_CONFIG" ] && cp "$CONFIG_FILE" "$ORIGINAL_CONFIG"
    systemctl is-active "$SSH_SERVICE" &>/dev/null \
        && echo "active"   > "$BACKUP_DIR/service_status.txt" \
        || echo "inactive" > "$BACKUP_DIR/service_status.txt"
    log_success "Backup saved to $BACKUP_DIR"
}

generate_host_keys() {
    log_step "Generating Ed25519 host key"

    # Ed25519 — the only host key we need
    if [ ! -f "/etc/ssh/ssh_host_ed25519_key" ]; then
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' -q
        log_info "Generated Ed25519 host key"
    else
        log_info "Ed25519 host key already exists"
    fi

    # Remove weak legacy keys (RSA, ECDSA, DSA)
    for key_type in rsa ecdsa dsa; do
        if [ -f "/etc/ssh/ssh_host_${key_type}_key" ]; then
            rm -f "/etc/ssh/ssh_host_${key_type}_key" \
                  "/etc/ssh/ssh_host_${key_type}_key.pub"
            log_info "Removed legacy $key_type host key"
        fi
    done

    chmod 600 /etc/ssh/ssh_host_*_key
    chmod 644 /etc/ssh/ssh_host_*_key.pub
    log_success "Host keys configured (Ed25519 only)"
}

configure_ssh() {
    log_step "Writing hardened SSH configuration"

    local sftp_path="/usr/lib/openssh/sftp-server"
    [ -f "/usr/libexec/sftp-server" ]       && sftp_path="/usr/libexec/sftp-server"
    [ -f "/usr/libexec/openssh/sftp-server" ] && sftp_path="/usr/libexec/openssh/sftp-server"

    cat > "$CONFIG_FILE" << 'EOF'
# =============================================================================
# Hardened OpenSSH Server Configuration
# Ed25519-only · No password auth · FUTURE crypto policy compatible
#
# CVE mitigations:
#   CVE-2023-51767 — Ed25519 only (no RSA)
#   CVE-2025-26465 — UseDNS no
#   CVE-2025-26466 — LoginGraceTime 30, MaxStartups 20:50:100
#   CVE-2025-32728 — All forwarding explicitly disabled
#
# Key philosophy:
#   Password authentication over SSH is obsolete and insecure.
#   SSH keys are the only acceptable remote auth method.
#
#   Recommendation: store your SSH keys in Bitwarden (SSH Agent feature).
#   This gives you encrypted storage, cross-device sync, audit logs, and
#   easy revocation — without ever exposing your private key.
#
#   Use passwords only for sudo (local privilege escalation), never for
#   SSH authentication itself.
#
#   External access: PKI auth only, FUTURE crypto policy (Fedora/RHEL)
#   Internal access: PKI auth only, sudo as the second layer
# =============================================================================

# -----------------------------------------------------------------------------
# Network
# -----------------------------------------------------------------------------
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# -----------------------------------------------------------------------------
# Host Keys — Ed25519 only
# -----------------------------------------------------------------------------
HostKey /etc/ssh/ssh_host_ed25519_key

# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------
PermitRootLogin no
StrictModes yes
PermitEmptyPasswords no

# Public key authentication — the only accepted method
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedKeysFile .ssh/authorized_keys

# PasswordAuthentication is disabled. SSH passwords are not of this era.
# If you're locked out and need emergency access:
#   1. Get console access to the machine
#   2. Temporarily uncomment the line below and restart sshd
#   3. Fix your keys, then re-disable password auth immediately
# PasswordAuthentication yes
PasswordAuthentication no

# Disable all other auth methods
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
HostbasedAuthentication no
GSSAPIAuthentication no

# UsePAM: disabled — we don't need PAM for key-only auth
# WARNING: on some distros this affects account/session modules.
# If you see login issues, re-enable and investigate pam config.
UsePAM no

# Restrict to specific users (recommended — add your username)
# AllowUsers youruser

# -----------------------------------------------------------------------------
# DoS / Connection Protection
# -----------------------------------------------------------------------------
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 10
MaxStartups 20:50:100
PerSourceMaxStartups 20
PerSourceNetBlockSize 32:128
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# -----------------------------------------------------------------------------
# Cryptographic Algorithms — FUTURE policy compatible
# Ed25519 + curve25519 + AES-256 + SHA-256+ only
# No RSA, no ECDSA, no SHA-1, no AES-128
# -----------------------------------------------------------------------------
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519
PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com

# No compression — faster on modern connections, avoids CRIME-style attacks
Compression no

# -----------------------------------------------------------------------------
# Forwarding — all disabled
# -----------------------------------------------------------------------------
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
X11Forwarding no
X11UseLocalhost yes
PermitTunnel no
PermitUserEnvironment no
StreamLocalBindUnlink no
IgnoreRhosts yes

# -----------------------------------------------------------------------------
# Privacy & DNS
# -----------------------------------------------------------------------------
UseDNS no
PrintMotd no
PrintLastLog yes

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
SyslogFacility AUTH
LogLevel VERBOSE

# -----------------------------------------------------------------------------
# SFTP
# -----------------------------------------------------------------------------
EOF

    # Append sftp path (can't use single-quote heredoc for variable)
    echo "Subsystem sftp internal-sftp -f AUTHPRIV -l INFO" >> "$CONFIG_FILE"

    chmod 644 "$CONFIG_FILE"
    mkdir -p /run/sshd
    chmod 755 /run/sshd

    log_success "SSH configuration written"
}

configure_firewall() {
    log_step "Configuring firewall"
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-service=ssh &>/dev/null || true
        firewall-cmd --reload &>/dev/null || true
        log_info "firewalld configured for SSH"
    elif command -v ufw &>/dev/null; then
        ufw allow ssh &>/dev/null || true
        log_info "ufw configured for SSH"
    else
        log_warn "No firewall detected — ensure port 22 is accessible"
    fi
    log_success "Firewall done"
}

test_configuration() {
    log_step "Testing SSH configuration"
    if sshd -t 2>/dev/null; then
        log_success "Configuration syntax valid"
    else
        log_error "Configuration has syntax errors:"
        sshd -t
        return 1
    fi
}

show_summary() {
    local ssh_version
    ssh_version=$(sshd -V 2>&1 | grep -o 'OpenSSH_[^ ]*' || echo "unknown")

    echo
    echo -e "${BOLD}Summary${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}✓${NC} $ssh_version installed"
    echo -e "${GREEN}✓${NC} Ed25519-only host key"
    echo -e "${GREEN}✓${NC} Password authentication disabled"
    echo -e "${GREEN}✓${NC} FUTURE crypto policy compatible"
    echo -e "${GREEN}✓${NC} All forwarding disabled"
    echo -e "${GREEN}✓${NC} CVE mitigations applied"
    systemctl is-active --quiet "$SSH_SERVICE" \
        && echo -e "${GREEN}✓${NC} sshd running" \
        || echo -e "${YELLOW}!${NC} sshd not running"
    echo
    echo -e "${BOLD}Next steps${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "1. Add your public key:  ${BLUE}ssh-copy-id user@host${NC}"
    echo -e "2. Test login:           ${BLUE}ssh user@$(hostname -I | awk '{print $1}')${NC}"
    echo -e "3. Store key in:         ${BLUE}Bitwarden SSH Agent${NC}"
    echo -e "4. On Fedora/RHEL:       ${BLUE}sudo update-crypto-policies --set FUTURE${NC}"
    echo
    echo -e "${YELLOW}Emergency password access:${NC}"
    echo -e "Uncomment ${BLUE}PasswordAuthentication yes${NC} in $CONFIG_FILE"
    echo -e "then ${BLUE}sudo systemctl restart $SSH_SERVICE${NC} — fix keys — re-disable."
    echo
}

install() {
    if [[ -n "${SSH_CONNECTION:-}" ]] && [[ "${FORCE_SSH_INSTALL:-}" != "1" ]]; then
        log_error "Running in SSH session — this will modify SSH config."
        log_warn "Use tmux/screen, or: FORCE_SSH_INSTALL=1 $0 install"
        exit 1
    fi

    if [[ "${CONFIRM:-}" != "yes" ]]; then
        if [[ -t 0 ]]; then
            read -rp "Install hardened OpenSSH? This disables password auth. [y/N] " answer
            [[ "${answer,,}" != "y" ]] && { log_error "Cancelled"; exit 0; }
        else
            log_error "Non-interactive: use CONFIRM=yes $0 install"
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
    systemctl enable "$SSH_SERVICE"
    systemctl restart "$SSH_SERVICE"
    show_summary
    log_success "Done!"
}

remove() {
    check_root

    if [[ "${CONFIRM:-}" != "yes" ]]; then
        if [[ -t 0 ]]; then
            read -rp "Remove OpenSSH server? [y/N] " answer
            [[ "${answer,,}" != "y" ]] && { log_error "Cancelled"; exit 0; }
        else
            log_error "Non-interactive: use CONFIRM=yes $0 remove"
            exit 0
        fi
    fi

    systemctl is-active --quiet "$SSH_SERVICE" && systemctl stop "$SSH_SERVICE" || true
    systemctl is-enabled --quiet "$SSH_SERVICE" && systemctl disable "$SSH_SERVICE" || true
    [ -f "$ORIGINAL_CONFIG" ] && cp "$ORIGINAL_CONFIG" "$CONFIG_FILE" && log_info "Original config restored"

    command -v apt-get &>/dev/null && apt-get remove -y openssh-server &>/dev/null || true
    command -v dnf     &>/dev/null && dnf remove -y openssh-server &>/dev/null || true
    command -v yum     &>/dev/null && yum remove -y openssh-server &>/dev/null || true

    log_success "OpenSSH removed. Backup: $BACKUP_DIR"
}

verify() {
    local issues=0

    command -v sshd &>/dev/null \
        && log_success "sshd found: $(sshd -V 2>&1 | grep -o 'OpenSSH_[^ ]*')" \
        || { log_error "sshd not found"; ((issues++)); }

    [ -f "$CONFIG_FILE" ] && sshd -t 2>/dev/null \
        && log_success "Config syntax valid" \
        || { log_error "Config invalid or missing"; ((issues++)); }

    systemctl is-active --quiet  "$SSH_SERVICE" && log_success "sshd running"  || log_warn "sshd not running"
    systemctl is-enabled --quiet "$SSH_SERVICE" && log_success "sshd enabled"  || log_warn "sshd not enabled"

    for key in /etc/ssh/ssh_host_*_key; do
        [ -f "$key" ] && log_success "Host key: $(ssh-keygen -lf "$key" 2>/dev/null)"
    done

    ss -tlnp | grep -q :22 && log_success "Listening on :22" || log_warn "Not listening on :22"

    [ $issues -eq 0 ] && log_success "Verification passed" || { log_error "$issues issue(s) found"; return 1; }
}

main() {
    case "${1:-help}" in
        install) install ;;
        remove)  remove  ;;
        verify)  verify  ;;
        *)
            echo
            echo -e "${BOLD}OpenSSH Hardened Configuration Installer${NC}"
            echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "Usage: $0 {install|remove|verify}"
            echo
            echo "  install   Install OpenSSH with hardened config (no password auth)"
            echo "  remove    Remove OpenSSH and restore original config"
            echo "  verify    Verify installation and config"
            echo
            echo "Env vars:"
            echo "  CONFIRM=yes          Skip confirmation prompt"
            echo "  FORCE_SSH_INSTALL=1  Allow running over SSH (risky)"
            echo
            ;;
    esac
}

main "$@"
