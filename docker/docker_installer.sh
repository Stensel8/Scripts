#!/usr/bin/env bash
#
# Docker Installer Script
#
# Installs Docker CE on Debian/Ubuntu (apt) and RHEL/Fedora/CentOS (dnf),
# and Docker from the community repos on Arch Linux (pacman).
# Falls back to get.docker.com on failure (disable with DOCKER_FALLBACK=0).
# Run as root.
#

set -euo pipefail

# ============================================================================
# Common Helper Functions
# The same helpers are used in every bash script in this repo, so the
# scripts stay consistent while remaining standalone single-file downloads.
# Function names follow the PowerShell Verb-Noun convention.
# ============================================================================

# shellcheck disable=SC2034  # not every script uses every color
readonly RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' \
         BLUE='\033[0;34m' PURPLE='\033[0;35m' BOLD='\033[1m' NC='\033[0m'

# Optional plain-text logfile; set LOG_FILE after this block to enable.
LOG_FILE="${LOG_FILE:-}"

# Usage: Write-Log <INFO|SUCCESS|WARN|ERROR|STEP> "message"
Write-Log() {
    local level=$1; shift
    local color=$NC
    case $level in
        INFO)    color=$BLUE ;;
        SUCCESS) color=$GREEN ;;
        WARN)    color=$YELLOW ;;
        ERROR)   color=$RED ;;
        STEP)    color=$PURPLE ;;
    esac
    if [[ $level == ERROR ]]; then
        echo -e "${color}[$level]${NC} $*" >&2
    else
        echo -e "${color}[$level]${NC} $*"
    fi
    if [[ -n "$LOG_FILE" ]]; then
        echo "[$level] $*" >> "$LOG_FILE"
    fi
}

# Usage: Stop-Script "fatal message"
Stop-Script() {
    Write-Log ERROR "$1"
    exit 1
}

# Usage: Test-Root  (exits unless running as root)
Test-Root() {
    [[ $EUID -eq 0 ]] || Stop-Script "Run as root (sudo)."
}

# Usage: mgr=$(Get-PkgMgr)  ->  apt | dnf | pacman | unknown
Get-PkgMgr() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# Usage: os_id=$(Get-OsId)  ->  lowercase /etc/os-release ID (ubuntu, debian,
# fedora, arch, ...) or "unknown". Call in $(...) so sourcing stays contained.
Get-OsId() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        local os_id="${ID:-unknown}"
        echo "${os_id,,}"
    else
        echo "unknown"
    fi
}

# Usage: Invoke-Cmd command [args...]
# Logs the command, sends its output to LOG_FILE when set, aborts on failure.
Invoke-Cmd() {
    Write-Log INFO "Executing: $*"
    if [[ -n "$LOG_FILE" ]]; then
        "$@" >> "$LOG_FILE" 2>&1 || Stop-Script "Command failed: '$*'. Check log: $LOG_FILE"
    else
        "$@" || Stop-Script "Command failed: '$*'"
    fi
}

# === Settings ===
LOG_FILE="/tmp/docker_install_$(date +%Y%m%d_%H%M%S).log"
CODENAME=""

# === Fallback ===
Invoke-FallbackInstaller() {
    if [[ "${DOCKER_FALLBACK:-1}" != "1" ]]; then
        Stop-Script "Installation failed and fallback is disabled (DOCKER_FALLBACK=0)."
    fi
    Write-Log WARN "Installation failed. Falling back to get.docker.com..."
    Write-Log WARN "This runs an unverified convenience script from get.docker.com."
    curl -fsSL https://get.docker.com | bash || Stop-Script "Fallback installer also failed."
    exit 0
}
trap 'Invoke-FallbackInstaller' ERR

# === Root check ===
Test-Root

# === Docker already installed? ===
if command -v docker &>/dev/null; then
    Write-Log WARN "Docker is already installed. Skipping."
    docker --version
    exit 0
fi

# === Detect distro ===
DISTRO=$(Get-OsId)
[[ "$DISTRO" != "unknown" ]] || Stop-Script "Cannot read /etc/os-release. Unsupported system."
Write-Log INFO "Detected distribution: ${DISTRO}"

# === Install ===
case "$DISTRO" in
    ubuntu|debian)
        Write-Log INFO "APT-based system: ${DISTRO}"

        if command -v lsb_release &>/dev/null; then
            CODENAME=$(lsb_release -cs)
        else
            CODENAME=$(grep VERSION_CODENAME /etc/os-release | cut -d'=' -f2)
        fi
        Write-Log INFO "Codename: ${CODENAME}"

        # Remove any broken/stale repo entry and GPG key from earlier attempts
        Write-Log INFO "Cleaning up stale Docker repo entries..."
        rm -f /etc/apt/sources.list.d/docker.list
        rm -f /etc/apt/keyrings/docker.gpg

        Invoke-Cmd apt-get update -y
        Invoke-Cmd apt-get install -y ca-certificates curl gnupg

        mkdir -p /etc/apt/keyrings
        curl -fsSL "https://download.docker.com/linux/${DISTRO}/gpg" | \
            gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>>"$LOG_FILE" || \
            Stop-Script "Failed to add Docker GPG key."
        chmod a+r /etc/apt/keyrings/docker.gpg

        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${DISTRO} ${CODENAME} stable" \
            > /etc/apt/sources.list.d/docker.list

        Invoke-Cmd apt-get update -y
        Invoke-Cmd apt-get install -y docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin
        ;;

    fedora|rhel|centos)
        Write-Log INFO "DNF-based system: ${DISTRO}"
        command -v dnf &>/dev/null || Stop-Script "dnf not found. Only dnf is supported for ${DISTRO}."

        Invoke-Cmd dnf install -y dnf-plugins-core
        rm -f /etc/yum.repos.d/docker-ce.repo

        Invoke-Cmd dnf config-manager addrepo \
            --from-repofile="https://download.docker.com/linux/${DISTRO}/docker-ce.repo"

        Invoke-Cmd dnf install -y docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin
        ;;

    arch)
        Write-Log INFO "Pacman-based system: ${DISTRO}"
        # Docker has no vendor repo for Arch; these are the community packages.
        Invoke-Cmd pacman -Syu --noconfirm docker docker-buildx docker-compose
        ;;

    *)
        Stop-Script "Unsupported distribution: ${DISTRO}. Only Debian/Ubuntu (apt), RHEL/Fedora/CentOS (dnf) and Arch Linux (pacman) are supported."
        ;;
esac

# === Enable & start Docker ===
Write-Log INFO "Enabling and starting Docker service..."
Invoke-Cmd systemctl enable docker
Invoke-Cmd systemctl start docker

# === Summary ===
DOCKER_VER=$(docker --version 2>/dev/null) || DOCKER_VER="N/A"

echo -e "\n${GREEN}==============================================================${NC}"
Write-Log SUCCESS "Docker installation complete!"
echo -e "${GREEN}==============================================================${NC}\n"
echo -e "${BLUE}Docker:${NC}       ${GREEN}${DOCKER_VER}${NC}"
echo -e "${BLUE}Distro:${NC}       ${GREEN}${DISTRO} (${CODENAME:-n/a})${NC}"
echo -e "${BLUE}Log:${NC}          ${GREEN}${LOG_FILE}${NC}"
echo ""
echo -e "${BLUE}Rootless:${NC}     dockerd-rootless-setuptool.sh install"
echo -e "${BLUE}Uninstall:${NC}    sudo apt-get remove docker-ce docker-ce-cli containerd.io  # apt"
echo -e "              sudo dnf remove docker-ce docker-ce-cli containerd.io     # dnf"
echo -e "              sudo pacman -Rns docker docker-buildx docker-compose      # pacman"
