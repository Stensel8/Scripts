#!/bin/bash
#
# Docker Installer Script
#
# Installs Docker CE on Debian/Ubuntu (apt) and RHEL/Fedora/CentOS (dnf).
# Falls back to get.docker.com on failure.
# Run as root.
#

set -e
set -o pipefail

# === Colors ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG_FILE="/tmp/docker_install_$(date +%Y%m%d_%H%M%S).log"

# === Logging ===
info()    { echo -e "${BLUE}[INFO]${NC} $1"    | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"  | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"    | tee -a "$LOG_FILE"; exit 1; }

run() {
    info "Executing: $*"
    "$@" >> "$LOG_FILE" 2>&1 || error "Command failed: '$*'. Check log: $LOG_FILE"
}

# === Fallback ===
fallback_installer() {
    warn "Installation failed. Falling back to get.docker.com..."
    curl -fsSL https://get.docker.com | bash || error "Fallback installer also failed."
    exit 0
}
trap 'fallback_installer' ERR

# === Root check ===
[ "$EUID" -ne 0 ] && error "Run as root (sudo)."

# === Docker already installed? ===
if command -v docker &>/dev/null; then
    warn "Docker is already installed. Skipping."
    docker --version
    exit 0
fi

# === Detect distro ===
[ -r /etc/os-release ] || error "Cannot read /etc/os-release. Unsupported system."
. /etc/os-release
DISTRO="${ID,,}"
info "Detected distribution: ${DISTRO}"

# === Install ===
case "$DISTRO" in
    ubuntu|debian)
        info "APT-based system: ${DISTRO}"

        if command -v lsb_release &>/dev/null; then
            CODENAME=$(lsb_release -cs)
        else
            CODENAME=$(grep VERSION_CODENAME /etc/os-release | cut -d'=' -f2)
        fi
        info "Codename: ${CODENAME}"

        # Verwijder eventuele kapotte/oude repo entry en GPG key van eerdere pogingen
        info "Cleaning up stale Docker repo entries..."
        rm -f /etc/apt/sources.list.d/docker.list
        rm -f /etc/apt/keyrings/docker.gpg

        run apt-get update -y
        run apt-get install -y ca-certificates curl gnupg

        mkdir -p /etc/apt/keyrings
        curl -fsSL "https://download.docker.com/linux/${DISTRO}/gpg" | \
            gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>>"$LOG_FILE" || \
            error "Failed to add Docker GPG key."
        chmod a+r /etc/apt/keyrings/docker.gpg

        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${DISTRO} ${CODENAME} stable" \
            > /etc/apt/sources.list.d/docker.list

        run apt-get update -y
        run apt-get install -y docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin
        ;;

    fedora|rhel|centos)
        info "DNF-based system: ${DISTRO}"
        command -v dnf &>/dev/null || error "dnf not found. Only dnf is supported for ${DISTRO}."

        run dnf install -y dnf-plugins-core
        rm -f /etc/yum.repos.d/docker-ce.repo

        run dnf config-manager addrepo \
            --from-repofile="https://download.docker.com/linux/${DISTRO}/docker-ce.repo"

        run dnf install -y docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin
        ;;

    *)
        error "Unsupported distribution: ${DISTRO}. Only Debian/Ubuntu and RHEL/Fedora/CentOS are supported."
        ;;
esac

# === Enable & start Docker ===
info "Enabling and starting Docker service..."
run systemctl enable docker
run systemctl start docker

# === Summary ===
DOCKER_VER=$(docker --version 2>/dev/null) || DOCKER_VER="N/A"

echo -e "\n${GREEN}==============================================================${NC}"
success "Docker installation complete!"
echo -e "${GREEN}==============================================================${NC}\n"
echo -e "${BLUE}Docker:${NC}       ${GREEN}${DOCKER_VER}${NC}"
echo -e "${BLUE}Distro:${NC}       ${GREEN}${DISTRO} (${CODENAME})${NC}"
echo -e "${BLUE}Log:${NC}          ${GREEN}${LOG_FILE}${NC}"
echo ""
echo -e "${BLUE}Rootless:${NC}     dockerd-rootless-setuptool.sh install"
echo -e "${BLUE}Uninstall:${NC}    sudo apt-get remove docker-ce docker-ce-cli containerd.io  # apt"
echo -e "              sudo dnf remove docker-ce docker-ce-cli containerd.io     # dnf"
