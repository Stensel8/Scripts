#!/bin/bash
#
# Kubernetes (kubectl) Installer Script
#
# Installs kubectl on Debian/Ubuntu (apt) and RHEL/Fedora/CentOS (dnf).
# Optionally installs minikube.
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

LOG_FILE="/tmp/kubernetes_install_$(date +%Y%m%d_%H%M%S).log"

# === Logging ===
info()    { echo -e "${BLUE}[INFO]${NC} $1"    | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"  | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"    | tee -a "$LOG_FILE"; exit 1; }

run() {
    info "Executing: $*"
    "$@" >> "$LOG_FILE" 2>&1 || error "Command failed: '$*'. Check log: $LOG_FILE"
}

# === Root check ===
[ "$EUID" -ne 0 ] && error "Run as root (sudo)."

# === Settings ===
K8S_VERSION="${K8S_VERSION:-v1.32}"
APT_BASE_URL="https://pkgs.k8s.io/core:/stable:/${K8S_VERSION}/deb/"
RPM_BASE_URL="https://pkgs.k8s.io/core:/stable:/${K8S_VERSION}/rpm/"

# === kubectl already installed? ===
if command -v kubectl &>/dev/null; then
    warn "kubectl is already installed: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"
    exit 0
fi

info "Installing kubectl ${K8S_VERSION}..."

# === Install kubectl ===
if command -v apt-get &>/dev/null; then
    info "APT-based system detected."

    run apt-get update -y
    run apt-get install -y apt-transport-https ca-certificates curl gnupg

    mkdir -p -m 755 /etc/apt/keyrings
    curl -fsSL "${APT_BASE_URL}Release.key" | \
        gpg --dearmour -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg 2>>"$LOG_FILE" || \
        error "Failed to download Kubernetes signing key."
    chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg

    echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] ${APT_BASE_URL} /" \
        > /etc/apt/sources.list.d/kubernetes.list
    chmod 644 /etc/apt/sources.list.d/kubernetes.list

    run apt-get update -y
    run apt-get install -y kubectl

elif command -v dnf &>/dev/null; then
    info "DNF-based system detected."

    cat > /etc/yum.repos.d/kubernetes.repo <<EOF
[kubernetes]
name=Kubernetes
baseurl=${RPM_BASE_URL}
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=${RPM_BASE_URL}repodata/repomd.xml.key
exclude=kube*
EOF

    run dnf install -y kubectl --disableexcludes=kubernetes

else
    error "Unsupported system. Only Debian/Ubuntu (apt) and RHEL/Fedora/CentOS (dnf) are supported."
fi

success "kubectl installed: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"

# === Minikube (optional) ===
echo ""
read -rp "Install minikube as well? (y/n): " install_minikube
if [[ "$install_minikube" == "y" ]]; then
    info "Installing minikube..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  MINIKUBE_BIN="minikube-linux-amd64" ;;
        aarch64) MINIKUBE_BIN="minikube-linux-arm64" ;;
        *)       error "Unsupported architecture for minikube: ${ARCH}" ;;
    esac

    curl -LO "https://github.com/kubernetes/minikube/releases/latest/download/${MINIKUBE_BIN}" \
        2>>"$LOG_FILE" || error "Failed to download minikube."
    install "${MINIKUBE_BIN}" /usr/local/bin/minikube
    rm -f "${MINIKUBE_BIN}"
    success "minikube installed: $(minikube version --short 2>/dev/null)"
fi

# === Summary ===
KUBECTL_VER=$(kubectl version --client --short 2>/dev/null || kubectl version --client)

echo -e "\n${GREEN}==============================================================${NC}"
success "Kubernetes installation complete!"
echo -e "${GREEN}==============================================================${NC}\n"
echo -e "${BLUE}kubectl:${NC}      ${GREEN}${KUBECTL_VER}${NC}"
echo -e "${BLUE}Log:${NC}          ${GREEN}${LOG_FILE}${NC}"
echo ""
echo -e "${BLUE}Verify:${NC}       kubectl version --client"
echo -e "${BLUE}Cluster:${NC}      kubectl cluster-info"
