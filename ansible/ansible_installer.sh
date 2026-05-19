#!/bin/bash
#
# Ansible Installer Script
#
# Installs Ansible (with its bundled ansible-core dependency) in a Python virtual environment.
# Note: 'ansible' is the community package; 'ansible-core' is the engine it ships with.
# Supports Debian/Ubuntu (apt) and RHEL/Fedora (dnf).
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

# === Settings ===
VENV_DIR="${VENV_DIR:-/opt/ansible-env}"

LOG_FILE="/tmp/ansible_install_$(date +%Y%m%d_%H%M%S).log"

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

# === Package manager detection ===
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
else
    error "Unsupported distro. Only Debian/Ubuntu (apt) and RHEL/Fedora (dnf) are supported."
fi
info "Package manager: ${PKG_MANAGER}"

# === Update system packages ===
info "Updating system packages..."
case $PKG_MANAGER in
    apt) run env DEBIAN_FRONTEND=noninteractive apt update -y ;;
    dnf) run dnf upgrade -y ;;
esac

# === Install Python and pip ===
info "Installing Python and pip..."
case $PKG_MANAGER in
    apt) run env DEBIAN_FRONTEND=noninteractive apt install -y python3 python3-venv python3-pip ;;
    dnf) run dnf install -y python3 python3-pip ;;
esac

# === Find Python ===
PY_CMD=$(command -v python3 || true)
[ -z "$PY_CMD" ] && error "python3 not found after install."
info "Using Python: ${PY_CMD} ($("$PY_CMD" --version 2>&1))"

# === Create virtual environment ===
if [ -d "$VENV_DIR" ]; then
    info "Virtual environment already exists at ${VENV_DIR}."
else
    info "Creating virtual environment at ${VENV_DIR}..."
    mkdir -p "$(dirname "$VENV_DIR")"
    run "$PY_CMD" -m venv "$VENV_DIR"
fi

# === Install Ansible ===
info "Installing Ansible (community package, bundles ansible-core)..."
(
    source "$VENV_DIR/bin/activate"
    command -v pip &>/dev/null || error "pip not found in venv."
    run pip install --upgrade pip setuptools wheel
    run pip install ansible==13.7.0
) || error "Failed during venv operations."

# === Global symlinks ===
info "Creating symlinks in /usr/local/bin..."
for tool in ansible ansible-playbook ansible-galaxy ansible-doc ansible-config \
            ansible-console ansible-inventory ansible-vault; do
    if [ -f "$VENV_DIR/bin/$tool" ]; then
        ln -sf "$VENV_DIR/bin/$tool" "/usr/local/bin/$tool"
    else
        warn "${tool} not found in venv, skipping symlink."
    fi
done

# === Global ansible.cfg ===
info "Writing /etc/ansible/ansible.cfg..."
mkdir -p /etc/ansible
VENV_SITE_PACKAGES=$("$VENV_DIR/bin/python" -c "import site; print(site.getsitepackages()[0])")
[ -z "$VENV_SITE_PACKAGES" ] && error "Could not determine venv site-packages."
cat > /etc/ansible/ansible.cfg <<EOF
[defaults]
collections_path = ${VENV_SITE_PACKAGES}/ansible_collections:/usr/share/ansible/collections
EOF
success "Wrote /etc/ansible/ansible.cfg"

# === Summary ===
PY_VER=$("$PY_CMD" --version 2>&1)
ANSIBLE_PKG_VER=$("$VENV_DIR/bin/pip" show ansible 2>/dev/null | grep '^Version:' | cut -d' ' -f2)
[ -n "$ANSIBLE_PKG_VER" ] && ANSIBLE_PKG_VER="ansible ${ANSIBLE_PKG_VER}" || ANSIBLE_PKG_VER="N/A"
ANSIBLE_CORE_VER=$("$VENV_DIR/bin/pip" show ansible-core 2>/dev/null | grep '^Version:' | cut -d' ' -f2)
[ -n "$ANSIBLE_CORE_VER" ] && ANSIBLE_CORE_VER="ansible-core ${ANSIBLE_CORE_VER}" || ANSIBLE_CORE_VER="N/A"

echo -e "\n${GREEN}==============================================================${NC}"
success "Ansible installation complete!"
echo -e "${GREEN}==============================================================${NC}\n"
echo -e "${BLUE}Python:${NC}       ${GREEN}${PY_VER}${NC}"
echo -e "${BLUE}Ansible:${NC}      ${GREEN}${ANSIBLE_PKG_VER}${NC}  (community package)"
echo -e "${BLUE}Core:${NC}         ${GREEN}${ANSIBLE_CORE_VER}${NC}  (engine)"
echo -e "${BLUE}Venv:${NC}         ${GREEN}${VENV_DIR}${NC}"
echo -e "${BLUE}Log:${NC}          ${GREEN}${LOG_FILE}${NC}"
echo ""
echo -e "${BLUE}Activate:${NC}     source ${VENV_DIR}/bin/activate"
echo -e "${BLUE}Uninstall:${NC}    sudo rm -rf ${VENV_DIR} /usr/local/bin/ansible* /etc/ansible"
