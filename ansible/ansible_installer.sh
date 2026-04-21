#!/bin/bash
#
# Ansible Installer Script
#
# Installs Ansible 13.5.0 (with its bundled ansible-core dependency) in a Python 3.14 virtual environment.
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
REQ_PYTHON_VERSION="${REQ_PYTHON_VERSION:-3.14}"
BUILD_PYTHON_VERSION="${BUILD_PYTHON_VERSION:-3.14.3}"
VENV_DIR="${VENV_DIR:-/opt/ansible-env}"
FORCE_BUILD="${FORCE_BUILD:-false}"
SKIP_BUILD="${SKIP_BUILD:-false}"

LOG_FILE="/tmp/ansible_install_$(date +%Y%m%d_%H%M%S).log"

PY_BUILD_TARBALL="Python-${BUILD_PYTHON_VERSION}.tgz"
PY_BUILD_URL="https://www.python.org/ftp/python/${BUILD_PYTHON_VERSION}/${PY_BUILD_TARBALL}"
PY_BUILD_SRC_DIR="/usr/src/Python-${BUILD_PYTHON_VERSION}"
PY_CMD=""

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
    apt)
        run env DEBIAN_FRONTEND=noninteractive apt update -y
        run env DEBIAN_FRONTEND=noninteractive apt upgrade -y
        ;;
    dnf)
        run dnf upgrade -y
        ;;
esac

# === Install build dependencies ===
info "Installing build dependencies..."
case $PKG_MANAGER in
    apt)
        APT_DEPS="build-essential libssl-dev zlib1g-dev libncurses5-dev libffi-dev \
            libsqlite3-dev libbz2-dev libreadline-dev liblzma-dev make git wget curl \
            python3-pip python3-venv software-properties-common"
        apt-cache show libmpdec-dev &>/dev/null && APT_DEPS+=" libmpdec-dev"
        run apt install -y $APT_DEPS
        ;;
    dnf)
        run dnf install -y gcc openssl-devel bzip2-devel libffi-devel zlib-devel \
            ncurses-devel sqlite-devel xz-devel readline-devel make git wget curl \
            mpdecimal-devel python3-pip python3-virtualenv
        ;;
esac

# === Find or install Python ===
info "Looking for Python ${REQ_PYTHON_VERSION}..."
if command -v "python${REQ_PYTHON_VERSION}" &>/dev/null; then
    PY_CMD="python${REQ_PYTHON_VERSION}"
    info "Found system Python: ${PY_CMD}"
elif [ "$PKG_MANAGER" = "apt" ] && [ "$FORCE_BUILD" = false ]; then
    info "Trying deadsnakes PPA for Python ${REQ_PYTHON_VERSION}..."
    if command -v add-apt-repository &>/dev/null; then
        run add-apt-repository -y ppa:deadsnakes/ppa
        run apt update -y
        run apt install -y "python${REQ_PYTHON_VERSION}" "python${REQ_PYTHON_VERSION}-venv" || \
            warn "Failed to install python${REQ_PYTHON_VERSION} from PPA."
    else
        warn "'add-apt-repository' not found, skipping PPA."
    fi
    command -v "python${REQ_PYTHON_VERSION}" &>/dev/null && PY_CMD="python${REQ_PYTHON_VERSION}"
fi

# === Build Python from source if needed ===
if [ -z "$PY_CMD" ] && [ "$SKIP_BUILD" = false ]; then
    info "Building Python ${BUILD_PYTHON_VERSION} from source..."
    TARGET_PY_BIN="/usr/local/bin/python${BUILD_PYTHON_VERSION%.*}"
    if [ -x "$TARGET_PY_BIN" ] && [ "$FORCE_BUILD" = false ]; then
        PY_CMD="$TARGET_PY_BIN"
    else
        cd /usr/src
        if [ ! -f "$PY_BUILD_TARBALL" ]; then
            run wget -q "$PY_BUILD_URL"
        fi
        [ -d "$PY_BUILD_SRC_DIR" ] && rm -rf "$PY_BUILD_SRC_DIR"
        run tar -xzf "$PY_BUILD_TARBALL"
        cd "$PY_BUILD_SRC_DIR"
        run ./configure --enable-optimizations --with-system-libmpdec --prefix=/usr/local
        run make -j"$(nproc)"
        run make altinstall
        [ -x "$TARGET_PY_BIN" ] && PY_CMD="$TARGET_PY_BIN" || \
            error "Python build failed."
    fi
elif [ -z "$PY_CMD" ]; then
    error "No suitable Python found. Aborting."
fi

[ -z "$PY_CMD" ] || ! command -v "$PY_CMD" &>/dev/null && \
    error "Python command not usable (PY_CMD='${PY_CMD}')."
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
info "Installing Ansible 13.5.0 (community package, bundles ansible-core~=2.20.4)..."
(
    source "$VENV_DIR/bin/activate"
    command -v pip &>/dev/null || error "pip not found in venv."
    run pip install --upgrade pip setuptools wheel
    run pip install ansible==13.6.0
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
