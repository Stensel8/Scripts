
#!/usr/bin/env bash
# Podman Installer Script (standalone)
# https://podman.io/docs/installation

set -euo pipefail

# Color definitions
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_step() { echo -e "${BOLD}$1${NC}"; }
die() { log_error "$1"; exit 1; }

usage() {
	echo "Usage: $0 [install|remove]"
	exit 1
}

install_podman() {
	log_step "Installing Podman..."
	if command -v podman &>/dev/null; then
		log_success "Podman is already installed."
		return 0
	fi
	if [ -f /etc/os-release ]; then
		. /etc/os-release
		case "$ID" in
			ubuntu|debian)
				log_info "Detected $ID. Installing via apt."
				sudo apt-get update
				sudo apt-get install -y podman
				;;
			fedora)
				log_info "Detected Fedora. Installing via dnf."
				sudo dnf -y install podman
				;;
			centos|rhel)
				log_info "Detected $ID. Installing via yum."
				sudo yum -y install podman
				;;
			arch)
				log_info "Detected Arch Linux. Installing via pacman."
				sudo pacman -Sy --noconfirm podman
				;;
			*)
				die "Unsupported OS: $ID. Please install Podman manually."
				;;
		esac
	else
		die "Cannot detect OS. Please install Podman manually."
	fi
	log_success "Podman installation complete."
}

remove_podman() {
	log_step "Removing Podman..."
	if ! command -v podman &>/dev/null; then
		log_warn "Podman is not installed."
		return 0
	fi
	if [ -f /etc/os-release ]; then
		. /etc/os-release
		case "$ID" in
			ubuntu|debian)
				sudo apt-get remove -y podman
				;;
			fedora)
				sudo dnf -y remove podman
				;;
			centos|rhel)
				sudo yum -y remove podman
				;;
			arch)
				sudo pacman -Rns --noconfirm podman
				;;
			*)
				die "Unsupported OS: $ID. Please remove Podman manually."
				;;
		esac
	else
		die "Cannot detect OS. Please remove Podman manually."
	fi
	log_success "Podman removal complete."
}

main() {
	if [ $# -ne 1 ]; then
		usage
	fi
	case "$1" in
		install)
			install_podman
			;;
		remove)
			remove_podman
			;;
		*)
			usage
			;;
	esac
}

main "$@"
