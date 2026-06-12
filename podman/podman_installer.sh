#!/usr/bin/env bash
#
# Podman Installer Script (standalone)
#
# Installs or removes Podman from the distro repos on Debian/Ubuntu (apt),
# RHEL/Fedora (dnf) and Arch Linux (pacman).
# https://podman.io/docs/installation
# Run as root.
#

set -euo pipefail

# ============================================================================
# BEGIN COMMON BOILERPLATE
# Keep this block byte-identical across all bash scripts in this repo.
# It is verified by .github/scripts/check-boilerplate.sh in CI.
# Function names follow the PowerShell Verb-Noun convention by repo policy.
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

# ============================================================================
# END COMMON BOILERPLATE
# ============================================================================

# === Root check ===
Test-Root

Show-Usage() {
    echo "Usage: $0 [install|remove]"
    exit 1
}

Install-Podman() {
    Write-Log STEP "Installing Podman..."
    if command -v podman &>/dev/null; then
        Write-Log SUCCESS "Podman is already installed."
        return 0
    fi
    case $(Get-PkgMgr) in
        apt)
            Write-Log INFO "APT-based system detected. Installing via apt."
            Invoke-Cmd apt-get update
            Invoke-Cmd apt-get install -y podman
            ;;
        dnf)
            Write-Log INFO "DNF-based system detected. Installing via dnf."
            Invoke-Cmd dnf -y install podman
            ;;
        pacman)
            Write-Log INFO "Pacman-based system detected. Installing via pacman."
            Invoke-Cmd pacman -Sy --noconfirm podman
            ;;
        *)
            Stop-Script "Unsupported system. Please install Podman manually."
            ;;
    esac
    Write-Log SUCCESS "Podman installation complete."
}

Remove-Podman() {
    Write-Log STEP "Removing Podman..."
    if ! command -v podman &>/dev/null; then
        Write-Log WARN "Podman is not installed."
        return 0
    fi
    case $(Get-PkgMgr) in
        apt)
            Invoke-Cmd apt-get remove -y podman
            ;;
        dnf)
            Invoke-Cmd dnf -y remove podman
            ;;
        pacman)
            Invoke-Cmd pacman -Rns --noconfirm podman
            ;;
        *)
            Stop-Script "Unsupported system. Please remove Podman manually."
            ;;
    esac
    Write-Log SUCCESS "Podman removal complete."
}

Invoke-Main() {
    if [[ $# -ne 1 ]]; then
        Show-Usage
    fi
    case "$1" in
        install) Install-Podman ;;
        remove)  Remove-Podman ;;
        *)       Show-Usage ;;
    esac
}

Invoke-Main "$@"
