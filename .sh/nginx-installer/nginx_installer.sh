#!/usr/bin/env bash
#########################################################################
# NGINX Installer - Modular Version
# Compiles and installs NGINX with OpenSSL from source
#########################################################################

set -euo pipefail
set -E
umask 022

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load configuration and libraries
source "$SCRIPT_DIR/config/versions.conf"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/download.sh"
source "$SCRIPT_DIR/lib/build.sh"
source "$SCRIPT_DIR/lib/install.sh"
source "$SCRIPT_DIR/lib/service.sh"

# Main function
main() {
    validate_env
    
    case "${1:-help}" in
        install)
            cmd_install
            ;;
        remove)
            check_root
            cmd_remove
            ;;
        verify)
            cmd_verify
            ;;
        *)
            if [ -n "${1-}" ] && [ "${1}" != "help" ]; then
                log_error "Unknown command: '${1}'"
                echo "Valid commands: install | remove | verify"
            fi
            print_usage
            ;;
    esac
}

# Installation command
cmd_install() {
    log_info "Starting NGINX ${NGINX_VERSION} installation with OpenSSL ${OPENSSL_VERSION}"
    
    # Safety checks
    safety_checks
    confirm_or_exit "Proceed with NGINX installation?"
    
    check_root
    print_header
    
    # Installation steps
    backup_existing
    install_dependencies
    require_cmds
    download_sources
    build_openssl
    build_nginx
    install_nginx
    test_configuration
    
    # Start service
    start_nginx_service
    show_summary
    
    log_success "NGINX installation completed successfully!"
}

# Removal command
cmd_remove() {
    log_info "Removing NGINX installation..."
    confirm_or_exit "Remove NGINX installation?"
    
    stop_nginx_service
    remove_nginx_files
    remove_nginx_user
    
    log_success "NGINX installation removed successfully"
}

# Verification command
cmd_verify() {
    log_info "Verifying NGINX installation..."
    
    verify_binary
    verify_config
    verify_service
    verify_modules
    verify_directories
    verify_user
    verify_ports
    
    log_success "NGINX installation verification completed"
}

# Run main function
main "$@"
