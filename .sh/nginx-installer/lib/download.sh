# Download and verification functions for NGINX installer

# Compute SHA256 hash
compute_sha256() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        die "No SHA256 tool available"
    fi
}

# Verify file checksums
verify_checksum() {
    local file="$1"
    local expected_sha="$2"
    local policy="$EFFECTIVE_CHECKSUM_POLICY"
    
    [ -z "$policy" ] && policy="strict"
    policy=$(lc "$policy")
    
    if [ "$policy" = "skip" ]; then
        log_warn "Checksum verification skipped for $file (CHECKSUM_POLICY=skip)"
        return 0
    fi
    
    if [ -z "$expected_sha" ]; then
        if [ "$policy" = "strict" ]; then
            log_error "Missing checksum for $file"
            log_info "Set CHECKSUM_POLICY=allow-missing to proceed without a hash"
            return 1
        else
            log_warn "No checksum available for $file - continuing due to CHECKSUM_POLICY=$policy"
            return 0
        fi
    fi
    
    local actual_sha
    actual_sha=$(compute_sha256 "$file")
    
    if [ "$actual_sha" = "$expected_sha" ]; then
        log_success "Checksum verified for $file"
        return 0
    else
        log_error "Checksum mismatch for $file"
        log_error "Expected: $expected_sha"
        log_error "Actual:   $actual_sha"
        return 1
    fi
}

# Download with fallback URLs
download_with_fallbacks() {
    local id="$1"
    local outfile="$2"
    local urls_csv="$3"
    local log_file="$LOG_DIR/download-${id}.log"
    
    local IFS=','
    local urls=($urls_csv)
    
    : > "$log_file"
    
    for u in "${urls[@]}"; do
        if [ -z "$u" ]; then continue; fi
        
        echo "Attempting to download from: $u" >> "$log_file"
        if curl -LfsS --connect-timeout 15 -o "$outfile" "$u" >>"$log_file" 2>&1; then
            echo "$u"
            return 0
        fi
        echo "Download failed from: $u" >> "$log_file"
    done
    
    log_error "All download attempts failed for ${id}. See log: ${log_file}"
    return 1
}

# Download and extract all sources
download_sources() {
    log_step "Downloading source files"
    
    cd "$BUILD_DIR" || exit 1

    for spec in "${ARTIFACTS[@]}"; do
        IFS='|' read -r id archive sha strip target_dir enabled_flag urls <<< "$spec"
        
        if [ -n "$enabled_flag" ] && ! is_enabled "$enabled_flag" auto; then
            log_info "${id}: disabled via ${enabled_flag}; skipping"
            continue
        fi
        
        log_info "Fetching ${id} from ${urls}"
        if ! src_url=$(download_with_fallbacks "$id" "$archive" "$urls"); then
            log_error "Failed to download ${id} from all sources"
            exit 1
        fi
        
        verify_checksum "$archive" "$sha" || exit 1
        
        # Extract
        if [ "$strip" = "0" ]; then
            tar xf "$archive" || { log_error "Failed to extract ${id}"; exit 1; }
        else
            mkdir -p "$target_dir"
            tar -xzf "$archive" --strip-components="$strip" -C "$target_dir" || { log_error "Failed to extract ${id}"; exit 1; }
        fi
        
        log_success "Downloaded ${id} (${src_url})"
    done

    log_success "Source files downloaded and extracted"
}

# Install system dependencies
install_dependencies() {
    log_step "Installing build dependencies"
    
    pkg_ok() { command -v "$1" &>/dev/null; }
    run_or_fail() { "$@" || { log_error "Package setup failed"; exit 1; }; }

    if pkg_ok apt-get; then
        log_info "Detected Debian/Ubuntu system"
        export DEBIAN_FRONTEND=noninteractive
        run_or_fail apt-get update -qq &>"$LOG_DIR/apt-update.log"
        local apt_pkgs=(build-essential libpcre2-dev zlib1g-dev perl curl gcc make hostname zstd libzstd-dev pkg-config)
        run_or_fail apt-get install -y "${apt_pkgs[@]}" &>"$LOG_DIR/apt-install.log"
    elif pkg_ok dnf; then
        log_info "Detected Fedora/RHEL system"
        if dnf --version 2>/dev/null | grep -q "dnf5"; then
            run_or_fail dnf install -y @development-tools &>"$LOG_DIR/dnf-install.log"
        else
            run_or_fail dnf groupinstall -y "Development Tools" &>"$LOG_DIR/dnf-install.log"
        fi
        local dnf_pkgs=(pcre2-devel zlib-devel perl curl gcc make hostname zstd libzstd libzstd-devel pkgconfig pkgconf-pkg-config)
        run_or_fail dnf install -y "${dnf_pkgs[@]}" &>"$LOG_DIR/dnf-install.log"
    elif pkg_ok yum; then
        log_info "Detected CentOS/RHEL system"
        run_or_fail yum groupinstall -y "Development Tools" &>"$LOG_DIR/yum-install.log"
        local yum_pkgs=(pcre2-devel zlib-devel perl curl gcc make hostname zstd libzstd libzstd-devel pkgconfig pkgconf-pkg-config)
        run_or_fail yum install -y "${yum_pkgs[@]}" &>"$LOG_DIR/yum-install.log"
    else
        log_error "Unsupported package manager. This script requires apt, dnf, or yum."
        exit 1
    fi
    
    log_success "Build dependencies installed"
}
