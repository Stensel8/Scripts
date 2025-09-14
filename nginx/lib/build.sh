# Build functions for NGINX installer

# Show log tail helper
show_log_tail() {
    local f="$1"
    local n="${2:-100}"
    [ -f "$f" ] || return 0
    log_info "Last ${n} lines of $(basename "$f"):"
    tail -n "$n" "$f" || true
}

# Build OpenSSL from source
build_openssl() {
    log_step "Building OpenSSL ${OPENSSL_VERSION}"
    
    cd "$BUILD_DIR/openssl-${OPENSSL_VERSION}" || exit 1
    
    local openssl_target
    openssl_target=$(detect_openssl_target)

    ./Configure "$openssl_target" \
        --prefix="$BUILD_DIR/openssl-install" \
        --openssldir="$BUILD_DIR/openssl-install/ssl" \
        enable-tls1_3 \
        no-shared \
        no-tests \
        -fPIC \
        -O3 &>"$LOG_DIR/openssl-configure.log" || {
            log_error "OpenSSL configure failed"
            show_log_tail "$LOG_DIR/openssl-configure.log" 80
            exit 1
        }

    make -j"$(num_procs)" &>"$LOG_DIR/openssl-make.log" || {
        log_error "OpenSSL make failed"
        show_log_tail "$LOG_DIR/openssl-make.log" 80
        exit 1
    }
    
    make install_sw &>"$LOG_DIR/openssl-install.log" || {
        log_error "OpenSSL install failed"
        show_log_tail "$LOG_DIR/openssl-install.log" 80
        exit 1
    }

    log_success "OpenSSL built successfully"
    cd "$BUILD_DIR" || exit 1
}

# Configure and build NGINX
build_nginx() {
    log_step "Configuring NGINX ${NGINX_VERSION}"
    
    cd "$BUILD_DIR/nginx-${NGINX_VERSION}" || exit 1
    
    # Set build flags
    export CFLAGS="-I${BUILD_DIR}/openssl-install/include -O3"
    export LDFLAGS="-L${BUILD_DIR}/openssl-install/lib64 -L${BUILD_DIR}/openssl-install/lib"
    
    # Get base configure args
    local configure_args_base=($(get_base_configure_args))
    
    # Add optional modules
    local configure_args_dynamic=("${configure_args_base[@]}")
    add_optional_modules configure_args_dynamic
    
    # Prepare static fallback for zstd
    local configure_args_static=("${configure_args_base[@]}")
    add_optional_modules configure_args_static "static"
    
    # Find configure script
    local cfg_cmd
    if [ -x "./configure" ]; then
        cfg_cmd=("./configure")
    elif [ -f "auto/configure" ]; then
        cfg_cmd=("bash" "auto/configure")
    else
        log_error "No configure script found in nginx source tree"
        exit 1
    fi

    # Try dynamic build first, fallback to static if needed
    if run_configure_make "dynamic" "${cfg_cmd[@]}" "${configure_args_dynamic[@]}"; then
        ZSTD_BUILD_MODE="dynamic"
        log_success "NGINX built successfully"
    else
        attempt_static_fallback "${cfg_cmd[@]}" "${configure_args_static[@]}"
    fi
}

# Get base NGINX configure arguments
get_base_configure_args() {
    local args=(
        --prefix="$PREFIX"
        --sbin-path=/usr/sbin/nginx
        --conf-path=/etc/nginx/nginx.conf
        --error-log-path=/var/log/nginx/error.log
        --http-log-path=/var/log/nginx/access.log
        --pid-path=/run/nginx.pid
        --lock-path=/run/nginx.lock
        --http-client-body-temp-path=/var/cache/nginx/client_temp
        --http-proxy-temp-path=/var/cache/nginx/proxy_temp
        --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp
        --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp
        --http-scgi-temp-path=/var/cache/nginx/scgi_temp
        --user=nginx
        --group=nginx
        --with-openssl="$BUILD_DIR/openssl-${OPENSSL_VERSION}"
        --with-pcre="$BUILD_DIR/pcre2-${PCRE2_VERSION}"
        --with-pcre-jit
        --with-zlib="$BUILD_DIR/zlib-${ZLIB_VERSION}"
        --with-compat
        --with-file-aio
        --with-threads
        --with-http_addition_module
        --with-http_auth_request_module
        --with-http_dav_module
        --with-http_flv_module
        --with-http_gunzip_module
        --with-http_gzip_static_module
        --with-http_mp4_module
        --with-http_random_index_module
        --with-http_realip_module
        --with-http_secure_link_module
        --with-http_slice_module
        --with-http_ssl_module
        --with-http_stub_status_module
        --with-http_sub_module
        --with-http_v2_module
        --with-http_v3_module
        --with-ld-opt="$LDFLAGS"
    )

    # Add stream support if enabled
    if is_enabled ENABLE_STREAM auto; then
        args+=(
            --with-stream
            --with-stream_ssl_module
            --with-stream_realip_module
            --with-stream_ssl_preread_module
        )
    fi
    
    printf '%s\n' "${args[@]}"
}

# Add optional modules to configure args
add_optional_modules() {
    local -n args_ref=$1
    local mode="${2:-dynamic}"
    
    if is_enabled ENABLE_HEADERS_MORE auto && [ -d "$BUILD_DIR/headers-more-module" ]; then
        args_ref+=(--add-dynamic-module="$BUILD_DIR/headers-more-module")
    fi
    
    if is_enabled ENABLE_ZSTD auto && [ -d "$BUILD_DIR/zstd-module" ]; then
        if [ "$mode" = "static" ]; then
            args_ref+=(--add-module="$BUILD_DIR/zstd-module")
        else
            args_ref+=(--add-dynamic-module="$BUILD_DIR/zstd-module")
        fi
    fi
}

# Run configure and make
run_configure_make() {
    local mode="$1"; shift
    local -a cmd=("$@")
    
    : >"$LOG_DIR/nginx-configure.log"
    : >"$LOG_DIR/nginx-build.log"
    
    "${cmd[@]}" &>"$LOG_DIR/nginx-configure.log" || return 2
    log_step "Building NGINX (${mode})"
    
    if ! make -j"$(num_procs)" &>"$LOG_DIR/nginx-build.log"; then
        return 3
    fi
    return 0
}

# Attempt static fallback for zstd
attempt_static_fallback() {
    local -a cmd=("$@")
    local cfg_rc=$?
    
    if [ $cfg_rc -eq 2 ]; then
        log_error "NGINX configuration failed"
        show_log_tail "$LOG_DIR/nginx-configure.log" 100
        exit 1
    fi
    
    # Check if it's zstd -fPIC issue
    if is_enabled ENABLE_ZSTD auto && grep -qE "recompile with -fPIC|ngx_http_zstd_.*\.so" "$LOG_DIR/nginx-build.log"; then
        log_warn "Zstd dynamic module failed to link (-fPIC). Falling back to static module build."
        make clean >/dev/null 2>&1 || true
        
        if run_configure_make "static-zstd" "${cmd[@]}"; then
            ZSTD_BUILD_MODE="static"
            log_success "NGINX built successfully with static Zstd module"
        else
            log_error "NGINX build failed after zstd static fallback"
            show_log_tail "$LOG_DIR/nginx-build.log" 200
            exit 1
        fi
    else
        log_error "NGINX build failed"
        show_log_tail "$LOG_DIR/nginx-build.log" 200
        exit 1
    fi
}
