# Installation functions for NGINX installer

# Create backup of existing installation
backup_existing() {
    log_step "Creating backup of existing installation"
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup existing NGINX configuration
    if [ -d "/etc/nginx" ]; then
        cp -a /etc/nginx "$BACKUP_DIR/"
        log_info "NGINX configuration backed up to $BACKUP_DIR"
    fi
    
    # Backup existing NGINX binary
    if [ -f "/usr/sbin/nginx" ]; then
        cp /usr/sbin/nginx "$BACKUP_DIR/nginx.sbin"
        log_info "NGINX binary backed up to $BACKUP_DIR/nginx.sbin"
    fi
    
    # Save current NGINX service status
    if has_systemd; then
        if systemctl is-active --quiet nginx &>/dev/null; then
            echo "nginx was active" > "$BACKUP_DIR/service_status.txt"
        else
            echo "nginx was inactive" > "$BACKUP_DIR/service_status.txt"
        fi
    fi
    
    log_success "Backup created successfully"
}

# Install NGINX files and configure system
install_nginx() {
    log_step "Installing NGINX"
    
    # Create nginx user
    create_nginx_user
    
    # Create directories
    create_nginx_directories
    
    # Install NGINX binary
    cd "$BUILD_DIR/nginx-${NGINX_VERSION}" || exit 1
    make install &>"$LOG_DIR/nginx-install.log" || {
        log_error "NGINX installation failed. See $LOG_DIR/nginx-install.log"
        exit 1
    }
    
    # Install dynamic modules
    install_dynamic_modules
    
    # Set permissions
    set_nginx_permissions
    
    # Create configuration files
    create_nginx_config
    
    log_success "NGINX installation completed"
}

# Create nginx user and group
create_nginx_user() {
    if ! id nginx >/dev/null 2>&1; then
        local nologin_shell
        if [ -x /usr/sbin/nologin ]; then
            nologin_shell=/usr/sbin/nologin
        elif [ -x /sbin/nologin ]; then
            nologin_shell=/sbin/nologin
        else
            nologin_shell=/bin/false
        fi
        
        getent group nginx >/dev/null 2>&1 || groupadd --system nginx
        useradd --system --home /var/cache/nginx --no-create-home \
                --shell "$nologin_shell" --gid nginx \
                --comment "nginx user" nginx
        log_info "Created nginx user"
    fi
}

# Create nginx directories
create_nginx_directories() {
    mkdir -p /var/cache/nginx/{client_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp}
    mkdir -p /var/log/nginx
    mkdir -p /etc/nginx/{conf.d,snippets,modules,modules.d,stream.d}
    mkdir -p /usr/share/nginx/html
    
    touch /var/log/nginx/error.log /var/log/nginx/access.log 2>/dev/null || true
}

# Install dynamic modules
install_dynamic_modules() {
    log_info "Installing dynamic modules"
    
    if [ -d "$BUILD_DIR/nginx-${NGINX_VERSION}/objs" ]; then
        if find "$BUILD_DIR/nginx-${NGINX_VERSION}/objs" -maxdepth 1 -type f -name "*.so" | grep -q .; then
            find "$BUILD_DIR/nginx-${NGINX_VERSION}/objs" -maxdepth 1 -type f -name "*.so" -exec cp {} /etc/nginx/modules/ \;
        else
            log_warn "No dynamic modules found in objs directory"
            find "$BUILD_DIR" -type f -name "*.so" -exec cp {} /etc/nginx/modules/ \; 2>/dev/null || true
        fi

        chown root:root /etc/nginx/modules/*.so 2>/dev/null || true
        chmod 0644 /etc/nginx/modules/*.so 2>/dev/null || true

        if ls /etc/nginx/modules/*.so >/dev/null 2>&1; then
            log_success "Dynamic modules installed to /etc/nginx/modules/"
        else
            log_warn "No dynamic module .so files were installed"
        fi
    else
        log_error "NGINX objs directory not found - modules may not be available"
    fi
}

# Set nginx permissions
set_nginx_permissions() {
    # Configs: owned by root, manageable by nginx group
    chown -R root:nginx /etc/nginx
    chmod -R 775 /etc/nginx
    find /etc/nginx -type f -exec chmod 664 {} +

    # Logs: owned by nginx user/group for worker processes
    chown -R nginx:nginx /var/log/nginx
    chmod -R 775 /var/log/nginx
    find /var/log/nginx -type f -exec chmod 664 {} +

    # Cache: owned by nginx user/group for worker processes
    chown -R nginx:nginx /var/cache/nginx
    chmod -R 750 /var/cache/nginx
}

# Create nginx configuration
create_nginx_config() {
    # Load configuration templates
    source "$SCRIPT_DIR/templates/nginx_conf.sh"
    source "$SCRIPT_DIR/templates/html_files.sh"
    
    # Create main config
    create_main_config
    
    # Create snippets
    create_config_snippets
    
    # Create HTML files
    create_html_files
    
    # Create mime.types
    create_mime_types_file
    
    # Setup module loaders
    setup_module_loaders
    
    # Create optional configs
    create_optional_configs
}

# Create mime.types file
create_mime_types_file() {
    local src="$BUILD_DIR/nginx-${NGINX_VERSION}/conf/mime.types"
    if [ -f "$src" ]; then
        /usr/bin/install -D -m 0644 "$src" /etc/nginx/mime.types
        log_success "Installed mime.types from NGINX source"
    else
        cat > /etc/nginx/mime.types << 'EOF'
types { 
    text/html html htm shtml; 
    text/plain txt; 
    application/json json; 
    application/javascript js; 
    text/css css; 
    image/png png; 
    image/jpeg jpeg jpg; 
    image/svg+xml svg; 
}
EOF
        chmod 0644 /etc/nginx/mime.types || true
        log_warn "Using minimal fallback mime.types (source file not found)"
    fi
}

# Setup module loaders
setup_module_loaders() {
    # Headers-more module
    if is_enabled ENABLE_HEADERS_MORE auto; then
        write_module_loader_conf \
            "/etc/nginx/modules/ngx_http_headers_more_filter_module.so" \
            "headers_more.conf"
    else
        rm -f /etc/nginx/modules.d/headers_more.conf 2>/dev/null || true
    fi

    # Zstd modules
    if is_enabled ENABLE_ZSTD auto; then
        if [ "$ZSTD_BUILD_MODE" = "dynamic" ]; then
            write_module_loader_conf "/etc/nginx/modules/ngx_http_zstd_filter_module.so" "zstd_filter.conf"
            write_module_loader_conf "/etc/nginx/modules/ngx_http_zstd_static_module.so" "zstd_static.conf"
        else
            log_info "Zstd compiled statically; no loader needed"
            rm -f /etc/nginx/modules.d/zstd_*.conf 2>/dev/null || true
        fi
    else
        log_info "Zstd disabled via ENABLE_ZSTD"
        rm -f /etc/nginx/modules.d/zstd_*.conf 2>/dev/null || true
    fi
}

# Write module loader configuration
write_module_loader_conf() {
    local so_path="$1"
    local conf_name="$2"

    if [ -f "$so_path" ]; then
        cat > "/etc/nginx/modules.d/$conf_name" <<EOF
load_module $so_path;
EOF
        chmod 0644 "/etc/nginx/modules.d/$conf_name" || true
        log_success "Enabled module loader: /etc/nginx/modules.d/$conf_name"
    else
        log_warn "Module .so not found, skipping: $so_path"
    fi
}

# Create optional configurations
create_optional_configs() {
    # Zstd configuration
    if is_enabled ENABLE_ZSTD auto; then
        if [ -f /etc/nginx/modules/ngx_http_zstd_filter_module.so ] || \
           [ -f /etc/nginx/modules.d/zstd_filter.conf ] || \
           nginx -V 2>&1 | grep -qE "--add-(dynamic-)?module=.*zstd-module"; then
            
            cat > /etc/nginx/snippets/zstd.conf << 'EOF'
# Zstd compression configuration
zstd on;
zstd_comp_level 7;
zstd_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;
EOF
            chmod 0644 /etc/nginx/snippets/zstd.conf || true
            log_success "Enabled Zstandard HTTP config: /etc/nginx/snippets/zstd.conf"
            
            # Remove legacy configs
            rm -f /etc/nginx/conf.d/zstd.conf 2>/dev/null || true
        else
            log_warn "Zstd module not present; skipping snippets/zstd.conf"
        fi
    else
        rm -f /etc/nginx/snippets/zstd.conf /etc/nginx/conf.d/zstd.conf 2>/dev/null || true
        log_info "Zstd disabled; removed zstd.conf if it existed"
    fi
}

# Remove NGINX files
remove_nginx_files() {
    log_info "Removing NGINX files..."
    
    rm -rf "$PREFIX"
    rm -f /usr/sbin/nginx
    rm -rf /etc/nginx
    rm -rf /var/log/nginx
    rm -rf /var/cache/nginx
    rm -rf /usr/share/nginx
    
    log_success "NGINX files removed"
}

# Remove nginx user
remove_nginx_user() {
    if id nginx >/dev/null 2>&1; then
        userdel nginx 2>/dev/null || true
        log_info "Removed nginx user"
    fi
}
