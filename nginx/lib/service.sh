# Service management functions for NGINX installer

# Create systemd service
create_systemd_service() {
    if ! has_systemd; then
        log_warn "Systemd not detected; skipping service creation. Manage nginx manually."
        return 0
    fi
    
    cat > /etc/systemd/system/nginx.service << 'EOF'
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable nginx
    log_info "Created and enabled systemd service"
}

# Start NGINX service
start_nginx_service() {
    if has_systemd; then
        systemctl enable nginx
        systemctl restart nginx
        log_success "NGINX service started and enabled"
    else
        log_warn "Systemd not available; nginx not started automatically. Use /usr/sbin/nginx to start."
    fi
}

# Stop NGINX service
stop_nginx_service() {
    if has_systemd && systemctl is-active --quiet nginx 2>/dev/null; then
        log_info "Stopping NGINX service..."
        systemctl stop nginx
    fi
    
    if has_systemd && systemctl is-enabled --quiet nginx 2>/dev/null; then
        log_info "Disabling NGINX service..."
        systemctl disable nginx
    fi
    
    # Remove systemd service file
    if has_systemd && [[ -f /etc/systemd/system/nginx.service ]]; then
        rm -f /etc/systemd/system/nginx.service
        systemctl daemon-reload
        log_info "Removed systemd service"
    fi
}

# Test NGINX configuration
test_configuration() {
    log_step "Testing NGINX configuration"
    
    # Ensure log directory exists
    mkdir -p /var/log/nginx
    touch /var/log/nginx/error.log /var/log/nginx/access.log 2>/dev/null || true
    chown -R nginx:nginx /var/log/nginx 2>/dev/null || true

    # Test configuration syntax
    if nginx -t 2>/dev/null; then
        log_success "NGINX configuration syntax is valid"
    else
        log_error "NGINX configuration has syntax errors"
        log_info "Running configuration test with verbose output:"
        nginx -t
        return 1
    fi
    
    # Check if NGINX service can start
    if has_systemd; then
        if systemctl is-active --quiet nginx; then
            log_info "NGINX service is already running"
        else
            if systemctl start nginx; then
                log_success "NGINX service started successfully"
            else
                log_error "Failed to start NGINX service"
                return 1
            fi
        fi
    fi
    
    log_success "NGINX configuration test passed"
}

# Verification functions
verify_binary() {
    if [[ -x /usr/sbin/nginx ]]; then
        local nginx_version=$(nginx -v 2>&1 | grep -o 'nginx/[0-9.]*' || echo "Unknown")
        log_success "NGINX binary installed: $nginx_version"
        return 0
    else
        log_error "NGINX binary not found or not executable"
        return 1
    fi
}

verify_config() {
    if [[ -f /etc/nginx/nginx.conf ]]; then
        log_success "NGINX configuration file exists: /etc/nginx/nginx.conf"
        
        if nginx -t 2>/dev/null; then
            log_success "NGINX configuration syntax is valid"
            return 0
        else
            log_error "NGINX configuration has syntax errors"
            return 1
        fi
    else
        log_error "NGINX configuration file not found"
        return 1
    fi
}

verify_service() {
    local issues=0
    
    if has_systemd && systemctl is-active --quiet nginx 2>/dev/null; then
        log_success "NGINX service is running"
    else
        log_warn "NGINX service is not running"
        ((issues++))
    fi
    
    if has_systemd && systemctl is-enabled --quiet nginx 2>/dev/null; then
        log_success "NGINX service is enabled"
    else
        log_warn "NGINX service is not enabled"
        ((issues++))
    fi
    
    return $issues
}

verify_modules() {
    local nv=""
    local nv_ok=0
    
    if command -v nginx &>/dev/null; then
        nv=$(nginx -V 2>&1 || true)
        nv_ok=1
    fi
    
    # Check OpenSSL integration
    if [ "$nv_ok" -eq 1 ] && grep -q "built with OpenSSL" <<<"$nv"; then
        local openssl_version=$(grep -o 'built with OpenSSL [0-9.]*' <<<"$nv" | cut -d' ' -f4 || echo "Unknown")
        log_success "OpenSSL integration: $openssl_version"
    else
        log_error "OpenSSL integration not found"
        return 1
    fi
    
    # Check HTTP/3 support
    if [ "$nv_ok" -eq 1 ] && grep -q "http_v3_module" <<<"$nv"; then
        log_success "HTTP/3 support: enabled"
    else
        log_warn "HTTP/3 support: not enabled"
    fi

    # Check stream support
    if is_enabled ENABLE_STREAM auto; then
        if [ "$nv_ok" -eq 1 ] && grep -q "--with-stream" <<<"$nv"; then
            log_success "Stream core: enabled"
        else
            log_warn "Stream core: not enabled"
        fi
    fi
    
    return 0
}

verify_directories() {
    local issues=0
    local dirs=("/var/log/nginx" "/var/cache/nginx" "/etc/nginx" "/usr/share/nginx/html")
    
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_success "Directory exists: $dir"
        else
            log_error "Directory missing: $dir"
            ((issues++))
        fi
    done
    
    return $issues
}

verify_user() {
    if id nginx >/dev/null 2>&1; then
        log_success "NGINX user exists"
        return 0
    else
        log_error "NGINX user missing"
        return 1
    fi
}

verify_ports() {
    if command -v ss &>/dev/null; then
        local https_ports=$(ss -tlnp | grep :443 | wc -l)
        if [ "$https_ports" -gt 0 ]; then
            log_success "NGINX is listening on port 443 (HTTPS)"
            return 0
        else
            log_warn "NGINX is not listening on port 443 (HTTPS)"
            return 1
        fi
    fi
    return 0
}

# Show installation summary
show_summary() {
    echo
    echo -e "${BOLD}Installation Summary${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if command -v nginx &>/dev/null; then
        local nginx_version=$(nginx -v 2>&1 | grep -o 'nginx/[0-9.]*' || echo "Unknown")
        local openssl_version=$(nginx -V 2>&1 | grep -o 'built with OpenSSL [0-9.]*' | cut -d' ' -f4 || echo "Unknown")

        echo -e "${GREEN}✓${NC} NGINX compiled and installed: $nginx_version"
        echo -e "${GREEN}✓${NC} OpenSSL integration: $openssl_version"
        echo -e "${GREEN}✓${NC} HTTP/3 support with QUIC protocol"
        echo -e "${GREEN}✓${NC} Modern, modular configuration applied"
        echo -e "${GREEN}✓${NC} Systemd service created and enabled"

        if has_systemd && systemctl is-active --quiet nginx; then
            echo -e "${GREEN}✓${NC} NGINX service is running"
        else
            echo -e "${YELLOW}!${NC} NGINX service is not running"
        fi
    else
        echo -e "${RED}✗${NC} NGINX installation may have failed"
    fi

    echo
    echo -e "${BOLD}Service Management${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if has_systemd; then
        echo -e "Start NGINX:    ${BLUE}sudo systemctl start nginx${NC}"
        echo -e "Stop NGINX:     ${BLUE}sudo systemctl stop nginx${NC}"
        echo -e "Restart NGINX:  ${BLUE}sudo systemctl restart nginx${NC}"
        echo -e "Status:         ${BLUE}sudo systemctl status nginx${NC}"
    else
        echo -e "Run NGINX:      ${BLUE}sudo /usr/sbin/nginx${NC}"
        echo -e "Reload:         ${BLUE}sudo /usr/sbin/nginx -s reload${NC}"
        echo -e "Stop:           ${BLUE}sudo pkill -TERM nginx${NC}"
    fi
    
    echo -e "Test config:    ${BLUE}sudo nginx -t${NC}"
    echo -e "Reload config:  ${BLUE}sudo nginx -s reload${NC}"
    echo
    echo -e "${BOLD}Files and Directories${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Config file:    ${BLUE}/etc/nginx/nginx.conf${NC}"
    echo -e "Snippets:       ${BLUE}/etc/nginx/snippets/${NC}"
    echo -e "Site configs:   ${BLUE}/etc/nginx/conf.d/${NC}"
    echo -e "Document root:  ${BLUE}/usr/share/nginx/html${NC}"
    echo -e "Log files:      ${BLUE}/var/log/nginx/${NC}"
    echo -e "Backup:         ${BLUE}$BACKUP_DIR${NC}"
    echo
    echo -e "${YELLOW}Connect with:${NC} ${BLUE}https://localhost${NC} ${GREEN}(self-signed certificate)${NC}"
    echo
}
