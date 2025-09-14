# NGINX configuration templates

# Create main nginx.conf
create_main_config() {
    local stream_block=""
    if is_enabled ENABLE_STREAM auto; then
        stream_block='
# TCP/UDP stream (optional)
stream {
    include /etc/nginx/stream.d/*.conf;
}'
    fi

    cat > /etc/nginx/nginx.conf << EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

# Load dynamic modules when present/enabled
include /etc/nginx/modules.d/*.conf;

events {
    worker_connections 1024;
    use epoll;
}

http {
    # Hide NGINX version on error pages
    server_tokens off;

    include /etc/nginx/mime.types;

    # Pull in modular HTTP snippets (core, security, compression, TLS, etc.)
    include /etc/nginx/snippets/*.conf;

    # Site-specific vhosts belong in conf.d (kept empty by this installer)
    include /etc/nginx/conf.d/*.conf;
    
    # Default server - HTTPS only
    server {
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;
        
        # Enable HTTP/2
        http2 on;

        server_name localhost;
        root /usr/share/nginx/html;
        
        # SSL certificate configuration
        ssl_certificate /etc/nginx/ssl/localhost.crt;
        ssl_certificate_key /etc/nginx/ssl/localhost.key;
        
        include /etc/nginx/snippets/http_hardening.snippet;
        
        location / {
            index index.html index.htm;
        }
        
        error_page 404 /404.html;
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /usr/share/nginx/html;
        }
    }
}
${stream_block}
EOF
    
    chmod 0644 /etc/nginx/nginx.conf || true
    log_success "Created main nginx.conf"
}

# Create configuration snippets
create_config_snippets() {
    mkdir -p /etc/nginx/snippets

    # Common core settings
    cat > /etc/nginx/snippets/common.conf << 'EOF'
# Common HTTP core settings
default_type application/octet-stream;

log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" '
                '"$http_user_agent" "$http_x_forwarded_for"';

access_log /var/log/nginx/access.log main;

sendfile on;
tcp_nopush on;
tcp_nodelay on;
keepalive_timeout 65;
EOF

    # Security headers
    cat > /etc/nginx/snippets/security.conf << 'EOF'
# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;

# Completely remove the Server header
# This requires the headers-more module, which is enabled by default
more_clear_headers "Server";
EOF

    # TLS core
    cat > /etc/nginx/snippets/ssl_core.conf << 'EOF'
# Core SSL/TLS settings
ssl_protocols TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
EOF

    # Compression (gzip)
    cat > /etc/nginx/snippets/compression.conf << 'EOF'
# Gzip compression (fallback)
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css text/xml application/json application/javascript \
           application/xml+rss application/atom+xml image/svg+xml;
EOF

    # HTTP hardening
    cat > /etc/nginx/snippets/http_hardening.snippet << 'EOF'
# Block HTTP/1.0 and HTTP/1.1
# Return 444 (Connection Closed Without Response) if not HTTP/2 or HTTP/3
if ($server_protocol ~* "HTTP/1") {
    return 444;
}
EOF

    # Set permissions
    chmod 0644 /etc/nginx/snippets/*.conf /etc/nginx/snippets/*.snippet || true
    log_success "Created configuration snippets"
}
