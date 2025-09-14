# HTML file templates for NGINX

# Create default HTML files
create_html_files() {
    mkdir -p /usr/share/nginx/html

    # Main index.html
    cat > /usr/share/nginx/html/index.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Welcome to NGINX</title>
    <style>
        body {
            font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif;
            margin: 0;
            background: #f7f9fb;
            color: #111;
        }
        header {
            background: linear-gradient(135deg, #009639, #00b36b);
            color: #fff;
            padding: 20px;
        }
        main {
            max-width: 900px;
            margin: 32px auto;
            padding: 0 16px;
        }
        code {
            background: #eef4f1;
            border-radius: 4px;
            padding: 2px 6px;
        }
        section {
            background: #fff;
            border: 1px solid #e5ece8;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 2px 4px rgba(0,0,0,.04);
        }
    </style>
</head>
<body>
    <header>
        <h1 style="margin:0">NGINX installed</h1>
    </header>
    <main>
        <section>
            <p>If you see this page, your server is running and serving content.</p>
            <ul>
                <li>Root: <code>/usr/share/nginx/html</code></li>
                <li>Config: <code>/etc/nginx/nginx.conf</code></li>
                <li>Snippets: <code>/etc/nginx/snippets/</code></li>
                <li>Sites: <code>/etc/nginx/conf.d/</code></li>
            </ul>
            <p>Reload with: <code>nginx -s reload</code></p>
            <p>Features: HTTP/3, TLS 1.3, optimized build</p>
        </section>
    </main>
</body>
</html>
EOF

    # 404 error page
    cat > /usr/share/nginx/html/404.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>404 Not Found</title>
    <style>
        body {
            font-family: system-ui, sans-serif;
            display: grid;
            place-items: center;
            min-height: 100vh;
            background: #f7f9fb;
        }
        main {
            background: #fff;
            border: 1px solid #e5ece8;
            border-radius: 10px;
            padding: 24px 28px;
            box-shadow: 0 2px 4px rgba(0,0,0,.04);
            text-align: center;
        }
    </style>
</head>
<body>
    <main>
        <h1 style="margin:0 0 8px;color:#c1121f">404</h1>
        <p>The requested resource could not be found.</p>
        <p><a href="/" style="color:#009639;text-decoration:none">Go to homepage</a></p>
    </main>
</body>
</html>
EOF

    # 50x error page
    cat > /usr/share/nginx/html/50x.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Server error</title>
    <style>
        body {
            font-family: system-ui, sans-serif;
            display: grid;
            place-items: center;
            min-height: 100vh;
            background: #f7f9fb;
        }
        main {
            background: #fff;
            border: 1px solid #e5ece8;
            border-radius: 10px;
            padding: 24px 28px;
            box-shadow: 0 2px 4px rgba(0,0,0,.04);
            text-align: center;
        }
    </style>
</head>
<body>
    <main>
        <h1 style="margin:0 0 8px;color:#b08900">Something went wrong</h1>
        <p>A temporary error occurred while processing your request.</p>
        <p>Please try again later.</p>
    </main>
</body>
</html>
EOF

    # Set permissions
    chmod 0644 /usr/share/nginx/html/*.html || true
    log_success "Created HTML files"
}
