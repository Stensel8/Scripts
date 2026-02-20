# NGINX Installer

Scripts for building NGINX from source with my own hardened defaults.

Builds with: OpenSSL 3.x, HTTP/2, HTTP/3 (QUIC), zstd compression, headers-more, and ACME module.

## Quick start

```bash
# Install
sudo ./nginx_installer.sh install

# Remove
sudo ./nginx_installer.sh remove
```

## Installed paths

| Path | Purpose |
|------|---------|
| `/usr/sbin/nginx` | Binary |
| `/etc/nginx/` | Configuration |
| `/etc/nginx/nginx.conf` | Main config |
| `/etc/nginx/ssl/` | TLS certificates |
| `/etc/nginx/modules` | Symlink → `/usr/lib64/nginx/modules` |
| `/usr/lib64/nginx/modules/` | Dynamic modules (`.so` files) |
| `/usr/share/nginx/html/` | Default web root |
| `/var/log/nginx/` | Access and error logs |
| `/var/cache/nginx/` | ACME state and nginx cache |
| `/var/lib/nginx/` | Temp files (client body, proxy, etc.) |
| `/etc/systemd/system/nginx.service` | Systemd service |

## Managing the service

```bash
sudo systemctl start nginx
sudo systemctl stop nginx
sudo systemctl reload nginx     # reload config without downtime
sudo systemctl restart nginx
sudo systemctl status nginx
```

## Manual cleanup

If you want to remove nginx without using the `remove` command, delete the following:

```bash
# Stop and disable the service
sudo systemctl stop nginx
sudo systemctl disable nginx
sudo rm -f /etc/systemd/system/nginx.service
sudo systemctl daemon-reload

# Remove all installed files
sudo rm -rf \
    /usr/sbin/nginx \
    /etc/nginx \
    /usr/lib64/nginx \
    /usr/share/nginx \
    /var/log/nginx \
    /var/cache/nginx \
    /var/lib/nginx

# Remove the nginx user
sudo userdel nginx

# Remove backups created by the installer (if any)
sudo rm -rf /var/lib/nginx-backup-*
```

Build directories are created in `/tmp/` and cleaned up automatically when the installer exits.
