# Installation & Setup Guide

## Quick Start

### 1. Build the Proxy

```bash
cargo build --release
```

### 2. First Run

```bash
./target/release/blanktrace
```

On first run, the proxy will:
- Generate a CA certificate (`ca_cert.pem`)
- Generate a private key (`ca_key.pem`)
- Start listening on `127.0.0.1:8080`

**Important**: The CA certificate is persisted to disk and reused on subsequent runs.

## Browser Configuration

### Firefox

#### 1. Configure Proxy

1. Open Firefox Settings
2. Search for "proxy"
3. Click "Settings" under "Network Settings"
4. Select "Manual proxy configuration"
5. Set:
   - HTTP Proxy: `127.0.0.1`
   - Port: `8080`
   - Check "Also use this proxy for HTTPS"
   - Check "Use this proxy server for all protocols"

#### 2. Trust CA Certificate

1. Open Firefox Settings
2. Search for "certificates"
3. Click "View Certificates"
4. Go to "Authorities" tab
5. Click "Import"
6. Select `ca_cert.pem` from the proxy directory
7. Check "Trust this CA to identify websites"
8. Click OK

### Chrome/Chromium

#### 1. Configure Proxy

**macOS:**
1. System Settings → Network
2. Select your network → Details
3. Go to "Proxies" tab
4. Check "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)"
5. Set both to:
   - Server: `127.0.0.1`
   - Port: `8080`

**Linux:**
1. Settings → Network → Network Proxy
2. Select "Manual"
3. Set HTTP and HTTPS proxy to `127.0.0.1:8080`

#### 2. Trust CA Certificate

**macOS:**
1. Open Keychain Access
2. File → Import Items
3. Select `ca_cert.pem`
4. Double-click the imported certificate
5. Expand "Trust"
6. Set "When using this certificate" to "Always Trust"

**Linux:**
```bash
# Ubuntu/Debian
sudo cp ca_cert.pem /usr/local/share/ca-certificates/blanktrace.crt
sudo update-ca-certificates

# Fedora/RHEL
sudo cp ca_cert.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

## CLI Commands

### View Statistics

```bash
./target/release/blanktrace stats
```

Shows:
- Total requests proxied
- Unique domains accessed
- Blocked domains count
- Whitelisted domains count
- Top 10 most requested domains

### Export Data

```bash
./target/release/blanktrace export --file export.json
```

Exports all data to JSON format including:
- Request logs (last 1000)
- Tracking domains
- Whitelist entries

### Manage Whitelist

```bash
# Add domain to whitelist
./target/release/blanktrace whitelist --domain example.com --reason "trusted site"

# Block domain manually
./target/release/blanktrace block --domain tracker.com
```

### View Top Domains

```bash
./target/release/blanktrace domains --limit 20
```

## Configuration

Edit `config.yaml` to customize:

```yaml
fingerprint:
  rotation_mode: "launch"        # every_request, interval, or launch
  rotation_interval: 3600        # seconds (for interval mode)
  randomize_user_agent: true
  randomize_accept_language: true
  strip_referer: true

cookies:
  block_all: true               # Block all cookies
  log_attempts: true
  auto_block_trackers: true
  allow_list:
    - "github.com"
    - "stackoverflow.com"
  block_list:
    - "doubleclick.net"
    - "facebook.com"

blocking:
  auto_block: true
  auto_block_threshold: 5
  block_patterns:
    - ".*analytics.*"
    - ".*doubleclick.*"
    - ".*google-analytics.*"
    - ".*facebook.*"
    - ".*twitter.*"

cleanup:
  enabled: true
  retention_days: 7
  interval_seconds: 3600

port: 8080
db_path: "blanktrace.db"
```

## Troubleshooting

### HTTPS Sites Show Certificate Errors

**Cause**: CA certificate not trusted by browser/system

**Solution**: Follow the "Trust CA Certificate" steps above

### Proxy Won't Start - Port Already in Use

**Cause**: Another application is using port 8080

**Solution**: Change port in `config.yaml` or stop the conflicting application

### No Traffic Being Proxied

**Cause**: Browser not configured to use proxy

**Solution**: Verify proxy settings in browser (should show `127.0.0.1:8080`)

### Database Locked Errors

**Cause**: Multiple instances running

**Solution**: Stop all instances and restart

## Security Considerations

### CA Certificate Security

- **Keep `ca_key.pem` private** - Never share this file
- The CA certificate allows intercepting HTTPS traffic
- Only install the CA on devices you control
- Delete the CA from browser/system when not using the proxy

### Privacy

- All traffic is logged to SQLite database
- Database contains:
  - Domains visited
  - Request paths
  - User agents
  - Timestamps
- Regularly export and clear the database if needed

### Network Security

- Proxy only listens on `127.0.0.1` (localhost)
- Not accessible from other devices on network
- No authentication required (local-only access)

## Advanced Usage

### Running as Background Service

**macOS (launchd):**

Create `~/Library/LaunchAgents/com.privacy.proxy.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.privacy.proxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/blanktrace</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/path/to/proxy/directory</string>
</dict>
</plist>
```

Load: `launchctl load ~/Library/LaunchAgents/com.privacy.proxy.plist`

**Linux (systemd):**

Create `/etc/systemd/user/blanktrace.service`:

```ini
[Unit]
Description=BlankTrace Proxy
After=network.target

[Service]
Type=simple
ExecStart=/path/to/blanktrace
WorkingDirectory=/path/to/proxy/directory
Restart=on-failure

[Install]
WantedBy=default.target
```

Enable: `systemctl --user enable --now blanktrace`

### Viewing Logs

```bash
# Run with logging
RUST_LOG=info ./target/release/blanktrace

# Log levels: error, warn, info, debug, trace
RUST_LOG=debug ./target/release/blanktrace
```

## Uninstallation

1. Remove proxy configuration from browser
2. Remove CA certificate from browser/system trust store
3. Delete proxy files:
   ```bash
   rm -rf target/
   rm ca_cert.pem ca_key.pem
   rm blanktrace.db*
   ```

## Support

For issues or questions:
- Check the troubleshooting section above
- Review logs with `RUST_LOG=debug`
- Check database with `stats` command
