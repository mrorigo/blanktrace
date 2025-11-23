<img src="docs/blanktrace.png">

# BlankTrace

BlankTrace is a cross-platform (Linux/macOS) Rust CLI/daemon MITM proxy that anonymizes browser traffic by randomizing fingerprints, blocking trackers, and stripping cookies.

## Features

- **MITM HTTP/HTTPS Proxy** - Runs on localhost:8080 by default with full HTTPS interception
- **Fingerprint Randomization** - Random User-Agent (using `rand_agents` crate for realistic diversity) and Accept-Language headers
- **Cookie Blocking** - Block all cookies or log cookie attempts
- **Tracker Blocking** - Regex-based domain blocking with whitelist support
- **SQLite Logging** - Track requests, cookies, fingerprints, and blocked domains
- **CLI Management** - Query stats, manage whitelist/blocklist, export data

## Quick Start

### Build

```bash
cargo build --release
```

### Run Proxy

```bash
./target/release/blanktrace
```

The proxy will start on `127.0.0.1:8080` with automatic CA certificate generation for HTTPS interception.

**Important**: For HTTPS to work, you'll need to trust the generated CA certificate in your browser/system. The proxy will generate a new CA on each startup.

### Test User Agent Randomization

```bash
cargo run --example test_randomizer
```

This will demonstrate the `rand_agents` integration, showing how diverse and realistic user agents are generated.

### CLI Commands

```bash
# Show statistics
./target/release/blanktrace stats

# List top tracked domains
./target/release/blanktrace domains --limit 10

# Add domain to whitelist
./target/release/blanktrace whitelist --domain example.com --reason "trusted site"

# Manually block a domain
./target/release/blanktrace block --domain tracker.com

# Export data
./target/release/blanktrace export --file export.json
```

## Configuration

Edit `config.yaml` to customize behavior:

```yaml
fingerprint:
  rotation_mode: "launch"  # every_request, interval, launch
  rotation_interval: 3600  # seconds (for interval mode)
  randomize_user_agent: true
  randomize_accept_language: true
  strip_referer: true

cookies:
  block_all: true
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

cleanup:
  enabled: true
  retention_days: 7
  interval_seconds: 3600

port: 8080
db_path: "blanktrace.db"
```

## CI/CD Pipeline

The project uses GitHub Actions for Continuous Integration and Continuous Deployment:

- **Automated Builds & Tests**: Runs on every push and pull request to `master`.
- **Cross-Platform Support**: Validates builds and tests on Linux (Ubuntu), macOS, and Windows.
- **Release Automation**: Pushing a tag (e.g., `v1.0.0`) automatically creates a GitHub Release with pre-built binaries for all supported platforms.

## Current Status

✅ **Compiles successfully** - All core modules implemented  
✅ **CLI works** - Management commands fully functional  
✅ **User Agent Randomization** - Using `rand_agents` crate for realistic, diverse user agents  
✅ **Proxy fully functional** - HTTP/HTTPS interception working with hudsucker 0.4  
✅ **Request/Response manipulation** - Fingerprint randomization, cookie stripping, domain blocking all working  
✅ **Database logging** - Async logging of all proxy activity  
✅ **Test Coverage** - Core logic covered by unit tests (run `./scripts/coverage.sh` for report)

### What's Working

- **HTTP/HTTPS Interception**: Full MITM proxy with TLS support
- **Fingerprint Randomization**: User-Agent and Accept-Language headers are randomized on every request
- **Cookie Blocking**: Cookies stripped from requests and Set-Cookie removed from responses (configurable allow/block lists)
- **Domain Blocking**: Regex-based blocking with 403 responses and auto-blocking based on hit counts
- **Async Logging**: Non-blocking database writes via mpsc channels
- **Periodic Cleanup**: Configurable retention policy for database logs
- **Graceful Shutdown**: Ctrl+C handling
- **CA Certificate Persistence**: Automatically saves and reuses `ca_cert.pem` and `ca_key.pem` to maintain trust across restarts

### Known Limitations

- **HTTPS Trust**: As with any MITM proxy, you must manually install the generated CA certificate (`ca_cert.pem`) in your browser or system trust store to intercept HTTPS traffic without warnings. This is a necessary step for the proxy to function with encrypted traffic.

## Database Schema

The SQLite database tracks:
- `tracking_domains` - Domains hit and their block status
- `tracking_ips` - IP addresses tracked
- `cookie_traffic` - Cookie attempts and blocks
- `fingerprint_rotations` - Fingerprint changes over time
- `request_log` - All proxied requests
- `whitelist` - Whitelisted domains

## Architecture

- `src/main.rs` - Entry point, initialization
- `src/lib.rs` - Library exports for examples and tests
- `src/config.rs` - YAML configuration loading
- `src/db.rs` - SQLite database operations
- `src/proxy.rs` - MITM proxy with hudsucker 0.4 integration
- `src/randomizer.rs` - User-Agent/language rotation (uses `rand_agents`)
- `src/cookie.rs` - Cookie stripping
- `src/blocker.rs` - Domain blocking logic
- `src/cli.rs` - CLI command handling

## Dependencies

Key dependencies:
- `rand_agents` - Generates realistic, diverse user agents
- `hudsucker 0.4` - MITM proxy framework
- `hyper 0.14` - HTTP library
- `rusqlite` - SQLite database
- `tokio` - Async runtime
- `clap` - CLI argument parsing
- `rcgen` - Certificate generation

## Browser Configuration

### Firefox
1. Preferences → Network Settings → Manual proxy configuration
2. HTTP Proxy: `127.0.0.1`, Port: `8080`
3. Check "Also use this proxy for HTTPS"
4. For HTTPS: Settings → Privacy & Security → Certificates → View Certificates → Import the CA cert

### Chrome/Chromium
1. Settings → System → Open proxy settings
2. Configure HTTP/HTTPS proxy to `127.0.0.1:8080`
3. For HTTPS: Settings → Privacy and security → Security → Manage certificates → Import the CA cert

## Attribution

This project is based on the excellent [browser-privacy-proxy](https://github.com/SoMaCoSF/browser-privacy-proxy), but is a complete rewrite in Rust, focusing on performance, flexibility and ease of use. Huge thanks to the original authors for their work!

## License

MIT
