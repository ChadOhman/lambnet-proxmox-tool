# LambNet Proxmox Update Manager

A datacenter-wide update management tool for Proxmox environments. Runs as an LXC container and provides a web interface for managing APT updates across all your Proxmox hosts, VMs, and CTs.

## Features

- **Datacenter-wide update scanning** — Scan all hosts, VMs, and CTs for available APT updates with severity detection
- **Web SSH terminal** — Browser-based SSH sessions to any managed guest
- **Mastodon (glitch-soc) upgrade automation** — One-click upgrades with PGBouncer swap, git stash/pop, Proxmox snapshots, and auto-upgrade support
- **Gmail notifications** — Email alerts when updates are available, with severity breakdown
- **Scheduled scans & auto-updates** — Configurable scan intervals and maintenance windows
- **Tag-based access control** — Users can only access VMs/CTs matching their assigned Proxmox tags
- **Encrypted credential storage** — SSH passwords and API tokens encrypted at rest with Fernet
- **Cloudflare Zero Trust** — Optional SSO authentication via Cloudflare Access
- **Local network bypass** — Trusted subnets skip authentication entirely
- **Self-updating** — Check for updates and apply them from the web UI

## Quick Start

### Option 1: Automated CT Creation

Run this on any Proxmox host to create a ready-to-use CT:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ChadOhman/lambnet-proxmox-tool/main/create-ct.sh)" -- \
  --hostname lambnet \
  --storage local-lvm \
  --memory 1024 \
  --disk 8 \
  --cores 2 \
  --bridge vmbr0 \
  --ip dhcp
```

With a static IP:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ChadOhman/lambnet-proxmox-tool/main/create-ct.sh)" -- \
  --hostname lambnet \
  --ip 10.0.0.100/24 \
  --gateway 10.0.0.1
```

With Cloudflare Tunnel support:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ChadOhman/lambnet-proxmox-tool/main/create-ct.sh)" -- \
  --hostname lambnet \
  --ip dhcp \
  --cloudflared
```

#### CT Creation Options

| Flag | Default | Description |
|------|---------|-------------|
| `--ctid <ID>` | next available | Proxmox CT ID |
| `--hostname <NAME>` | `lambnet` | CT hostname |
| `--storage <STORE>` | `local-lvm` | Storage for CT rootfs |
| `--template <PATH>` | auto-download Debian 12 | CT template path |
| `--memory <MB>` | `1024` | Memory allocation |
| `--disk <GB>` | `8` | Disk size |
| `--cores <N>` | `2` | CPU cores |
| `--bridge <BRIDGE>` | `vmbr0` | Network bridge |
| `--ip <IP/CIDR>` | `dhcp` | Static IP or `dhcp` |
| `--gateway <GW>` | — | Gateway (required for static IP) |
| `--cloudflared` | — | Also install cloudflared |

### Option 2: Manual Setup

Create a Debian 12 or Ubuntu 22.04+ CT in Proxmox, then inside the CT:

```bash
apt-get update && apt-get install -y git
git clone https://github.com/ChadOhman/lambnet-proxmox-tool.git /tmp/lambnet
cd /tmp/lambnet && bash setup.sh
```

### First Login

Once deployed, open `http://<CT-IP>:5000` in your browser.

- **Username:** `admin`
- **Password:** `admin`

**Change the default password immediately** via the user dropdown menu.

## Configuration

### Adding Proxmox Hosts

1. Navigate to **Hosts** and click **Add Host**
2. Enter the Proxmox hostname/IP, port (default 8006), and authentication credentials (API token recommended)
3. Click **Test Connection** to verify, then save
4. Click **Discover Guests** to automatically import all VMs and CTs

### Adding Standalone Guests

Guests not managed by Proxmox (e.g. bare-metal servers) can be added manually under **Guests > Add Guest** with an IP address and SSH credential.

### Credentials

Under **Credentials**, add SSH credentials (password or private key) that will be used to connect to your guests. You can assign a specific credential to each guest, or set one as the default.

### Gmail Notifications

1. Go to **Settings > Gmail Notifications**
2. Enter your Gmail address and an [App Password](https://myaccount.google.com/apppasswords) (requires 2FA enabled)
3. Add recipient email addresses (comma-separated)
4. Enable notifications and click **Send Test Email** to verify

### Scan Settings

Under **Settings > Scan Settings**, configure how often to automatically scan for updates (1–168 hours). The scanner checks all enabled guests for available APT packages and flags security updates as critical.

### Maintenance Windows & Auto-Updates

Under **Schedules**, create maintenance windows specifying day, time range, and update type (`upgrade` or `dist-upgrade`). Assign windows to guests, then enable auto-update on each guest to have updates applied automatically during their window.

## Mastodon Upgrades

The **Mastodon** page automates glitch-soc upgrades:

1. Navigate to **Mastodon** and configure:
   - **Mastodon App Guest** — the VM/CT running puma/sidekiq
   - **PostgreSQL Guest** — the VM/CT running your database
   - **PGBouncer host/port** — your normal DB connection (via PGBouncer)
   - **Direct DB host/port** — direct PostgreSQL connection (used during migrations)
   - **Current version** — your installed Mastodon version
2. Click **Check for Updates** to query the [mastodon/mastodon](https://github.com/mastodon/mastodon/releases) GitHub repo
3. Click **Upgrade Now** to run the full upgrade sequence:

The upgrade process:
1. Snapshots both the app and database guests via Proxmox API
2. `git stash` to save local customizations
3. Swaps `.env.production` DB_HOST/DB_PORT from PGBouncer to direct PostgreSQL
4. `git pull` to fetch the latest glitch-soc code
5. `git stash pop` to restore local customizations
6. `bundle install` and `yarn install`
7. Pre-deployment database migrations
8. Asset precompilation
9. Service reload/restart
10. Cache clear and post-deployment migrations
11. Restores `.env.production` back to PGBouncer
12. Final service restart

Enable **automatic upgrades** to have this run whenever a new release is detected.

## User Management & Access Control

Admins can manage users under **Users**:

- **Tags** map to Proxmox guest tags. Create tags, assign them to users, and users will only see guests that share their tags.
- **Permissions**: `can_ssh` (terminal access), `can_update` (apply updates), `is_admin` (full access)
- Admins see all guests regardless of tags

## Cloudflare Zero Trust

For secure external access without a VPN:

1. Go to **Settings > Cloudflare Zero Trust**
2. Enter your team domain (e.g. `myteam.cloudflareaccess.com`) and Application Audience (AUD) tag
3. Enable CF Access authentication

Options:
- **Auto-provision users** — automatically creates accounts for new CF Access users
- **CF Access as sole authentication** — disables local login entirely (ensure CF Access is working first)

Setup requires a Cloudflare Tunnel. Run `bash setup.sh --cloudflared` to install cloudflared, then follow the setup guide shown in the settings page.

## Local Network Bypass

Under **Settings > Local Network Access**, trusted subnets (default `10.0.0.0/8`) are automatically authenticated as admin without login. This allows seamless LAN access while requiring authentication for external connections.

## Updating

### From the Web UI

Go to **Settings > Application** and click **Check for Updates**. If a new version is available, click **Update Now**.

### From the Command Line

```bash
bash /opt/lambnet/update.sh
```

This backs up the database, pulls the latest code, updates dependencies, and restarts the service.

## Architecture

```
Flask Web UI (:5000)
├── Dashboard ─── update overview across datacenter
├── Hosts ─────── Proxmox node management + guest discovery
├── Guests ────── VM/CT list with update status
├── Terminal ──── browser-based SSH (xterm.js + WebSocket)
├── Mastodon ──── glitch-soc upgrade automation
├── Credentials ─ encrypted SSH key/password storage
├── Schedules ─── maintenance windows for auto-updates
├── Users ─────── tag-based RBAC
└── Settings ──── email, scan, CF Access, local bypass

Background Services (APScheduler)
├── Update scanner ─── periodic APT check across all guests
├── Mastodon checker ─ polls GitHub for new releases
├── Auto-updater ───── applies updates during maintenance windows
└── Email notifier ─── Gmail SMTP alerts
```

## Tech Stack

- **Backend:** Python 3.11+, Flask, SQLAlchemy, APScheduler
- **Frontend:** Bootstrap 5 (dark theme), htmx, xterm.js
- **Database:** SQLite
- **Connections:** proxmoxer (Proxmox API), paramiko (SSH)
- **Security:** Fernet encryption, PyJWT (Cloudflare Access)

## File Layout

```
/opt/lambnet/          # Application code
/var/lib/lambnet/      # SQLite database + backups
/etc/lambnet/          # Encryption keys (secret.key, flask_secret)
```

## License

MIT
