#!/bin/bash
set -e

# ============================================================
# LambNet Proxmox Update Manager - CT Setup Script
# Run this inside a fresh Debian/Ubuntu LXC container
# Usage: bash setup.sh [--cloudflared]
#   --cloudflared  Also install cloudflared for CF Zero Trust tunnel
# ============================================================

APP_NAME="lambnet-update-manager"
APP_DIR="/opt/lambnet"
DATA_DIR="/var/lib/lambnet"
SECRET_DIR="/etc/lambnet"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
REPO_URL="https://github.com/ChadOhman/lambnet-proxmox-tool.git"
INSTALL_CLOUDFLARED=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --cloudflared)
            INSTALL_CLOUDFLARED=true
            ;;
    esac
done

echo "============================================"
echo " LambNet Proxmox Update Manager - Setup"
echo "============================================"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    echo "Detected OS: $PRETTY_NAME"
else
    echo "ERROR: Cannot detect OS. This script requires Debian or Ubuntu."
    exit 1
fi

if [[ "$OS" != "debian" && "$OS" != "ubuntu" ]]; then
    echo "ERROR: This script only supports Debian and Ubuntu."
    exit 1
fi

TOTAL_STEPS=7
if [ "$INSTALL_CLOUDFLARED" = true ]; then
    TOTAL_STEPS=8
fi

echo ""
echo "[1/$TOTAL_STEPS] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git curl > /dev/null 2>&1
echo "  Done."

echo ""
echo "[2/$TOTAL_STEPS] Setting up application directory..."
if [ -d "$APP_DIR" ]; then
    echo "  Directory $APP_DIR already exists. Updating..."
    cd "$APP_DIR"
    if [ -d ".git" ]; then
        git pull --quiet
    fi
else
    # Check if we're running from the repo directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SCRIPT_DIR/app.py" ]; then
        echo "  Installing from local directory..."
        cp -r "$SCRIPT_DIR" "$APP_DIR"
    else
        echo "  Cloning from GitHub..."
        git clone --quiet "$REPO_URL" "$APP_DIR"
        cd "$APP_DIR"
        # Navigate into the nested directory if it exists
        if [ -d "lambnet-proxmox-tool" ]; then
            APP_DIR="$APP_DIR/lambnet-proxmox-tool"
        fi
    fi
fi
echo "  Done."

echo ""
echo "[3/$TOTAL_STEPS] Creating Python virtual environment..."
cd "$APP_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "  Done."

echo ""
echo "[4/$TOTAL_STEPS] Creating data directories..."
mkdir -p "$DATA_DIR"
mkdir -p "$SECRET_DIR"
chmod 700 "$SECRET_DIR"
echo "  Done."

echo ""
echo "[5/$TOTAL_STEPS] Generating encryption key..."
if [ ! -f "$SECRET_DIR/secret.key" ]; then
    python3 -c "
from cryptography.fernet import Fernet
key = Fernet.generate_key()
with open('$SECRET_DIR/secret.key', 'wb') as f:
    f.write(key)
"
    chmod 600 "$SECRET_DIR/secret.key"
    echo "  New encryption key generated."
else
    echo "  Encryption key already exists, keeping existing."
fi

echo ""
echo "[6/$TOTAL_STEPS] Initializing database..."
cd "$APP_DIR"
source venv/bin/activate
python3 -c "
from app import create_app
app = create_app()
print('  Database initialized.')
"

echo ""
echo "[7/$TOTAL_STEPS] Creating systemd service..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=LambNet Proxmox Update Manager
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment=LAMBNET_DATA_DIR=$DATA_DIR
Environment=LAMBNET_SECRET_KEY=$SECRET_DIR/secret.key
ExecStart=$APP_DIR/venv/bin/gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker --bind 0.0.0.0:5000 --workers 1 --timeout 120 "app:create_app()"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Install gevent for websocket support in production
source venv/bin/activate
pip install --quiet gevent gevent-websocket

systemctl daemon-reload
systemctl enable "$APP_NAME"
systemctl restart "$APP_NAME"
echo "  Done."

# Optional: Install cloudflared
if [ "$INSTALL_CLOUDFLARED" = true ]; then
    echo ""
    echo "[8/$TOTAL_STEPS] Installing cloudflared..."

    # Detect architecture
    ARCH=$(dpkg --print-architecture)
    if [ "$ARCH" = "amd64" ]; then
        CLOUDFLARED_ARCH="amd64"
    elif [ "$ARCH" = "arm64" ]; then
        CLOUDFLARED_ARCH="arm64"
    else
        echo "  WARNING: Unsupported architecture $ARCH for cloudflared. Skipping."
        INSTALL_CLOUDFLARED=false
    fi

    if [ "$INSTALL_CLOUDFLARED" = true ]; then
        # Install cloudflared via official package repo
        curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg 2>/dev/null
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflared.list
        apt-get update -qq
        apt-get install -y -qq cloudflared > /dev/null 2>&1
        echo "  cloudflared installed: $(cloudflared --version 2>&1 | head -1)"
    fi
fi

echo ""
echo "============================================"
echo " Setup Complete!"
echo "============================================"
echo ""
echo " Web UI:    http://$(hostname -I | awk '{print $1}'):5000"
echo " Username:  admin"
echo " Password:  admin"
echo ""
echo " IMPORTANT: Change the default password after first login!"
echo ""
echo " Service commands:"
echo "   systemctl status $APP_NAME"
echo "   systemctl restart $APP_NAME"
echo "   journalctl -u $APP_NAME -f"
echo ""
echo " Data directory: $DATA_DIR"
echo " App directory:  $APP_DIR"
echo ""

if [ "$INSTALL_CLOUDFLARED" = true ]; then
    echo " Cloudflare Tunnel Setup:"
    echo "   1. cloudflared tunnel login"
    echo "   2. cloudflared tunnel create lambnet"
    echo "   3. Create config at /etc/cloudflared/config.yml:"
    echo ""
    echo "      tunnel: <TUNNEL-ID>"
    echo "      credentials-file: /root/.cloudflared/<TUNNEL-ID>.json"
    echo "      ingress:"
    echo "        - hostname: lambnet.yourdomain.com"
    echo "          service: http://localhost:5000"
    echo "        - service: http_status:404"
    echo ""
    echo "   4. cloudflared tunnel route dns lambnet lambnet.yourdomain.com"
    echo "   5. cloudflared service install"
    echo "   6. systemctl start cloudflared"
    echo ""
    echo "   Then configure CF Access in Zero Trust dashboard"
    echo "   and enter the AUD tag in Settings > Cloudflare Zero Trust."
    echo ""
fi
