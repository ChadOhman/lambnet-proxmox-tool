#!/bin/bash
set -e

# ============================================================
# LambNet Proxmox Update Manager - Self-Update Script
# Pulls latest from GitHub, updates deps, restarts service
# Usage: bash update.sh
# ============================================================

APP_NAME="lambnet-update-manager"
APP_DIR="/opt/lambnet"
DATA_DIR="/var/lib/lambnet"
BACKUP_DIR="/var/lib/lambnet/backups"

echo "============================================"
echo " LambNet Update Manager - Updating..."
echo "============================================"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

# Navigate into the correct directory
if [ -f "$APP_DIR/app.py" ]; then
    cd "$APP_DIR"
elif [ -f "$APP_DIR/lambnet-proxmox-tool/app.py" ]; then
    APP_DIR="$APP_DIR/lambnet-proxmox-tool"
    cd "$APP_DIR"
else
    echo "ERROR: Cannot find application directory."
    exit 1
fi

# Read current version
CURRENT_VERSION="unknown"
if [ -f "VERSION" ]; then
    CURRENT_VERSION=$(cat VERSION | tr -d '[:space:]')
fi
echo "Current version: v$CURRENT_VERSION"

echo ""
echo "[1/4] Backing up database..."
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -f "$DATA_DIR/lambnet.db" ]; then
    cp "$DATA_DIR/lambnet.db" "$BACKUP_DIR/lambnet_${TIMESTAMP}.db"
    echo "  Backup saved to $BACKUP_DIR/lambnet_${TIMESTAMP}.db"

    # Keep only last 10 backups
    ls -t "$BACKUP_DIR"/lambnet_*.db 2>/dev/null | tail -n +11 | xargs -r rm
    echo "  Old backups cleaned up."
else
    echo "  No database to backup."
fi

echo ""
echo "[2/4] Pulling latest code..."
if [ -d ".git" ]; then
    git fetch --quiet origin
    git reset --hard origin/main --quiet
    echo "  Code updated from GitHub."
else
    echo "  WARNING: Not a git repository. Manual update may be needed."
fi

# Read new version
NEW_VERSION="unknown"
if [ -f "VERSION" ]; then
    NEW_VERSION=$(cat VERSION | tr -d '[:space:]')
fi
echo "  New version: v$NEW_VERSION"

echo ""
echo "[3/4] Updating Python dependencies..."
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "  Done."

echo ""
echo "[4/4] Restarting service..."
systemctl restart "$APP_NAME"
sleep 2

if systemctl is-active --quiet "$APP_NAME"; then
    echo "  Service restarted successfully."
else
    echo "  WARNING: Service may not have started. Check: journalctl -u $APP_NAME"
fi

echo ""
echo "============================================"
echo " Update Complete!"
echo " v$CURRENT_VERSION -> v$NEW_VERSION"
echo "============================================"
echo ""
