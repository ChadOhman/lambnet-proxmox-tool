#!/bin/bash
set -e

# ============================================================
# Mastodon Canada Administration Tool - Self-Update Script
# Pulls latest from GitHub, updates deps, restarts service
# Usage: bash update.sh
# ============================================================

APP_NAME="mstdnca-proxmox-tool"
APP_DIR="/opt/mstdnca"
DATA_DIR="/var/lib/mstdnca"
BACKUP_DIR="/var/lib/mstdnca/backups"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
UPDATE_BRANCH=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --branch) UPDATE_BRANCH="$2"; shift 2 ;;
        *) shift ;;
    esac
done

# ── Migration: rename old lambnet paths to mstdnca ──────────
OLD_APP_NAME="lambnet-update-manager"
OLD_APP_DIR="/opt/lambnet"
OLD_DATA_DIR="/var/lib/lambnet"
OLD_SECRET_DIR="/etc/lambnet"
OLD_SERVICE_FILE="/etc/systemd/system/${OLD_APP_NAME}.service"
SECRET_DIR="/etc/mstdnca"

# Migrate app directory
if [ -d "$OLD_APP_DIR" ] && [ ! -d "$APP_DIR" ]; then
    echo "Migrating $OLD_APP_DIR -> $APP_DIR..."
    mv "$OLD_APP_DIR" "$APP_DIR"
fi

# Migrate data directory
if [ -d "$OLD_DATA_DIR" ] && [ ! -d "$DATA_DIR" ]; then
    echo "Migrating $OLD_DATA_DIR -> $DATA_DIR..."
    mv "$OLD_DATA_DIR" "$DATA_DIR"
fi

# Migrate DB file within data dir
if [ -f "$DATA_DIR/lambnet.db" ] && [ ! -f "$DATA_DIR/mstdnca.db" ]; then
    echo "Renaming database file..."
    mv "$DATA_DIR/lambnet.db" "$DATA_DIR/mstdnca.db"
fi

# Migrate old backup file names
for f in "$DATA_DIR/backups"/lambnet_*.db; do
    [ -f "$f" ] || continue
    newname="${f/lambnet_/mstdnca_}"
    mv "$f" "$newname"
done

# Migrate secret directory
if [ -d "$OLD_SECRET_DIR" ] && [ ! -d "$SECRET_DIR" ]; then
    echo "Migrating $OLD_SECRET_DIR -> $SECRET_DIR..."
    mv "$OLD_SECRET_DIR" "$SECRET_DIR"
fi

# Migrate systemd service
if [ -f "$OLD_SERVICE_FILE" ]; then
    echo "Migrating systemd service..."
    systemctl stop "$OLD_APP_NAME" 2>/dev/null || true
    systemctl disable "$OLD_APP_NAME" 2>/dev/null || true

    # Copy old service file as base for new one, then update paths/names
    cp "$OLD_SERVICE_FILE" "$SERVICE_FILE"
    sed -i "s|$OLD_APP_NAME|$APP_NAME|g" "$SERVICE_FILE"
    sed -i "s|LAMBNET_DATA_DIR|MSTDNCA_DATA_DIR|g" "$SERVICE_FILE"
    sed -i "s|LAMBNET_SECRET_KEY|MSTDNCA_SECRET_KEY|g" "$SERVICE_FILE"
    sed -i "s|/opt/lambnet|/opt/mstdnca|g" "$SERVICE_FILE"
    sed -i "s|/var/lib/lambnet|/var/lib/mstdnca|g" "$SERVICE_FILE"
    sed -i "s|/etc/lambnet|/etc/mstdnca|g" "$SERVICE_FILE"

    rm -f "$OLD_SERVICE_FILE"
    systemctl daemon-reload
    echo "  Service migrated to $APP_NAME."
fi
# ── End migration ────────────────────────────────────────────

# Log all output to file for web UI progress tracking
LOG_FILE="$DATA_DIR/update.log"
mkdir -p "$DATA_DIR"
echo "" > "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

ts() { date '+%H:%M:%S'; }

echo "============================================"
echo " Mastodon Canada Administration Tool"
echo " Self-Update  $(ts)"
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
elif [ -f "$APP_DIR/mstdnca-proxmox-tool/app.py" ]; then
    APP_DIR="$APP_DIR/mstdnca-proxmox-tool"
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
echo "Current version : v$CURRENT_VERSION"
echo "App directory   : $APP_DIR"
echo ""

# ── Step 1: Backup ──────────────────────────────────────────
echo "[1/4] Backing up database...  ($(ts))"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -f "$DATA_DIR/mstdnca.db" ]; then
    DB_SIZE=$(du -sh "$DATA_DIR/mstdnca.db" | cut -f1)
    cp "$DATA_DIR/mstdnca.db" "$BACKUP_DIR/mstdnca_${TIMESTAMP}.db"
    echo "  Saved $BACKUP_DIR/mstdnca_${TIMESTAMP}.db  ($DB_SIZE)"

    # Keep only last 10 backups
    REMOVED=$(ls -t "$BACKUP_DIR"/mstdnca_*.db 2>/dev/null | tail -n +11)
    if [ -n "$REMOVED" ]; then
        echo "$REMOVED" | xargs -r rm
        echo "  Removed old backups: $(echo "$REMOVED" | wc -l | tr -d ' ')"
    fi
else
    echo "  No database found — skipping backup."
fi

# ── Step 2: Pull code ────────────────────────────────────────
echo ""
echo "[2/4] Pulling latest code...  ($(ts))"

GIT_DIR="$APP_DIR"
if [ ! -d "$APP_DIR/.git" ]; then
    PARENT_DIR=$(dirname "$APP_DIR")
    if [ -d "$PARENT_DIR/.git" ]; then
        GIT_DIR="$PARENT_DIR"
    fi
fi

if [ -d "$GIT_DIR/.git" ]; then
    cd "$GIT_DIR"
    BRANCH="${UPDATE_BRANCH:-main}"
    echo "  Branch: $BRANCH"

    echo "  Fetching from origin..."
    git fetch origin 2>&1 | sed 's/^/    /'

    # Show incoming commits before applying them
    AHEAD=$(git log --oneline HEAD..origin/"$BRANCH" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$AHEAD" -gt 0 ]; then
        echo "  $AHEAD new commit(s) incoming:"
        git log --oneline HEAD..origin/"$BRANCH" 2>/dev/null | sed 's/^/    + /'
    else
        echo "  Already up to date."
    fi

    git checkout "$BRANCH" 2>&1 | sed 's/^/    /'
    git reset --hard "origin/$BRANCH" 2>&1 | sed 's/^/    /'
    cd "$APP_DIR"
    echo "  Code updated."
else
    echo "  WARNING: Not a git repository. Manual update may be needed."
fi

# Read new version
NEW_VERSION="unknown"
if [ -f "VERSION" ]; then
    NEW_VERSION=$(cat VERSION | tr -d '[:space:]')
fi
echo "  New version: v$NEW_VERSION"

# ── Step 3: Python dependencies ──────────────────────────────
echo ""
echo "[3/4] Updating Python dependencies...  ($(ts))"
source venv/bin/activate

echo "  Upgrading pip..."
pip install --upgrade pip 2>&1 | grep -E 'Successfully|already|Requirement|ERROR' | sed 's/^/    /'

echo "  Installing requirements..."
pip install -r requirements.txt 2>&1 | grep -E 'Successfully|already|Requirement|Collecting|ERROR' | sed 's/^/    /'

echo "  Installing gevent..."
pip install gevent 2>&1 | grep -E 'Successfully|already|Requirement|Collecting|ERROR' | sed 's/^/    /'

echo "  Dependencies up to date."

# ── Step 4: Restart ──────────────────────────────────────────
echo ""
echo "[4/4] Restarting service...  ($(ts))"

# Patch missing environment variables into the service file.
# SESSION_COOKIE_SECURE=0 is required for HTTP-only installs so that
# browsers send back the session cookie and session state (e.g. safety mode)
# is not lost on every request.
if [ -f "$SERVICE_FILE" ]; then
    if ! grep -q "SESSION_COOKIE_SECURE" "$SERVICE_FILE"; then
        sed -i '/^Environment=FLASK_SECRET_KEY_FILE/a Environment=SESSION_COOKIE_SECURE=0' "$SERVICE_FILE"
        systemctl daemon-reload
        echo "  Patched SESSION_COOKIE_SECURE=0 into service file."
    fi
fi

systemctl restart "$APP_NAME"
sleep 2

if systemctl is-active --quiet "$APP_NAME"; then
    echo "  Service is active."
    systemctl status "$APP_NAME" --no-pager -n 3 2>&1 | sed 's/^/    /'
else
    echo "  WARNING: Service may not have started."
    echo "  Check: journalctl -u $APP_NAME -n 20"
fi

echo ""
echo "============================================"
echo " Update Complete!  ($(ts))"
echo " v$CURRENT_VERSION -> v$NEW_VERSION"
echo "============================================"
echo ""
