#!/bin/bash
set -e

# ============================================================
# LambNet Proxmox Update Manager - CT Creation Script
# Run this on a Proxmox host to create and provision a CT
#
# Usage: bash create-ct.sh [OPTIONS]
#   --ctid <ID>          CT ID (default: next available)
#   --hostname <NAME>    Hostname (default: lambnet)
#   --storage <STORE>    Storage for CT (default: local-lvm)
#   --template <PATH>    CT template (default: auto-download latest Debian)
#   --memory <MB>        Memory in MB (default: 1024)
#   --disk <GB>          Disk size in GB (default: 8)
#   --cores <N>          CPU cores (default: 2)
#   --bridge <BRIDGE>    Network bridge (default: vmbr0)
#   --ip <IP/CIDR>       Static IP (default: dhcp)
#   --gateway <GW>       Gateway (required if static IP)
#   --cloudflared        Also install cloudflared
# ============================================================

# Defaults
CTID=""
HOSTNAME="lambnet"
STORAGE="local-lvm"
TEMPLATE=""
MEMORY=1024
DISK=8
CORES=2
BRIDGE="vmbr0"
IP="dhcp"
GATEWAY=""
INSTALL_CLOUDFLARED=""
REPO_URL="https://github.com/ChadOhman/lambnet-proxmox-tool.git"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --ctid) CTID="$2"; shift 2 ;;
        --hostname) HOSTNAME="$2"; shift 2 ;;
        --storage) STORAGE="$2"; shift 2 ;;
        --template) TEMPLATE="$2"; shift 2 ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --disk) DISK="$2"; shift 2 ;;
        --cores) CORES="$2"; shift 2 ;;
        --bridge) BRIDGE="$2"; shift 2 ;;
        --ip) IP="$2"; shift 2 ;;
        --gateway) GATEWAY="$2"; shift 2 ;;
        --cloudflared) INSTALL_CLOUDFLARED="--cloudflared"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "============================================"
echo " LambNet Update Manager - CT Provisioning"
echo "============================================"
echo ""

# Check we're on a Proxmox host
if ! command -v pct &> /dev/null; then
    echo "ERROR: This script must be run on a Proxmox host (pct not found)."
    exit 1
fi

# Auto-assign CT ID if not provided
if [ -z "$CTID" ]; then
    CTID=$(pvesh get /cluster/nextid 2>/dev/null || echo "")
    if [ -z "$CTID" ]; then
        echo "ERROR: Could not auto-assign CT ID. Use --ctid to specify one."
        exit 1
    fi
fi
echo "CT ID: $CTID"

# Download Debian template if not specified
if [ -z "$TEMPLATE" ]; then
    echo ""
    echo "[1/5] Downloading Debian template..."

    # Auto-detect a storage that supports vztmpl content
    TEMPLATE_STORAGE=""
    for STOR_NAME in $(pvesm status 2>/dev/null | tail -n +2 | awk '{print $1}'); do
        if pvesm show "$STOR_NAME" 2>/dev/null | grep -q "vztmpl"; then
            TEMPLATE_STORAGE="$STOR_NAME"
            break
        fi
    done

    if [ -z "$TEMPLATE_STORAGE" ]; then
        echo "ERROR: No storage with 'vztmpl' content type found."
        echo "  Enable vztmpl on a storage in Datacenter > Storage, or use --template."
        exit 1
    fi
    echo "  Template storage: $TEMPLATE_STORAGE"

    # Check if template already exists
    EXISTING=$(pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep "debian-12-standard" | head -1 | awk '{print $1}')
    if [ -n "$EXISTING" ]; then
        TEMPLATE="$EXISTING"
        echo "  Using existing template: $TEMPLATE"
    else
        echo "  Updating template list..."
        pveam update

        # Find latest Debian 12 template
        TEMPLATE_NAME=$(pveam available --section system 2>/dev/null | grep "debian-12-standard" | tail -1 | awk '{print $2}')
        if [ -z "$TEMPLATE_NAME" ]; then
            echo "ERROR: Could not find Debian 12 template. Specify one with --template."
            exit 1
        fi

        echo "  Downloading $TEMPLATE_NAME..."
        if ! pveam download "$TEMPLATE_STORAGE" "$TEMPLATE_NAME"; then
            echo "ERROR: Failed to download template. Check network connectivity and storage."
            exit 1
        fi
        TEMPLATE="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE_NAME}"
        echo "  Template ready: $TEMPLATE"
    fi
else
    echo ""
    echo "[1/5] Using provided template: $TEMPLATE"
fi

# Configure network
NET_CONFIG="name=eth0,bridge=${BRIDGE}"
if [ "$IP" = "dhcp" ]; then
    NET_CONFIG="${NET_CONFIG},ip=dhcp"
else
    NET_CONFIG="${NET_CONFIG},ip=${IP}"
    if [ -n "$GATEWAY" ]; then
        NET_CONFIG="${NET_CONFIG},gw=${GATEWAY}"
    fi
fi

echo ""
echo "[2/5] Creating CT $CTID ($HOSTNAME)..."
echo "  Storage: $STORAGE, Memory: ${MEMORY}MB, Disk: ${DISK}GB, Cores: $CORES"
echo "  Network: $NET_CONFIG"

pct create "$CTID" "$TEMPLATE" \
    --hostname "$HOSTNAME" \
    --storage "$STORAGE" \
    --rootfs "${STORAGE}:${DISK}" \
    --memory "$MEMORY" \
    --cores "$CORES" \
    --net0 "$NET_CONFIG" \
    --features nesting=1 \
    --unprivileged 1 \
    --start 0 \
    --onboot 1

echo "  CT created."

echo ""
echo "[3/5] Starting CT..."
pct start "$CTID"

# Wait for CT to be fully running
echo "  Waiting for CT to boot..."
sleep 5

# Wait for network
for i in $(seq 1 30); do
    if pct exec "$CTID" -- ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1; then
        break
    fi
    sleep 2
done

echo "  CT is running."

echo ""
echo "[4/5] Installing LambNet Update Manager..."

# Install git and clone repo
pct exec "$CTID" -- bash -c "apt-get update -qq && apt-get install -y -qq git curl > /dev/null 2>&1"
pct exec "$CTID" -- bash -c "git clone --quiet '$REPO_URL' /tmp/lambnet-install"

# Run setup.sh from the cloned repo
pct exec "$CTID" -- bash -c "cd /tmp/lambnet-install && bash setup.sh $INSTALL_CLOUDFLARED"

# Cleanup install temp
pct exec "$CTID" -- bash -c "rm -rf /tmp/lambnet-install"

echo ""
echo "[5/5] Verifying installation..."
sleep 3

if pct exec "$CTID" -- systemctl is-active --quiet lambnet-update-manager; then
    echo "  Service is running."
else
    echo "  WARNING: Service may not be running. Check with:"
    echo "  pct exec $CTID -- journalctl -u lambnet-update-manager"
fi

# Get CT IP
CT_IP=$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')

echo ""
echo "============================================"
echo " CT Provisioning Complete!"
echo "============================================"
echo ""
echo " CT ID:     $CTID"
echo " Hostname:  $HOSTNAME"
if [ -n "$CT_IP" ]; then
    echo " Web UI:    http://${CT_IP}:5000"
fi
echo " Username:  admin"
echo " Password:  admin"
echo ""
echo " IMPORTANT: Change the default password after first login!"
echo ""
echo " Proxmox commands:"
echo "   pct enter $CTID              # Shell into CT"
echo "   pct exec $CTID -- <command>  # Run command in CT"
echo "   pct stop $CTID               # Stop CT"
echo "   pct start $CTID              # Start CT"
echo ""
echo " App commands (inside CT):"
echo "   systemctl status lambnet-update-manager"
echo "   journalctl -u lambnet-update-manager -f"
echo "   bash /opt/lambnet/update.sh  # Manual update"
echo ""
