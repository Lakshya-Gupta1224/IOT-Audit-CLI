#!/usr/bin/env bash
# Linux / WSL Helper to Run Mosquitto Demo Broker
# Usage:
#   ./scripts/setup_demo_broker.sh vulnerable
#   ./scripts/setup_demo_broker.sh hardened

MODE=${1:-vulnerable}

echo "=========================================================="
echo "  Mosquitto Broker Runner for IoT Security Assessment     "
echo "=========================================================="

if ! command -v mosquitto &> /dev/null; then
    echo "[!] Mosquitto is not installed."
    echo "    Install via: sudo apt-get update && sudo apt-get install -y mosquitto mosquitto-clients"
    exit 1
fi

CONF="demo_configs/mosquitto_${MODE}.conf"

if [ ! -f "$CONF" ]; then
    echo "[!] Config $CONF not found."
    exit 1
fi

echo "[*] Launching Mosquitto in $MODE mode ($CONF)..."
mosquitto -c "$CONF" -v
