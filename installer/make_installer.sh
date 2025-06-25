#!/bin/zsh

set -e

echo "[1/4] Creating or activating Python virtual environment..."

if [ ! -d "venv" ]; then
    echo "Creating new venv..."
    python3 -m venv venv
else
    echo "venv already exists, skipping creation"
fi

# Activate virtual environment
source ./venv/bin/activate
echo "Virtual environment activated: $(which python3)"

echo "[2/4] Installing required Python packages..."

pip3 install --upgrade pip
pip3 install ledgerblue keyboard pyinstaller

echo "[3/4] Building installers..."

if [ -f "babyloninst.spec" ]; then
    echo "Building mainnet installer..."
    pyinstaller ./babyloninst.spec
else
    echo "ERROR: babyloninst.spec not found"
    exit 1
fi

if [ -f "babyloninst-test.spec" ]; then
    echo "Building testnet installer..."
    pyinstaller ./babyloninst-test.spec
else
    echo "ERROR: babyloninst-test.spec not found"
    exit 1
fi

echo "[4/4] Done. Installers are in the dist/ directory."