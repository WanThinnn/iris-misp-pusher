#!/bin/bash
#
# Script to install iris-misp-pusher module to IRIS Docker containers
# Usage: ./install_to_docker.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$SCRIPT_DIR"

echo "================================================"
echo "Installing iris-misp-pusher to IRIS containers"
echo "================================================"

# Build the wheel package
echo "[1/5] Building wheel package..."
cd "$MODULE_DIR"
rm -rf build dist *.egg-info
python3 setup.py bdist_wheel

WHEEL_FILE=$(ls dist/*.whl)
echo "Built: $WHEEL_FILE"

# Copy to app container
echo "[2/5] Copying to iriswebapp_app container..."
sudo docker cp "$WHEEL_FILE" iriswebapp_app:/tmp/iris_misp_pusher.whl

# Copy to worker container
echo "[3/5] Copying to iriswebapp_worker container..."
sudo docker cp "$WHEEL_FILE" iriswebapp_worker:/tmp/iris_misp_pusher.whl

# Install in app container
echo "[4/5] Installing in iriswebapp_app..."
sudo docker exec iriswebapp_app pip3 install --force-reinstall /tmp/iris_misp_pusher.whl

# Install in worker container
echo "[5/5] Installing in iriswebapp_worker..."
sudo docker exec iriswebapp_worker pip3 install --force-reinstall /tmp/iris_misp_pusher.whl

echo ""
echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "1. Restart containers: sudo docker restart iriswebapp_app iriswebapp_worker"
echo "2. Go to IRIS UI > Advanced > Modules"
echo "3. Add module 'iris_misp_pusher'"
echo "4. Configure MISP URL, API Key, Event IDs"
echo "5. Enable the module"
echo ""
