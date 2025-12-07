#!/bin/bash
# CLI-only Installation script for PhishSense

echo "=========================================="
echo "PhishSense CLI Installation Script"
echo "=========================================="
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "Virtual environment created!"
else
    echo "Virtual environment already exists."
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install CLI-only requirements
echo ""
echo "Installing CLI dependencies (no web server)..."
pip install -r requirements_cli.txt

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "To use PhishSense CLI:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run: python phishsense_cli.py https://example.com"
echo ""
echo "To deactivate: deactivate"
echo ""

