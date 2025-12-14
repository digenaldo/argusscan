#!/bin/bash
# Setup script for ArgusScan development environment

set -e

echo "Setting up ArgusScan development environment..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Install pre-commit hooks
echo "Installing pre-commit hooks..."
pip install pre-commit
pre-commit install

# Run tests to verify setup
echo "Running tests to verify setup..."
pytest --cov=argus_scan --cov-report=term-missing --cov-fail-under=80

echo "Setup complete!"
echo "To activate the virtual environment, run: source venv/bin/activate"

