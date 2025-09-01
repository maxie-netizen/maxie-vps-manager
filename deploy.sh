#!/bin/bash

# Maxie VPS Manager - Deployment Script
# This script deploys the complete Maxie VPS Manager to your VPS

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

print_header "Maxie VPS Manager - Deployment"
echo
echo "This script will deploy Maxie VPS Manager to your VPS."
echo "Make sure all script files are in the current directory."
echo

# Check for required files
required_files=(
    "maxie-tunneling-setup.sh"
    "user-management.sh"
    "system-utils.sh"
    "config.conf"
    "install.sh"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        missing_files+=("$file")
    fi
done

if [[ ${#missing_files[@]} -gt 0 ]]; then
    print_error "Missing required files:"
    for file in "${missing_files[@]}"; do
        echo "  - $file"
    done
    echo
    echo "Please ensure all files are present in the current directory."
    exit 1
fi

print_status "All required files found. Starting deployment..."

# Make all scripts executable
chmod +x *.sh

# Run the installation script
print_status "Running installation script..."
./install.sh

if [[ $? -eq 0 ]]; then
    print_header "Deployment Completed Successfully!"
    echo
    echo "Maxie VPS Manager has been deployed to your VPS."
    echo
    echo "=== Next Steps ==="
    echo "1. Run: maxie-vps-manager"
    echo "2. Choose option 1 to install all tunneling protocols"
    echo "3. Configure your domain and SSL certificates"
    echo "4. Access X-UI Panel at http://your-ip:54321"
    echo
    echo "=== Available Commands ==="
    echo "maxie-vps-manager                    - Main management interface"
    echo "maxie-vps-manager-uninstall          - Remove the manager"
    echo
    echo "=== Important Notes ==="
    echo "- All services will start automatically on boot"
    echo "- Firewall rules will be configured automatically"
    echo "- SSL certificates will auto-renew every 90 days"
    echo "- Default X-UI credentials: admin/admin (change immediately!)"
    echo
    echo "Deployment completed at: $(date)"
else
    print_error "Deployment failed. Please check the error messages above."
    exit 1
fi
