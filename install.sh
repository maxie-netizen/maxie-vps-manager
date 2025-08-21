#!/bin/bash

# Maxie VPS Manager Auto-Installer
echo -e "\033[1;36m"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║    __  __         _         __     __   _                ║
║   |  \/  |       / \       |  \   /  | | |               ║
║   | |\/| |      / _ \      |   \ /   | | |               ║
║   | |  | |     / ___ \     | |\   /| | | |___            ║
║   |_|  |_|    /_/   \_\    |_| \_/ |_| |_____|           ║
║                                                          ║
║                 VPS MANAGER v2.0 🌟                      ║
║           Multi-Protocol • Bandwidth Control             ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "\033[0m"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[1;31mPlease run as root: sudo -i\033[0m"
    exit 1
fi

# Check Ubuntu version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "22.04" ]; then
        echo -e "\033[1;32mUbuntu 22.04 detected - fully supported!\033[0m"
    else
        echo -e "\033[1;33mWarning: This script is optimized for Ubuntu 22.04\033[0m"
        read -p "Continue anyway? (y/N): " continue_anyway
        if [ "$continue_anyway" != "y" ] && [ "$continue_anyway" != "Y" ]; then
            exit 1
        fi
    fi
fi

# Prompt for domain
read -p "Enter your domain name (or press Enter to skip for now): " domain_name
read -p "Enter your email for SSL certificates: " email_address

# Update system
echo -e "\033[1;33mUpdating system...\033[0m"
apt --fix-missing update && apt update && apt upgrade -y
apt install -y bzip2 gzip coreutils screen dpkg wget vim curl nano zip unzip

# Download main manager and scripts
echo -e "\033[1;33mDownloading Maxie VPS Manager...\033[0m"
mkdir -p /etc/maxie/scripts /etc/maxie/banners /etc/maxie/templates

# Download main manager
wget -q https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/maxie-manager.sh -O /usr/local/bin/maxie
chmod +x /usr/local/bin/maxie

# Download component scripts
components=("v2ray" "ssh-websocket" "ssl-tls" "dropbear" "stunnel" "bandwidth" "monitoring" "user-management")
for component in "${components[@]}"; do
    wget -q "https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/scripts/${component}.sh" -O "/etc/maxie/scripts/${component}.sh"
    chmod +x "/etc/maxie/scripts/${component}.sh"
done

# Download banners
wget -q https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/banners/welcome.ban -O /etc/maxie/banners/welcome.ban
wget -q https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/banners/switch.ban -O /etc/maxie/banners/switch.ban

# Download templates
wget -q https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/templates/v2ray-config.json -O /etc/maxie/templates/v2ray-config.json
wget -q https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/templates/nginx-ssl.conf -O /etc/maxie/templates/nginx-ssl.conf

# Create default config
cat > /etc/maxie/config.conf << EOF
# Maxie VPS Manager Configuration
SSH_PORT=22
DROPBEAR_PORT=443
SSLH_PORT=4443
VMESS_PORT=8080
VLESS_PORT=8443
TROJAN_PORT=9000
STUNNEL_PORT=9443
HTTP_CUSTOM_PORT=8081
WS_PORT=2096
DOMAIN=$domain_name
EMAIL=$email_address
XRAY_PATH=/maxie
TROJAN_PASSWORD=\$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12)
THEME=blue
BANNER_ENABLED=true
BANDWIDTH_LIMIT_ENABLED=true
EOF

# Create services config
cat > /etc/maxie/services.conf << EOF
# Services Configuration
# 0 = disabled, 1 = enabled
SSH=1
DROPBEAR=1
V2RAY=1
SSL_TLS=1
STUNNEL=1
WEBSOCKET=1
BANDWIDTH_MONITORING=1
EOF

# Create bandwidth tracking database
cat > /etc/maxie/bandwidth.db << EOF
# User bandwidth database
# Format: username:total_download:total_upload:limit:expiry_date
EOF

# Create services status file
touch /etc/maxie/services.status

# Set up cron jobs for bandwidth monitoring
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/maxie update-bandwidth") | crontab -
(crontab -l 2>/dev/null; echo "0 0 * * * /usr/local/bin/maxie check-expiry") | crontab -

echo -e "\033[1;32mInstallation complete! 🎉\033[0m"
echo -e "\033[1;36mRun: maxie\033[0m to start configuration"

# Start manager in screen if domain was provided
if [ -n "$domain_name" ] && [ "$domain_name" != "your-domain.com" ]; then
    echo -e "\033[1;35mSetting up SSL certificate for $domain_name...\033[0m"
    if command -v screen &> /dev/null; then
        screen -S maxie-setup maxie setup-ssl
    else
        maxie setup-ssl
    fi
else
    echo -e "\033[1;33mYou can set up your domain later from the main menu\033[0m"
    if command -v screen &> /dev/null; then
        screen -S maxie-setup maxie
    else
        maxie
    fi
fi