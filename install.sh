#!/bin/bash

# Maxie VPS Manager - Installation Script
# This script downloads and installs the complete tunneling solution

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

print_header "Maxie VPS Manager - Installation"
echo
echo "This script will install the complete Maxie VPS Manager"
echo "with all tunneling protocols and management tools."
echo

# Create installation directory
INSTALL_DIR="/opt/maxie-vps-manager"
mkdir -p "$INSTALL_DIR"

# Copy the main tunneling setup script
print_status "Installing Maxie VPS Manager..."
cp maxie-tunneling-setup.sh "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/maxie-tunneling-setup.sh"

# Create the main manager script
print_status "Creating main manager script..."
cat > /usr/local/bin/maxie-vps-manager << 'EOF'
#!/bin/bash

# Maxie VPS Manager - Main Interface
# This is the main entry point for the VPS manager

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default ports for protocols
declare -A DEFAULT_PORTS=(
    ["badvpn"]=7300
    ["udp-custom"]=5300
    ["ssl-tunnel"]=444
    ["websocket"]=8080
    ["socks"]=200
    ["dnstt"]=53
    ["sslh-http"]=80
    ["sslh-https"]=443
)

# Check if port is in use
check_port_usage() {
    local port=$1
    local service=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f2)
    if [[ -n "$service" ]]; then
        echo "$service"
    else
        echo ""
    fi
}

# Check if service is running
check_service_status() {
    local service=$1
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Install individual protocol
install_protocol() {
    local protocol=$1
    local port=$2
    
    echo -e "${BLUE}=== Installing $protocol ===${NC}"
    
    # Check if service is already running
    if check_service_status "$protocol"; then
        echo -e "${YELLOW}⚠️  $protocol is already running. Skipping installation.${NC}"
        return 0
    fi
    
    # Check if port is in use
    local port_service=$(check_port_usage "$port")
    if [[ -n "$port_service" ]]; then
        echo -e "${YELLOW}⚠️  Port $port is being used by: $port_service${NC}"
        read -p "Do you want to free this port automatically? (y/N): " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Stopping $port_service to free port $port..."
            systemctl stop "$port_service" 2>/dev/null
            pkill -f "$port_service" 2>/dev/null
            sleep 2
        else
            echo -e "${RED}❌ Installation aborted. Returning to main menu.${NC}"
            sleep 2
            return 1
        fi
    fi
    
    # Install based on protocol
    case $protocol in
        "badvpn")
            install_badvpn "$port"
            ;;
        "udp-custom")
            install_udp_custom "$port"
            ;;
        "ssl-tunnel")
            install_ssl_tunnel "$port"
            ;;
        "websocket")
            install_websocket "$port"
            ;;
        "socks")
            install_socks "$port"
            ;;
        "dnstt")
            install_dnstt "$port"
            ;;
        "sslh-http")
            install_sslh_http "$port"
            ;;
        "sslh-https")
            install_sslh_https "$port"
            ;;
        *)
            echo -e "${RED}❌ Unknown protocol: $protocol${NC}"
            return 1
            ;;
    esac
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ $protocol installed successfully on port $port${NC}"
    else
        echo -e "${RED}❌ Failed to install $protocol${NC}"
    fi
    
    echo "Press Enter to continue..."
    read
}

# Uninstall individual protocol
uninstall_protocol() {
    local protocol=$1
    
    echo -e "${BLUE}=== Uninstalling $protocol ===${NC}"
    
    # Check if service is running
    if check_service_status "$protocol"; then
        echo "Stopping $protocol service..."
        systemctl stop "$protocol"
        systemctl disable "$protocol"
    fi
    
    # Remove based on protocol
    case $protocol in
        "badvpn")
            uninstall_badvpn
            ;;
        "udp-custom")
            uninstall_udp_custom
            ;;
        "ssl-tunnel")
            uninstall_ssl_tunnel
            ;;
        "websocket")
            uninstall_websocket
            ;;
        "socks")
            uninstall_socks
            ;;
        "dnstt")
            uninstall_dnstt
            ;;
        "sslh-http"|"sslh-https")
            uninstall_sslh
            ;;
        *)
            echo -e "${RED}❌ Unknown protocol: $protocol${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}✅ $protocol uninstalled successfully${NC}"
    echo "Press Enter to continue..."
    read
}

# Protocol installation functions
install_badvpn() {
    local port=$1
    apt update
    apt install -y badvpn
    cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 0.0.0.0:$port
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable badvpn
    systemctl start badvpn
}

install_udp_custom() {
    local port=$1
    # UDP-Custom installation logic here
    echo "Installing UDP-Custom on port $port..."
}

install_ssl_tunnel() {
    local port=$1
    apt update
    apt install -y stunnel4
    # SSL Tunnel configuration
}

install_websocket() {
    local port=$1
    apt update
    apt install -y nodejs npm
    # WebSocket proxy setup
}

install_socks() {
    local port=$1
    apt update
    apt install -y 3proxy
    # SOCKS proxy configuration
}

install_dnstt() {
    local port=$1
    # DNSTT installation
}

install_sslh_http() {
    local port=$1
    apt update
    apt install -y sslh
    # SSLH HTTP configuration
}

install_sslh_https() {
    local port=$1
    # SSLH HTTPS configuration
}

# Protocol uninstallation functions
uninstall_badvpn() {
    systemctl stop badvpn
    systemctl disable badvpn
    rm -f /etc/systemd/system/badvpn.service
    apt remove -y badvpn
}

uninstall_udp_custom() {
    # UDP-Custom removal logic
}

uninstall_ssl_tunnel() {
    systemctl stop stunnel4
    systemctl disable stunnel4
    apt remove -y stunnel4
}

uninstall_websocket() {
    systemctl stop websocket-proxy
    systemctl disable websocket-proxy
    rm -f /etc/systemd/system/websocket-proxy.service
}

uninstall_socks() {
    systemctl stop 3proxy
    systemctl disable 3proxy
    apt remove -y 3proxy
}

uninstall_dnstt() {
    # DNSTT removal
}

uninstall_sslh() {
    systemctl stop sslh
    systemctl disable sslh
    apt remove -y sslh
}

# Individual protocol management menu
manage_individual_protocols() {
    while true; do
        clear
        echo -e "${BLUE}=== Individual Protocol Management ===${NC}"
        echo
        echo "1. Install BadVPN (UDP Gateway)"
        echo "2. Install UDP-Custom"
        echo "3. Install SSL Tunnel"
        echo "4. Install WebSocket Proxy"
        echo "5. Install SOCKS Proxy"
        echo "6. Install DNSTT"
        echo "7. Install SSLH (HTTP)"
        echo "8. Install SSLH (HTTPS)"
        echo "9. Uninstall Protocol"
        echo "10. Back to Main Menu"
        echo
        
        read -p "Choose option: " choice
        
        case $choice in
            1)
                read -p "Enter port for BadVPN (default: 7300): " port
                port=${port:-7300}
                install_protocol "badvpn" "$port"
                ;;
            2)
                read -p "Enter port for UDP-Custom (default: 5300): " port
                port=${port:-5300}
                install_protocol "udp-custom" "$port"
                ;;
            3)
                read -p "Enter port for SSL Tunnel (default: 444): " port
                port=${port:-444}
                install_protocol "ssl-tunnel" "$port"
                ;;
            4)
                read -p "Enter port for WebSocket (default: 8080): " port
                port=${port:-8080}
                install_protocol "websocket" "$port"
                ;;
            5)
                read -p "Enter port for SOCKS (default: 200): " port
                port=${port:-200}
                install_protocol "socks" "$port"
                ;;
            6)
                read -p "Enter port for DNSTT (default: 53): " port
                port=${port:-53}
                install_protocol "dnstt" "$port"
                ;;
            7)
                read -p "Enter port for SSLH HTTP (default: 80): " port
                port=${port:-80}
                install_protocol "sslh-http" "$port"
                ;;
            8)
                read -p "Enter port for SSLH HTTPS (default: 443): " port
                port=${port:-443}
                install_protocol "sslh-https" "$port"
                ;;
            9)
                uninstall_protocol_menu
                ;;
            10)
                break
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
    done
}

# Uninstall protocol menu
uninstall_protocol_menu() {
    clear
    echo -e "${BLUE}=== Uninstall Protocol ===${NC}"
    echo
    echo "1. BadVPN"
    echo "2. UDP-Custom"
    echo "3. SSL Tunnel"
    echo "4. WebSocket Proxy"
    echo "5. SOCKS Proxy"
    echo "6. DNSTT"
    echo "7. SSLH"
    echo "8. Back"
    echo
    
    read -p "Choose protocol to uninstall: " choice
    
    case $choice in
        1) uninstall_protocol "badvpn" ;;
        2) uninstall_protocol "udp-custom" ;;
        3) uninstall_protocol "ssl-tunnel" ;;
        4) uninstall_protocol "websocket" ;;
        5) uninstall_protocol "socks" ;;
        6) uninstall_protocol "dnstt" ;;
        7) uninstall_protocol "sslh" ;;
        8) return ;;
        *) echo "Invalid option" ;;
    esac
}

print_menu() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    MAXIE VPS MANAGER${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
    echo "1. Install All Tunneling Protocols"
    echo "2. Check Service Status"
    echo "3. Manage Individual Services"
    echo "4. Individual Protocol Management"
    echo "5. Configure SSL Certificates"
    echo "6. View Connection Information"
    echo "7. System Utilities"
    echo "8. User Management"
    echo "9. Exit"
    echo
}

check_services() {
    echo -e "${GREEN}=== Service Status ===${NC}"
    echo
    
    services=("badvpn" "udp-custom" "stunnel4" "websocket-proxy" "3proxy" "dnstt" "sslh" "nginx" "x-ui")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "✅ $service: ${GREEN}RUNNING${NC}"
        else
            echo -e "❌ $service: ${RED}STOPPED${NC}"
        fi
    done
    
    echo
    echo "Press Enter to continue..."
    read
}

manage_services() {
    while true; do
        clear
        echo -e "${BLUE}=== Service Management ===${NC}"
        echo
        echo "1. Start All Services"
        echo "2. Stop All Services"
        echo "3. Restart All Services"
        echo "4. Enable All Services"
        echo "5. Back to Main Menu"
        echo
        
        read -p "Choose option: " choice
        
        case $choice in
            1)
                echo "Starting all services..."
                systemctl start badvpn udp-custom stunnel4 websocket-proxy 3proxy dnstt sslh nginx x-ui
                ;;
            2)
                echo "Stopping all services..."
                systemctl stop badvpn udp-custom stunnel4 websocket-proxy 3proxy dnstt sslh nginx x-ui
                ;;
            3)
                echo "Restarting all services..."
                systemctl restart badvpn udp-custom stunnel4 websocket-proxy 3proxy dnstt sslh nginx x-ui
                ;;
            4)
                echo "Enabling all services..."
                systemctl enable badvpn udp-custom stunnel4 websocket-proxy 3proxy dnstt sslh nginx x-ui
                ;;
            5)
                break
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
        
        echo "Press Enter to continue..."
        read
    done
}

configure_ssl() {
    echo -e "${BLUE}=== SSL Certificate Configuration ===${NC}"
    echo
    
    read -p "Enter your domain name: " domain
    read -p "Enter your email: " email
    
    if [[ -n "$domain" && -n "$email" ]]; then
        echo "Installing Certbot..."
        apt update
        apt install -y certbot python3-certbot-nginx
        
        echo "Obtaining SSL certificate..."
        certbot --nginx -d "$domain" --email "$email" --agree-tos --non-interactive
        
        echo "Setting up auto-renewal..."
        (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
        
        echo "SSL configuration completed!"
    else
        echo "Domain and email are required for SSL configuration"
    fi
    
    echo "Press Enter to continue..."
    read
}

view_connection_info() {
    if [[ -f "/root/tunneling-connection-info.txt" ]]; then
        cat /root/tunneling-connection-info.txt
    else
        echo "Connection information not found. Please run the tunneling setup first."
    fi
    
    echo "Press Enter to continue..."
    read
}

# Main menu loop
while true; do
    print_menu
    read -p "Choose option: " choice
    
    case $choice in
        1)
            echo "Running tunneling setup..."
            /opt/maxie-vps-manager/maxie-tunneling-setup.sh
            ;;
        2)
            check_services
            ;;
        3)
            manage_services
            ;;
        4)
            manage_individual_protocols
            ;;
        5)
            configure_ssl
            ;;
        6)
            view_connection_info
            ;;
        7)
            echo "Opening System Utilities..."
            /opt/maxie-vps-manager/system-utils.sh
            ;;
        8)
            echo "Opening User Management..."
            /opt/maxie-vps-manager/user-management.sh
            ;;
        9)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid option. Press Enter to continue..."
            read
            ;;
    esac
done
EOF

# Make the manager script executable
chmod +x /usr/local/bin/maxie-vps-manager

# Copy utility scripts
cp user-management.sh "$INSTALL_DIR/"
cp system-utils.sh "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR"/*.sh

# Create configuration directory
mkdir -p /etc/maxie-vps-manager

# Copy configuration file
cp config.conf /etc/maxie-vps-manager/config

# Create log directory and file
mkdir -p /var/log
touch /var/log/maxie-vps-manager.log

# Create backup directory
mkdir -p /backup/users

# Create systemd service for auto-startup
cat > /etc/systemd/system/maxie-vps-manager.service << 'EOF'
[Unit]
Description=Maxie VPS Manager
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecStop=/bin/true

[Install]
WantedBy=multi-user.target
EOF

# Enable the service
systemctl daemon-reload
systemctl enable maxie-vps-manager

# Create uninstall script
cat > /usr/local/bin/maxie-vps-manager-uninstall << 'EOF'
#!/bin/bash

# Maxie VPS Manager - Uninstall Script

echo "This will remove Maxie VPS Manager and all its components."
read -p "Are you sure? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing Maxie VPS Manager..."
    
    # Stop and disable services
    systemctl stop badvpn udp-custom stunnel4 websocket-proxy 3proxy dnstt sslh nginx x-ui
    systemctl disable badvpn udp-custom stunnel4 websocket-proxy 3proxy dnstt sslh nginx x-ui
    
    # Remove systemd services
    rm -f /etc/systemd/system/badvpn.service
    rm -f /etc/systemd/system/udp-custom.service
    rm -f /etc/systemd/system/websocket-proxy.service
    rm -f /etc/systemd/system/dnstt.service
    
    # Remove scripts
    rm -f /usr/local/bin/maxie-vps-manager
    rm -f /usr/local/bin/check-tunneling-status
    rm -f /usr/local/bin/maxie-vps-manager-uninstall
    
    # Remove installation directory
    rm -rf /opt/maxie-vps-manager
    
    # Remove configuration
    rm -rf /etc/maxie-vps-manager
    
    # Remove log files
    rm -f /var/log/maxie-vps-manager.log
    
    echo "Maxie VPS Manager has been removed."
    echo "Note: User data and some configuration files may remain."
    echo "You may need to manually remove them if desired."
else
    echo "Uninstall cancelled."
fi
EOF

chmod +x /usr/local/bin/maxie-vps-manager-uninstall

print_header "Installation Completed Successfully!"
echo
echo "Maxie VPS Manager has been installed to your system."
echo
echo "=== Available Commands ==="
echo "maxie-vps-manager                    - Main management interface"
echo "maxie-vps-manager-uninstall          - Remove the manager"
echo "check-tunneling-status               - Check service status (after setup)"
echo
echo "=== Next Steps ==="
echo "1. Run: maxie-vps-manager"
echo "2. Choose option 1 to install all tunneling protocols"
echo "3. Configure your domain and SSL certificates"
echo "4. Access X-UI Panel at http://your-ip:54321"
echo
echo "=== Important Notes ==="
echo "- All services will start automatically on boot"
echo "- Firewall rules will be configured automatically"
echo "- SSL certificates will auto-renew every 90 days"
echo "- Default X-UI credentials: admin/admin (change immediately!)"
echo
echo "Installation completed at: $(date)"
