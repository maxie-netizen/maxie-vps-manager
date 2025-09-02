#!/bin/bash

# Maxie VPS Manager - Complete Tunneling Protocol Setup Script
# This script installs and configures all tunneling protocols for your VPS
# Compatible with Ubuntu 20.04/22.04/24.04

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN=""
EMAIL=""
SSH_PORT="22"
FIREWALL_ENABLE=true

# Protocol ports
BADVPN_PORT="7300"
UDP_CUSTOM_PORT="5300"
SSL_TUNNEL_PORT="444"
WEBSOCKET_PORT="8080"
SOCKS_PORT="200"
DNSTT_PORT="53"
SSLH_PORT_HTTP="80"
SSLH_PORT_HTTPS="443"

# Log file
LOG_FILE="/var/log/maxie-tunneling-setup.log"

# Bandwidth monitoring
BANDWIDTH_LOG="/var/log/bandwidth.log"
BANDWIDTH_RESET_TIME="00:00" # Midnight Africa/Nairobi timezone

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "$(date): [INFO] $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "$(date): [WARNING] $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$(date): [ERROR] $1" >> "$LOG_FILE"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to check system requirements
check_system() {
    print_status "Checking system requirements..."
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        print_error "Cannot determine OS version"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        print_warning "This script is designed for Ubuntu. Other Debian-based distros may work but are not guaranteed."
    fi
    
    # Check architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" && "$ARCH" != "amd64" && "$ARCH" != "aarch64" ]]; then
        print_warning "Architecture $ARCH is not officially supported. Some protocols may not work."
    fi
    
    # Check RAM
    TOTAL_RAM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    if [[ $TOTAL_RAM -lt 512 ]]; then
        print_error "Insufficient RAM. Minimum 512MB required, found ${TOTAL_RAM}MB"
        exit 1
    fi
    
    # Check storage
    TOTAL_STORAGE=$(df -BG / | awk 'NR==2{printf "%.0f", $2}' | sed 's/G//')
    if [[ $TOTAL_STORAGE -lt 10 ]]; then
        print_error "Insufficient storage. Minimum 10GB required, found ${TOTAL_STORAGE}GB"
        exit 1
    fi
    
    print_status "System requirements check passed"
}

# Function to update system
update_system() {
    print_status "Updating system packages..."
    apt update -y >> "$LOG_FILE" 2>&1
    apt install -y curl wget git ufw >> "$LOG_FILE" 2>&1
    print_status "System updated successfully (upgrade skipped to avoid VM slowdown)"
}

# Function to configure firewall
configure_firewall() {
    if [[ "$FIREWALL_ENABLE" == true ]]; then
        print_status "Configuring UFW firewall..."
        
        # Reset UFW
        ufw --force reset >> "$LOG_FILE" 2>&1
        
        # Set default policies
        ufw default deny incoming >> "$LOG_FILE" 2>&1
        ufw default allow outgoing >> "$LOG_FILE" 2>&1
        
        # Allow SSH
        ufw allow $SSH_PORT/tcp >> "$LOG_FILE" 2>&1
        
        # Allow tunneling protocol ports
        ufw allow $BADVPN_PORT/udp >> "$LOG_FILE" 2>&1
        ufw allow $UDP_CUSTOM_PORT/udp >> "$LOG_FILE" 2>&1
        ufw allow $SSL_TUNNEL_PORT/tcp >> "$LOG_FILE" 2>&1
        ufw allow $WEBSOCKET_PORT/tcp >> "$LOG_FILE" 2>&1
        ufw allow $SOCKS_PORT/tcp >> "$LOG_FILE" 2>&1
        ufw allow $DNSTT_PORT/udp >> "$LOG_FILE" 2>&1
        
        # Allow nginx on standard ports
        ufw allow 80/tcp >> "$LOG_FILE" 2>&1
        ufw allow 443/tcp >> "$LOG_FILE" 2>&1
        
        # Allow SSLH on alternative ports to avoid conflicts
        ufw allow 8443/tcp >> "$LOG_FILE" 2>&1
        ufw allow 8081/tcp >> "$LOG_FILE" 2>&1
        
        # Allow additional WebSocket proxy ports
        ufw allow 2222/tcp >> "$LOG_FILE" 2>&1  # SSH WebSocket
        ufw allow 8082/tcp >> "$LOG_FILE" 2>&1  # HTTP WebSocket
        ufw allow 3128/tcp >> "$LOG_FILE" 2>&1  # Custom proxy
        ufw allow 8083/tcp >> "$LOG_FILE" 2>&1  # Custom proxy
        
        # Enable UFW
        ufw --force enable >> "$LOG_FILE" 2>&1
        
        print_status "Firewall configured successfully"
    fi
}

# Function to check SSL certificates with detailed information
check_ssl_certificates() {
    print_status "Checking SSL certificates..."
    
    # Check for existing certificates
    local cert_paths=(
        "/etc/letsencrypt/live"
        "/etc/ssl/certs"
        "/etc/ssl/private"
        "/root/.acme.sh"
    )
    
    local cert_found=false
    local cert_path=""
    local cert_domain=""
    local cert_expiry=""
    
    for path in "${cert_paths[@]}"; do
        if [[ -d "$path" ]]; then
            # Look for certificate files
            local cert_file=$(find "$path" -name "*.crt" -o -name "*.pem" -o -name "fullchain.pem" 2>/dev/null | head -1)
            if [[ -n "$cert_file" ]]; then
                cert_found=true
                cert_path="$path"
                
                # Extract domain from certificate
                cert_domain=$(openssl x509 -noout -subject -in "$cert_file" 2>/dev/null | sed -n 's/.*CN = \([^,]*\).*/\1/p')
                if [[ -z "$cert_domain" ]]; then
                    cert_domain=$(openssl x509 -noout -subject -in "$cert_file" 2>/dev/null | sed -n 's/.*CN=\([^,]*\).*/\1/p')
                fi
                
                # Get expiry date
                cert_expiry=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
                
                break
            fi
        fi
    done
    
    if [[ "$cert_found" == true ]]; then
        print_status "SSL certificate found:"
        echo "  Path: $cert_path"
        echo "  Domain: ${cert_domain:-"Unknown"}"
        echo "  Expires: ${cert_expiry:-"Unknown"}"
        
        # Check if certificate is valid
        if openssl x509 -checkend 86400 -noout -in "$cert_file" >/dev/null 2>&1; then
            print_status "Certificate is valid and not expiring soon"
            
            # Store certificate info for use by SSL protocols
            export SSL_CERT_PATH="$cert_path"
            export SSL_CERT_DOMAIN="$cert_domain"
            
            return 0
        else
            print_warning "Certificate is expired or expiring soon"
            return 1
        fi
    fi
    
    print_warning "No valid SSL certificates found"
    return 1
}

# Function to delete SSL certificate
delete_ssl_certificate() {
    print_status "SSL Certificate Management"
    echo
    
    if check_ssl_certificates; then
        echo "Current certificate:"
        echo "  Domain: $SSL_CERT_DOMAIN"
        echo "  Path: $SSL_CERT_PATH"
        echo
        
        read -p "Do you want to delete this certificate? (y/N): " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Deleting SSL certificate..."
            
            # Stop services that might be using the certificate
            systemctl stop nginx 2>/dev/null
            systemctl stop sslh 2>/dev/null
            
            # Remove Let's Encrypt certificate
            if [[ "$SSL_CERT_PATH" == "/etc/letsencrypt/live"* ]]; then
                certbot delete --cert-name "$SSL_CERT_DOMAIN" --non-interactive >> "$LOG_FILE" 2>&1
                print_status "Let's Encrypt certificate deleted"
            else
                # Remove manual certificates
                rm -rf "$SSL_CERT_PATH"/*.crt "$SSL_CERT_PATH"/*.pem 2>/dev/null
                print_status "Manual certificate deleted"
            fi
            
            # Clear exported variables
            unset SSL_CERT_PATH
            unset SSL_CERT_DOMAIN
            
            # Restart services
            systemctl start sslh 2>/dev/null
            systemctl start nginx 2>/dev/null
            
            print_status "Certificate deleted successfully"
        else
            print_status "Certificate deletion cancelled"
        fi
    else
        print_warning "No certificates to delete"
    fi
}

# Function to request SSL certificate
request_ssl_certificate() {
    print_status "Requesting SSL certificate..."
    
    if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
        print_error "Domain and email required for SSL certificate"
        return 1
    fi
    
    # Install Certbot
    apt install -y certbot >> "$LOG_FILE" 2>&1
    
    # Check if domain resolves
    if ! nslookup "$DOMAIN" >/dev/null 2>&1; then
        print_error "Domain $DOMAIN does not resolve. Please check DNS records."
        return 1
    fi
    
    # Stop services that might be using port 80/443 temporarily
    print_status "Temporarily stopping services using ports 80/443..."
    systemctl stop nginx 2>/dev/null
    systemctl stop sslh 2>/dev/null
    systemctl stop apache2 2>/dev/null
    
    # Wait a moment for ports to be freed
    sleep 3
    
    # Check if ports are free
    if ss -tlnp 2>/dev/null | grep -q ":80 "; then
        print_error "Port 80 is still in use. Cannot proceed with SSL certificate request."
        print_error "Please stop the service using port 80 manually and try again."
        return 1
    fi
    
    # Request certificate using standalone method (avoids nginx conflicts)
    print_status "Requesting certificate for domain: $DOMAIN using standalone method..."
    if certbot certonly --standalone -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive >> "$LOG_FILE" 2>&1; then
        print_status "SSL certificate obtained successfully"
        
        # Set up auto-renewal
        (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
        
        # Update certificate info
        export SSL_CERT_PATH="/etc/letsencrypt/live/$DOMAIN"
        export SSL_CERT_DOMAIN="$DOMAIN"
        
        # Restart services
        print_status "Restarting services..."
        systemctl start sslh 2>/dev/null
        systemctl start nginx 2>/dev/null
        
        return 0
    else
        print_error "Failed to obtain SSL certificate. Check logs for details."
        
        # Restart services even if certificate request failed
        print_status "Restarting services..."
        systemctl start sslh 2>/dev/null
        systemctl start nginx 2>/dev/null
        
        return 1
    fi
}

# Function to check and handle port conflicts
check_port_conflicts() {
    local port="$1"
    local service_name="$2"
    
    print_status "Checking port $port for conflicts..."
    
    # Check if port is already in use
    local conflicting_service=$(ss -tlnp 2>/dev/null | grep ":$port " | awk '{print $NF}' | cut -d'/' -f2)
    
    if [[ -n "$conflicting_service" ]]; then
        print_warning "Port $port is already in use by: $conflicting_service"
        
        # Ask user what to do
        echo
        echo "Options:"
        echo "1. Stop the conflicting service and continue"
        echo "2. Use a different port"
        echo "3. Skip this service"
        echo
        
        read -p "Select option (1-3): " choice
        
        case $choice in
            1)
                print_status "Stopping conflicting service: $conflicting_service"
                systemctl stop "$conflicting_service" 2>/dev/null
                sleep 2
                
                # Check if port is now free
                if ! ss -tlnp 2>/dev/null | grep -q ":$port "; then
                    print_status "Port $port is now free"
                    return 0
                else
                    print_error "Failed to free port $port"
                    return 1
                fi
                ;;
            2)
                read -p "Enter new port number: " new_port
                if [[ "$new_port" =~ ^[0-9]+$ ]] && [[ $new_port -gt 0 ]] && [[ $new_port -lt 65536 ]]; then
                    print_status "Using new port: $new_port"
                    return 2 # Signal to use new port
                else
                    print_error "Invalid port number"
                    return 1
                fi
                ;;
            3)
                print_status "Skipping $service_name installation"
                return 3 # Signal to skip
                ;;
            *)
                print_error "Invalid choice, skipping $service_name"
                return 3
                ;;
        esac
    else
        print_status "Port $port is free"
        return 0
    fi
}

# Function to setup bandwidth monitoring with iptables
setup_bandwidth_monitoring() {
    print_status "Setting up bandwidth monitoring..."
    
    # Install required packages
    apt install -y iptables-persistent >> "$LOG_FILE" 2>&1
    
    # Create bandwidth monitoring script
    cat > /usr/local/bin/bandwidth_monitor.sh << 'EOF'
#!/bin/bash

# Bandwidth monitoring script
LOG_FILE="/var/log/bandwidth_daily.log"
TIMEZONE="Africa/Nairobi"

# Function to reset daily counters
reset_daily_counters() {
    echo "=== Daily Bandwidth Reset - $(TZ=$TIMEZONE date '+%Y-%m-%d %H:%M:%S') ===" > "$LOG_FILE"
    echo "User bandwidth usage:" >> "$LOG_FILE"
    
    # Reset iptables counters
    iptables -Z OUTPUT
    
    # Log current usage before reset
    iptables -L OUTPUT -n -v | grep "bandwidth_monitor" | while read line; do
        if [[ $line =~ ^[0-9]+ ]]; then
            bytes=$(echo $line | awk '{print $1}')
            user=$(echo $line | awk '{print $NF}')
            if [[ $bytes -gt 0 ]]; then
                echo "  $user: $(numfmt --to=iec $bytes)" >> "$LOG_FILE"
            fi
        fi
    done
    
    echo "" >> "$LOG_FILE"
}

# Function to setup iptables rules for bandwidth monitoring
setup_iptables_rules() {
    # Create custom chain for bandwidth monitoring
    iptables -N bandwidth_monitor 2>/dev/null
    
    # Add rules for each user (example users - modify as needed)
    local users=("user1" "user2" "user3" "admin")
    
    for user in "${users[@]}"; do
        # Add rule to track bandwidth for this user
        iptables -A OUTPUT -m owner --uid-owner $(id -u "$user" 2>/dev/null || echo 1000) -j bandwidth_monitor
        iptables -A bandwidth_monitor -m owner --uid-owner $(id -u "$user" 2>/dev/null || echo 1000) -j RETURN
    done
    
    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4
}

# Main execution
case "$1" in
    "setup")
        setup_iptables_rules
        echo "Bandwidth monitoring rules set up"
        ;;
    "reset")
        reset_daily_counters
        echo "Daily bandwidth counters reset"
        ;;
    "status")
        echo "Current bandwidth usage:"
        iptables -L OUTPUT -n -v | grep "bandwidth_monitor"
        ;;
    *)
        echo "Usage: $0 {setup|reset|status}"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/bandwidth_monitor.sh
    
    # Setup iptables rules
    /usr/local/bin/bandwidth_monitor.sh setup
    
    # Create cron job to reset daily at midnight Africa/Nairobi timezone
    (crontab -l 2>/dev/null; echo "0 0 * * * TZ=Africa/Nairobi /usr/local/bin/bandwidth_monitor.sh reset") | crontab -
    
    # Create daily reset script
    cat > /etc/cron.daily/bandwidth-reset << 'EOF'
#!/bin/bash
TZ=Africa/Nairobi /usr/local/bin/bandwidth_monitor.sh reset
EOF
    
    chmod +x /etc/cron.daily/bandwidth-reset
    
    print_status "Bandwidth monitoring set up successfully"
    print_status "Daily reset scheduled at midnight (Africa/Nairobi timezone)"
}

# Function to install BadVPN
install_badvpn() {
    print_status "Installing BadVPN..."
    
    # Install dependencies
    apt install -y build-essential cmake libssl-dev >> "$LOG_FILE" 2>&1
    
    # Clone and build BadVPN
    cd /tmp
    git clone https://github.com/ambrop72/badvpn.git >> "$LOG_FILE" 2>&1
    cd badvpn
    mkdir build
    cd build
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local >> "$LOG_FILE" 2>&1
    make >> "$LOG_FILE" 2>&1
    make install >> "$LOG_FILE" 2>&1
    
    # Create systemd service
    cat > /etc/systemd/system/badvpn.service << 'BADVPN_SERVICE_EOF'
[Unit]
Description=BadVPN UDP Tunneling Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:PORT_PLACEHOLDER --max-clients 1000 --max-connections-for-client 1000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
BADVPN_SERVICE_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$BADVPN_PORT/g" /etc/systemd/system/badvpn.service
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable badvpn
    systemctl start badvpn
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet badvpn && ss -tlnp | grep -q ":$BADVPN_PORT "; then
        print_status "BadVPN installed and started on port $BADVPN_PORT"
        return 0
    else
        print_error "BadVPN failed to start properly"
        return 1
    fi
}

# Function to install UDP-Custom
install_udp_custom() {
    print_status "Installing UDP-Custom..."
    
    # Install dependencies
    apt install -y python3 python3-pip >> "$LOG_FILE" 2>&1
    
    # Create UDP-Custom script
    cat > /usr/local/bin/udp-custom << 'EOF'
#!/usr/bin/env python3
import socket
import threading
import time
import sys

class UDPCustom:
    def __init__(self, listen_port=5300):
        self.listen_port = listen_port
        self.running = False
        self.clients = {}
        
    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', self.listen_port))
        print(f"UDP-Custom listening on port {self.listen_port}")
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if addr not in self.clients:
                    self.clients[addr] = time.time()
                    print(f"New client connected: {addr}")
                
                # Echo back for testing (replace with actual proxy logic)
                self.sock.sendto(data, addr)
                
            except Exception as e:
                if self.running:
                    print(f"Error: {e}")
                    break
        
        self.sock.close()
    
    def stop(self):
        self.running = False

if __name__ == "__main__":
    udp = UDPCustom()
    try:
        udp.start()
    except KeyboardInterrupt:
        print("Shutting down UDP-Custom...")
        udp.stop()
EOF
    
    chmod +x /usr/local/bin/udp-custom
    
    # Create systemd service
    cat > /etc/systemd/system/udp-custom.service << 'UDP_SERVICE_EOF'
[Unit]
Description=UDP-Custom Proxy Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/udp-custom
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UDP_SERVICE_EOF
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable udp-custom
    systemctl start udp-custom
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet udp-custom && ss -tlnp | grep -q ":$UDP_CUSTOM_PORT "; then
        print_status "UDP-Custom installed and started on port $UDP_CUSTOM_PORT"
        return 0
    else
        print_error "UDP-Custom failed to start properly"
        return 1
    fi
}

# Function to install SSL Tunnel
install_ssl_tunnel() {
    print_status "Installing SSL Tunnel..."
    
    # Install stunnel
    apt install -y stunnel4 >> "$LOG_FILE" 2>&1
    
    # Check for SSL certificate
    local cert_file=""
    local key_file=""
    
    if [[ -n "$SSL_CERT_PATH" && -n "$SSL_CERT_DOMAIN" ]]; then
        # Use detected certificate
        if [[ -f "$SSL_CERT_PATH/fullchain.pem" ]]; then
            cert_file="$SSL_CERT_PATH/fullchain.pem"
            key_file="$SSL_CERT_PATH/privkey.pem"
            print_status "Using detected SSL certificate: $SSL_CERT_DOMAIN"
        elif [[ -f "$SSL_CERT_PATH/cert.pem" ]]; then
            cert_file="$SSL_CERT_PATH/cert.pem"
            key_file="$SSL_CERT_PATH/key.pem"
            print_status "Using detected SSL certificate: $SSL_CERT_DOMAIN"
        fi
    fi
    
    # If no certificate found, generate self-signed
    if [[ -z "$cert_file" ]]; then
        print_warning "No SSL certificate found, generating self-signed certificate"
        cert_file="/etc/stunnel/stunnel.pem"
        key_file="/etc/stunnel/stunnel.pem"
        
        # Generate self-signed certificate
        openssl req -new -x509 -days 365 -nodes -out "$cert_file" -keyout "$key_file" -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" >> "$LOG_FILE" 2>&1
    fi
    
    # Create stunnel configuration
    cat > /etc/stunnel/stunnel.conf << 'STUNNEL_CONFIG_EOF'
[ssl-tunnel]
accept = 0.0.0.0:SSL_PORT_PLACEHOLDER
connect = 127.0.0.1:22
cert = CERT_FILE_PLACEHOLDER
key = KEY_FILE_PLACEHOLDER
STUNNEL_CONFIG_EOF
    
    # Replace placeholders
    sed -i "s/SSL_PORT_PLACEHOLDER/$SSL_TUNNEL_PORT/g" /etc/stunnel/stunnel.conf
    sed -i "s|CERT_FILE_PLACEHOLDER|$cert_file|g" /etc/stunnel/stunnel.conf
    sed -i "s|KEY_FILE_PLACEHOLDER|$key_file|g" /etc/stunnel/stunnel.conf
    
    # Enable stunnel
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
    
    # Start stunnel
    systemctl enable stunnel4
    systemctl start stunnel4
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet stunnel4 && ss -tlnp | grep -q ":$SSL_TUNNEL_PORT "; then
        print_status "SSL Tunnel installed and started on port $SSL_TUNNEL_PORT"
        print_status "Certificate: ${cert_file:-"Self-signed"}"
        return 0
    else
        print_error "SSL Tunnel failed to start properly"
        return 1
    fi
}

# Function to install WebSocket Proxy
install_websocket_proxy() {
    print_status "Installing WebSocket Proxy..."
    
    # Install Node.js and npm
    apt update >> "$LOG_FILE" 2>&1
    apt install -y nodejs npm curl >> "$LOG_FILE" 2>&1
    
    # Create WebSocket proxy directory
    mkdir -p /opt/websocket-proxy
    
    # Create package.json for local dependencies
    cat > /opt/websocket-proxy/package.json << 'PACKAGE_EOF'
{
  "name": "websocket-proxy",
  "version": "1.0.0",
  "description": "WebSocket SSH Proxy Server",
  "main": "websocket-proxy.js",
  "dependencies": {
    "ws": "^8.13.0"
  },
  "scripts": {
    "start": "node websocket-proxy.js"
  }
}
PACKAGE_EOF
    
    # Create WebSocket proxy script with SSH tunneling and multiple protocols
    cat > /opt/websocket-proxy/websocket-proxy.js << 'WS_EOF'
#!/usr/bin/env node

const WebSocket = require('ws');
const net = require('net');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

// Configuration
const PORTS = {
    // SSH WebSocket ports
    'ssh-ws-80': { port: 80, protocol: 'ssh', target: { host: '127.0.0.1', port: 22 } },
    'ssh-ws-22': { port: 22, protocol: 'ssh', target: { host: '127.0.0.1', port: 22 } },
    'ssh-ws-8080': { port: 8080, protocol: 'ssh', target: { host: '127.0.0.1', port: 22 } },
    'ssh-ws-2222': { port: 2222, protocol: 'ssh', target: { host: '127.0.0.1', port: 22 } },
    
    // SSL/TLS WebSocket ports
    'ssl-ws-443': { port: 443, protocol: 'ssl', target: { host: '127.0.0.1', port: 443 } },
    'ssl-ws-8443': { port: 8443, protocol: 'ssl', target: { host: '127.0.0.1', port: 443 } },
    
    // HTTP WebSocket ports
    'http-ws-8081': { port: 8081, protocol: 'http', target: { host: '127.0.0.1', port: 80 } },
    'http-ws-8082': { port: 8082, protocol: 'http', target: { host: '127.0.0.1', port: 80 } },
    
    // Custom proxy ports
    'proxy-3128': { port: 3128, protocol: 'proxy', target: { host: '127.0.0.1', port: 3128 } },
    'proxy-8083': { port: 8083, protocol: 'proxy', target: { host: '127.0.0.1', port: 8083 } }
};

// SSL certificate paths (if available)
const SSL_CERT_PATH = '/etc/letsencrypt/live';
const SSL_KEY_PATH = '/etc/letsencrypt/live';

console.log('🚀 Starting Multi-Protocol WebSocket Proxy Server...');
console.log('🌟 DEV MAXWELL - Advanced Tunneling Solution');

// Function to check if SSL certificates exist
function getSSLCertificates() {
    try {
        const certDir = fs.readdirSync(SSL_CERT_PATH);
        const domain = certDir[0]; // Use first domain found
        if (domain) {
            const certFile = path.join(SSL_CERT_PATH, domain, 'fullchain.pem');
            const keyFile = path.join(SSL_CERT_PATH, domain, 'privkey.pem');
            
            if (fs.existsSync(certFile) && fs.existsSync(keyFile)) {
                console.log(`✅ SSL certificates found for domain: ${domain}`);
                return { cert: certFile, key: keyFile, domain };
            }
        }
    } catch (error) {
        console.log('ℹ️  No SSL certificates found, using HTTP only');
    }
    return null;
}

// Create HTTP server for WebSocket upgrades
const httpServer = http.createServer((req, res) => {
    handleWebSocketUpgrade(req, res, 'http');
});

// Create HTTPS server if SSL certificates are available
let httpsServer = null;
const sslCerts = getSSLCertificates();
if (sslCerts) {
    try {
        httpsServer = https.createServer({
            cert: fs.readFileSync(sslCerts.cert),
            key: fs.readFileSync(sslCerts.key)
        }, (req, res) => {
            handleWebSocketUpgrade(req, res, 'https');
        });
        console.log('🔐 HTTPS server created with SSL certificates');
    } catch (error) {
        console.log('⚠️  Failed to create HTTPS server:', error.message);
    }
}

// Handle WebSocket upgrade requests
function handleWebSocketUpgrade(req, res, protocol) {
    if (req.headers.upgrade && req.headers.upgrade.toLowerCase() === 'websocket') {
        const port = req.socket.localPort;
        const portConfig = Object.values(PORTS).find(p => p.port === port);
        
        if (portConfig) {
            const upgradeResponse = `HTTP/1.1 101 DEV MAXWELL Switching Protocols\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Accept: ${req.headers['sec-websocket-key']}\r
X-Protocol: ${portConfig.protocol}\r
X-Target: ${portConfig.target.host}:${portConfig.target.port}\r
\r
`;
            
            res.write(upgradeResponse);
            res.end();
            
            console.log(`🔗 WebSocket Upgrade Request (${protocol.toUpperCase()})`);
            console.log(`📡 Protocol: ${portConfig.protocol.toUpperCase()}`);
            console.log(`🌐 Port: ${port} → ${portConfig.target.host}:${portConfig.target.port}`);
            console.log(`✅ Status: 101 DEV MAXWELL Switching Protocols`);
        } else {
            res.writeHead(400);
            res.end('Port not configured for WebSocket');
        }
    } else {
        res.writeHead(400);
        res.end('WebSocket upgrade required');
    }
}

// Create WebSocket server for HTTP
const httpWss = new WebSocket.Server({ server: httpServer });

// Create WebSocket server for HTTPS
let httpsWss = null;
if (httpsServer) {
    httpsWss = new WebSocket.Server({ server: httpsServer });
}

// Handle WebSocket connections
function handleWebSocketConnection(ws, req, protocol) {
    const port = req.socket.localPort;
    const portConfig = Object.values(PORTS).find(p => p.port === port);
    
    if (!portConfig) {
        ws.close(1000, 'Port not configured');
        return;
    }
    
    console.log(`🌟 New ${portConfig.protocol.toUpperCase()} WebSocket connection`);
    console.log(`📍 Client IP: ${req.socket.remoteAddress}`);
    console.log(`🌐 Port: ${port} (${portConfig.protocol})`);
    console.log(`🎯 Target: ${portConfig.target.host}:${portConfig.target.port}`);
    
    // Create connection to target service
    const tcpSocket = net.createConnection(portConfig.target.port, portConfig.target.host);
    
    // Handle WebSocket messages
    ws.on('message', function message(data) {
        try {
            tcpSocket.write(data);
            console.log(`📤 ${portConfig.protocol.toUpperCase()} → Target: ${data.length} bytes`);
        } catch (error) {
            console.error(`Error writing to ${portConfig.protocol} target:`, error);
        }
    });
    
    // Handle target responses
    tcpSocket.on('data', function(data) {
        try {
            ws.send(data);
            console.log(`📥 Target → ${portConfig.protocol.toUpperCase()}: ${data.length} bytes`);
        } catch (error) {
            console.error(`Error sending to WebSocket:`, error);
        }
    });
    
    // Handle connection close
    ws.on('close', function() {
        console.log(`🔌 ${portConfig.protocol.toUpperCase()} WebSocket connection closed`);
        tcpSocket.destroy();
    });
    
    tcpSocket.on('close', function() {
        console.log(`🔌 ${portConfig.protocol.toUpperCase()} target connection closed`);
        ws.close();
    });
    
    // Handle errors
    tcpSocket.on('error', function(err) {
        console.log(`❌ ${portConfig.protocol.toUpperCase()} target error:`, err.message);
        ws.close();
    });
    
    ws.on('error', function(err) {
        console.log(`❌ ${portConfig.protocol.toUpperCase()} WebSocket error:`, err.message);
        tcpSocket.destroy();
    });
}

// Set up HTTP WebSocket connections
httpWss.on('connection', (ws, req) => handleWebSocketConnection(ws, req, 'http'));

// Set up HTTPS WebSocket connections
if (httpsWss) {
    httpsWss.on('connection', (ws, req) => handleWebSocketConnection(ws, req, 'https'));
}

// Start HTTP server on configured ports
Object.values(PORTS).forEach(portConfig => {
    if (portConfig.protocol === 'http' || portConfig.protocol === 'ssh' || portConfig.protocol === 'proxy') {
        try {
            httpServer.listen(portConfig.port, '0.0.0.0', () => {
                console.log(`🚀 HTTP WebSocket Server Started`);
                console.log(`📍 Port: ${portConfig.port} (${portConfig.protocol.toUpperCase()})`);
                console.log(`🎯 Target: ${portConfig.target.host}:${portConfig.target.port}`);
            });
        } catch (err) {
            console.log(`❌ Failed to bind HTTP to port ${portConfig.port}:`, err.message);
        }
    }
});

// Start HTTPS server on SSL ports
if (httpsServer) {
    Object.values(PORTS).forEach(portConfig => {
        if (portConfig.protocol === 'ssl') {
            try {
                httpsServer.listen(portConfig.port, '0.0.0.0', () => {
                    console.log(`🔐 HTTPS WebSocket Server Started`);
                    console.log(`📍 Port: ${portConfig.port} (${portConfig.protocol.toUpperCase()})`);
                    console.log(`🎯 Target: ${portConfig.target.host}:${portConfig.target.port}`);
                    console.log(`🔒 SSL: ${sslCerts.domain}`);
                });
            } catch (err) {
                console.log(`❌ Failed to bind HTTPS to port ${portConfig.port}:`, err.message);
            }
        }
    });
}

// Display server status
console.log('\n🔗 WebSocket Proxy Server Configuration:');
Object.values(PORTS).forEach(portConfig => {
    const protocol = portConfig.protocol === 'ssl' ? 'HTTPS' : 'HTTP';
    console.log(`  ${protocol} Port ${portConfig.port} → ${portConfig.target.host}:${portConfig.target.port} (${portConfig.protocol.toUpperCase()})`);
});

console.log('\n🌟 Ready for WebSocket connections!');
console.log('🔐 SSL/TLS support:', sslCerts ? `Enabled (${sslCerts.domain})` : 'Disabled');
console.log('🌐 SSH tunneling on ports: 80, 22, 8080, 2222');
console.log('🔒 SSL/TLS on ports: 443, 8443');
console.log('🌍 HTTP proxy on ports: 8081, 8082');
console.log('🔄 Custom proxy on ports: 3128, 8083');

// Handle server errors
httpServer.on('error', (err) => {
    console.log('❌ HTTP server error:', err.message);
});

if (httpsServer) {
    httpsServer.on('error', (err) => {
        console.log('❌ HTTPS server error:', err.message);
    });
}

// Graceful shutdown
function gracefulShutdown(signal) {
    console.log(`\n📡 Received ${signal}, shutting down gracefully...`);
    
    if (httpServer) {
        httpServer.close(() => {
            console.log('🔌 HTTP server closed');
        });
    }
    
    if (httpsServer) {
        httpsServer.close(() => {
            console.log('🔌 HTTPS server closed');
        });
    }
    
    setTimeout(() => {
        console.log('🚀 Server shutdown complete');
        process.exit(0);
    }, 1000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
WS_EOF
    
    # Install dependencies locally
    print_status "Installing WebSocket dependencies..."
    cd /opt/websocket-proxy
    npm install --production >> "$LOG_FILE" 2>&1
    
    if [[ $? -ne 0 ]]; then
        print_error "Failed to install npm dependencies"
        return 1
    fi
    
    # Make script executable
    chmod +x /opt/websocket-proxy/websocket-proxy.js
    
    # Create systemd service
    cat > /etc/systemd/system/websocket-proxy.service << 'WS_SERVICE_EOF'
[Unit]
Description=WebSocket SSH Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/node /opt/websocket-proxy/websocket-proxy.js
WorkingDirectory=/opt/websocket-proxy
Restart=always
RestartSec=5
User=root
Group=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
WS_SERVICE_EOF
    
    # Start WebSocket service
    print_status "Starting WebSocket proxy service..."
    systemctl daemon-reload
    systemctl enable websocket-proxy
    
    # Try to start the service
    if systemctl start websocket-proxy; then
        print_status "WebSocket proxy started successfully"
        
        # Verify the service is running
        sleep 3
        if systemctl is-active --quiet websocket-proxy; then
            print_status "WebSocket proxy is running and active"
            
            # Check if ports are listening
            local listening_ports=""
            local expected_ports="80 22 8080 2222 443 8443 8081 8082 3128 8083"
            
            for port in $expected_ports; do
                if ss -tlnp | grep -q ":$port "; then
                    listening_ports="$listening_ports $port"
                fi
            done
            
            if [[ -n "$listening_ports" ]]; then
                print_status "WebSocket Proxy installed and started successfully!"
                print_status "Listening ports: $listening_ports"
                print_status "SSH tunneling: Ports 80, 22, 8080, 2222"
                print_status "SSL/TLS: Ports 443, 8443 (if SSL certs available)"
                print_status "HTTP proxy: Ports 8081, 8082"
                print_status "Custom proxy: Ports 3128, 8083"
                return 0
            else
                print_warning "Service is running but ports may not be listening yet"
                return 0
            fi
        else
            print_error "WebSocket service may not be fully started"
            systemctl status websocket-proxy --no-pager -l >> "$LOG_FILE" 2>&1
            return 1
        fi
    else
        print_error "Failed to start WebSocket proxy service"
        print_status "Checking service status..."
        systemctl status websocket-proxy --no-pager -l >> "$LOG_FILE" 2>&1
        return 1
    fi
}

# Function to install SOCKS Proxy
install_socks_proxy() {
    print_status "Installing SOCKS Proxy..."
    
    # Update package list
    apt update >> "$LOG_FILE" 2>&1
    
    # Try to install 3proxy from default repos first
    if apt install -y 3proxy >> "$LOG_FILE" 2>&1; then
        print_status "3proxy installed from default repositories"
        PROXY_BIN="/usr/bin/3proxy"
    else
        print_warning "3proxy not available in default repos, trying alternative installation..."
        
        # Install from source
        cd /tmp
        wget https://github.com/z3APA3A/3proxy/archive/refs/tags/0.9.4.tar.gz >> "$LOG_FILE" 2>&1
        tar -xzf 0.9.4.tar.gz
        cd 3proxy-0.9.4
        
        # Install build dependencies
        apt install -y build-essential libssl-dev >> "$LOG_FILE" 2>&1
        
        # Compile and install
        make -f Makefile.Linux >> "$LOG_FILE" 2>&1
        if [[ $? -eq 0 ]]; then
            cp bin/3proxy /usr/local/bin/
            PROXY_BIN="/usr/local/bin/3proxy"
            print_status "3proxy compiled and installed from source"
        else
            print_error "Failed to compile 3proxy from source"
            return 1
        fi
    fi
    
    # Create 3proxy configuration
    mkdir -p /etc/3proxy
    cat > /etc/3proxy/3proxy.cfg << 'PROXY_CONFIG_EOF'
# 3proxy configuration file
nserver 8.8.8.8
nserver 8.8.4.4
nscache 65536
timeouts 1 5 30 60 180 1800 15 60

# SOCKS proxy on specified port
socks -pPROXY_PORT_PLACEHOLDER -i0.0.0.0

# Logging
log /var/log/3proxy.log D
logformat "- +_L%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"
PROXY_CONFIG_EOF
    
    # Replace port placeholder
    sed -i "s/PROXY_PORT_PLACEHOLDER/$SOCKS_PORT/g" /etc/3proxy/3proxy.cfg
    
    # Create systemd service
    cat > /etc/systemd/system/3proxy.service << 'PROXY_SERVICE_EOF'
[Unit]
Description=3proxy SOCKS Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=PROXY_BIN_PLACEHOLDER /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=5
User=root
Group=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
PROXY_SERVICE_EOF
    
    # Replace binary path placeholder
    sed -i "s|PROXY_BIN_PLACEHOLDER|$PROXY_BIN|g" /etc/systemd/system/3proxy.service
    
    # Start 3proxy
    print_status "Starting 3proxy service..."
    systemctl daemon-reload
    systemctl enable 3proxy
    
    # Try to start the service
    if systemctl start 3proxy; then
        print_status "3proxy started successfully"
        
        # Verify service is actually running
        sleep 3
        if systemctl is-active --quiet 3proxy; then
            print_status "3proxy is running and active"
            
            # Check if port is listening
            if ss -tlnp | grep -q ":$SOCKS_PORT "; then
                print_status "SOCKS Proxy installed and started on port $SOCKS_PORT"
                return 0
            else
                print_warning "Service is running but port may not be listening yet"
                return 0
            fi
        else
            print_error "3proxy service may not be fully started"
            systemctl status 3proxy --no-pager -l >> "$LOG_FILE" 2>&1
            return 1
        fi
    else
        print_error "Failed to start 3proxy service"
        print_status "Checking service status..."
        systemctl status 3proxy --no-pager -l >> "$LOG_FILE" 2>&1
        return 1
    fi
}

# Function to install DNSTT
install_dnstt() {
    print_status "Installing DNSTT..."
    
    # Install dependencies
    apt install -y golang-go >> "$LOG_FILE" 2>&1
    
    # Create DNSTT server
    cat > /usr/local/bin/dnstt-server.go << 'EOF'
package main

import (
    "fmt"
    "log"
    "net"
    "os"
)

func main() {
    port := ":53"
    if len(os.Args) > 1 {
        port = ":" + os.Args[1]
    }
    
    addr, err := net.ResolveUDPAddr("udp", port)
    if err != nil {
        log.Fatal(err)
    }
    
    conn, err := net.ListenUDP("udp", addr)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    fmt.Printf("DNSTT server listening on port %s\n", port)
    
    buffer := make([]byte, 1024)
    for {
        n, addr, err := conn.ReadFromUDP(buffer)
        if err != nil {
            continue
        }
        
        // Echo back for testing (replace with actual DNS tunneling logic)
        conn.WriteToUDP(buffer[:n], addr)
    }
}
EOF
    
    # Build DNSTT
    cd /usr/local/bin
    go build -o dnstt-server dnstt-server.go >> "$LOG_FILE" 2>&1
    rm dnstt-server.go
    
    # Create systemd service
    cat > /etc/systemd/system/dnstt.service << 'DNSTT_SERVICE_EOF'
[Unit]
Description=DNSTT DNS Tunneling Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/dnstt-server PORT_PLACEHOLDER
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
DNSTT_SERVICE_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$DNSTT_PORT/g" /etc/systemd/system/dnstt.service
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable dnstt
    systemctl start dnstt
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet dnstt && ss -tlnp | grep -q ":$DNSTT_PORT "; then
        print_status "DNSTT installed and started on port $DNSTT_PORT"
        return 0
    else
        print_error "DNSTT failed to start properly"
        return 1
    fi
}

# Function to install SSLH
install_sslh() {
    print_status "Installing SSLH..."
    
    # Install SSLH
    apt install -y sslh >> "$LOG_FILE" 2>&1
    
    # Configure SSLH to use different ports to avoid conflicts
    cat > /etc/default/sslh << 'SSLH_DEFAULT_EOF'
# Default options for sslh, generated by maintainerscripts

# Disabled by default, to force yourself
# to read the configuration:
# - /usr/share/doc/sslh/README.Debian (quick start)
# - /usr/share/doc/sslh/README, at "Configuration" section
# - /etc/sslh.conf (configuration file)

# Once configuration ready, you *must* set RUN to yes here
# (and use command line systemctl start sslh) to actually start the daemon.
RUN=yes

# binary to use: forked (sslh) or single-thread (sslh-select) version
# systemd users: don't forget to modify /lib/systemd/system/sslh.service
DAEMON=/usr/sbin/sslh

# on some systems, sslh needs to be started as root to listen to port 443, 80 etc
# use this to drop root privileges after startup
#RUN_AS=sslh

# give this user permission to redirect port 80
# from the firewall (iptables, ufw, etc)
#REDIRECT_USER=sslh

# listen on this specific IP or default to 0.0.0.0 (all IPs)
#LISTEN_IP=0.0.0.0
SSLH_DEFAULT_EOF
    
    # Create SSLH configuration using different ports to avoid conflicts
    cat > /etc/sslh.conf << 'SSLH_CONFIG_EOF'
verbose: false;
foreground: false;
inetd: false;
numeric: false;
transparent: false;
timeout: "2.0";
user: "sslh";
listen: [ { host: "0.0.0.0", port: "8443" }, { host: "0.0.0.0", port: "8081" } ];
protocols: [
     { name: "ssh";   service: "ssh"; host: "localhost"; port: "22"; log_level: 0; },
     { name: "ssl";   host: "localhost"; port: "443"; log_level: 0; },
     { name: "http";  host: "localhost"; port: "80"; log_level: 0; }
];
SSLH_CONFIG_EOF
    
    # Update firewall to allow new SSLH ports
    ufw allow 8443/tcp >> "$LOG_FILE" 2>&1
    ufw allow 8081/tcp >> "$LOG_FILE" 2>&1
    
    # Start SSLH
    systemctl enable sslh
    systemctl start sslh
    
    print_status "SSLH installed and started on ports 8443 and 8081 (avoiding conflicts with nginx)"
}

# Function to install Nginx Proxy
install_nginx_proxy() {
    print_status "Installing Nginx Proxy..."
    
    # Install Nginx
    apt install -y nginx >> "$LOG_FILE" 2>&1
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/tunneling-proxy << 'NGINX_CONFIG_EOF'
server {
    listen 80;
    server_name _;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX_CONFIG_EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/tunneling-proxy /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test and reload Nginx
    nginx -t >> "$LOG_FILE" 2>&1
    if [[ $? -eq 0 ]]; then
        systemctl reload nginx
        print_status "Nginx Proxy configured successfully"
        return 0
    else
        print_error "Nginx configuration test failed"
        return 1
    fi
}

# Function to install Dropbear SSH Server
install_dropbear_ssh() {
    print_status "Installing Dropbear SSH Server..."
    
    # Install Dropbear
    apt install -y dropbear >> "$LOG_FILE" 2>&1
    
    # Configure Dropbear
    cat > /etc/default/dropbear << 'DROPBEAR_CONFIG_EOF'
# Dropbear SSH Server Configuration
DROPBEAR_PORT=22
DROPBEAR_EXTRA_ARGS="-p 2222"
DROPBEAR_BANNER="/etc/dropbear/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_ED25519KEY="/etc/dropbear/dropbear_ed25519_host_key"
DROPBEAR_WINDOW_SIZE=65536
DROPBEAR_KEEPALIVE=0
DROPBEAR_PIDFILE="/var/run/dropbear.pid"
DROPBEAR_LOG_LEVEL=1
DROPBEAR_EXTRA_ARGS="-s -g -j -k"
DROPBEAR_CONFIG_EOF
    
    # Create banner
    mkdir -p /etc/dropbear
    cat > /etc/dropbear/banner << 'DROPBEAR_BANNER_EOF'
==========================================
    MAXIE VPS MANAGER - DROPBEAR SSH
==========================================
Welcome to the server!
DROPBEAR_BANNER_EOF
    
    # Generate host keys if they don't exist
    if [[ ! -f /etc/dropbear/dropbear_rsa_host_key ]]; then
        dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key -s 2048 >> "$LOG_FILE" 2>&1
    fi
    
    if [[ ! -f /etc/dropbear/dropbear_ecdsa_host_key ]]; then
        dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key -s 256 >> "$LOG_FILE" 2>&1
    fi
    
    if [[ ! -f /etc/dropbear/dropbear_ed25519_host_key ]]; then
        dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key >> "$LOG_FILE" 2>&1
    fi
    
    # Start Dropbear
    systemctl enable dropbear
    systemctl start dropbear
    
    # Wait for service to start
    sleep 5
    
    # Verify service is actually running
    if systemctl is-active --quiet dropbear; then
        print_status "Dropbear SSH service is active"
        
        # Check if it's listening on port 22 using ss (modern replacement for netstat)
        if ss -tlnp 2>/dev/null | grep -q ":22 "; then
            print_status "Dropbear SSH installed and started on port 22"
            print_status "Additional port 2222 also available"
            return 0
        else
            print_warning "Dropbear service is active but not listening on port 22"
            print_status "Checking for alternative ports..."
            
            # Check if it's listening on any SSH-related ports
            if ss -tlnp 2>/dev/null | grep -q "dropbear"; then
                local ports=$(ss -tlnp 2>/dev/null | grep "dropbear" | grep -o ":[0-9]*" | tr '\n' ' ')
                print_status "Dropbear is listening on ports: $ports"
                return 0
            else
                print_error "Dropbear is not listening on any ports"
                return 1
            fi
        fi
    else
        print_error "Dropbear SSH service failed to start"
        return 1
    fi
}

# Function to configure SSL certificates
configure_ssl() {
    if [[ -n "$DOMAIN" && -n "$EMAIL" ]]; then
        print_status "Configuring SSL certificates for domain: $DOMAIN"
        
        # Check if certificates already exist
        if check_ssl_certificates; then
            print_status "Valid SSL certificates already exist"
            return 0
        fi
        
        # Request new certificate
        if request_ssl_certificate; then
            print_status "SSL certificates configured successfully"
            return 0
        else
            print_warning "SSL certificate configuration failed"
            return 1
        fi
    else
        print_warning "Domain or email not provided. SSL certificates not configured."
        print_warning "To configure SSL later, run: certbot --nginx -d yourdomain.com"
        return 1
    fi
}

# Function to check SSL certificates from command line
check_ssl_certificates_cli() {
    echo "=== SSL Certificate Status ==="
    echo
    
    if check_ssl_certificates; then
        echo "✅ SSL Certificate Found:"
        echo "  Domain: $SSL_CERT_DOMAIN"
        echo "  Path: $SSL_CERT_PATH"
        echo "  Expires: $(openssl x509 -enddate -noout -in "$SSL_CERT_PATH/fullchain.pem" 2>/dev/null | cut -d= -f2 || echo "Unknown")"
        
        # Check if certificate is valid
        if openssl x509 -checkend 86400 -noout -in "$SSL_CERT_PATH/fullchain.pem" >/dev/null 2>&1; then
            echo "  Status: Valid (not expiring soon)"
        else
            echo "  Status: Expired or expiring soon"
        fi
    else
        echo "❌ No valid SSL certificates found"
        echo
        echo "To request a new certificate:"
        echo "1. Run the main script: bash maxie-tunneling-setup.sh"
        echo "2. Select option 6 (SSL Certificate Management)"
        echo "3. Select option 2 (Request New SSL Certificate)"
    fi
}

# Function to create SSL certificate management script
create_ssl_management_script() {
    print_status "Creating SSL certificate management script..."
    
    cat > /usr/local/bin/check-ssl-certificates << 'EOF'
#!/bin/bash

# SSL Certificate Management Script
# Usage: check-ssl-certificates [check|request|delete]

case "$1" in
    "check")
        # Check SSL certificates
        if [[ -f /etc/letsencrypt/live/*/fullchain.pem ]]; then
            cert_path=$(find /etc/letsencrypt/live/*/fullchain.pem | head -1)
            domain=$(basename $(dirname "$cert_path"))
            echo "✅ Let's Encrypt Certificate Found:"
            echo "  Domain: $domain"
            echo "  Path: $cert_path"
            echo "  Expires: $(openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null | cut -d= -f2 || echo "Unknown")"
            
            # Check validity
            if openssl x509 -checkend 86400 -noout -in "$cert_path" >/dev/null 2>&1; then
                echo "  Status: Valid (not expiring soon)"
            else
                echo "  Status: Expired or expiring soon"
            fi
        elif [[ -f /etc/ssl/certs/*.crt ]]; then
            cert_path=$(find /etc/ssl/certs/*.crt | head -1)
            echo "✅ SSL Certificate Found:"
            echo "  Path: $cert_path"
            echo "  Expires: $(openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null | cut -d= -f2 || echo "Unknown")"
        else
            echo "❌ No SSL certificates found"
        fi
        ;;
    "request")
        echo "To request a new SSL certificate:"
        echo "1. Run: bash maxie-tunneling-setup.sh"
        echo "2. Select option 6 (SSL Certificate Management)"
        echo "3. Select option 2 (Request New SSL Certificate)"
        ;;
    "delete")
        echo "To delete an SSL certificate:"
        echo "1. Run: bash maxie-tunneling-setup.sh"
        echo "2. Select option 6 (SSL Certificate Management)"
        echo "3. Select option 3 (Delete Existing SSL Certificate)"
        ;;
    *)
        echo "SSL Certificate Management Script"
        echo
        echo "Usage: check-ssl-certificates [check|request|delete]"
        echo
        echo "Commands:"
        echo "  check   - Check current SSL certificate status"
        echo "  request - Show how to request a new certificate"
        echo "  delete  - Show how to delete a certificate"
        echo
        echo "Examples:"
        echo "  check-ssl-certificates check"
        echo "  check-ssl-certificates request"
        echo "  check-ssl-certificates delete"
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/check-ssl-certificates
    
    print_status "SSL certificate management script created: check-ssl-certificates"
}

# Function to create status check script
create_status_script() {
    print_status "Creating status check script..."
    
    cat > /usr/local/bin/check-tunneling-status << 'EOF'
#!/bin/bash

echo "=== Maxie VPS Manager - Tunneling Status ==="
echo

# Check BadVPN
if systemctl is-active --quiet badvpn; then
    echo -e "✅ BadVPN: \033[32mRUNNING\033[0m (Port 7300)"
else
    echo -e "❌ BadVPN: \033[31mSTOPPED\033[0m"
fi

# Check UDP-Custom
if systemctl is-active --quiet udp-custom; then
    echo -e "✅ UDP-Custom: \033[32mRUNNING\033[0m (Port 5300)"
else
    echo -e "❌ UDP-Custom: \033[31mSTOPPED\033[0m"
fi

# Check SSL Tunnel
if systemctl is-active --quiet stunnel4; then
    echo -e "✅ SSL Tunnel: \033[32mRUNNING\033[0m (Port 444)"
else
    echo -e "❌ SSL Tunnel: \033[31mSTOPPED\033[0m"
fi

# Check WebSocket Proxy
if systemctl is-active --quiet websocket-proxy; then
    echo -e "✅ WebSocket Proxy: \033[32mRUNNING\033[0m (Ports 8080, 80, 22)"
else
    echo -e "❌ WebSocket Proxy: \033[31mSTOPPED\033[0m"
fi

# Check SOCKS Proxy
if systemctl is-active --quiet 3proxy; then
    echo -e "✅ SOCKS Proxy: \033[32mRUNNING\033[0m (Port 200)"
else
    echo -e "❌ SOCKS Proxy: \033[31mSTOPPED\033[0m"
fi

# Check DNSTT
if systemctl is-active --quiet dnstt; then
    echo -e "✅ DNSTT: \033[32mRUNNING\033[0m (Port 53)"
else
    echo -e "❌ DNSTT: \033[31mSTOPPED\033[0m"
fi

# Check SSLH
if systemctl is-active --quiet sslh; then
    echo -e "✅ SSLH: \033[32mRUNNING\033[0m (Ports 8443, 8081)"
else
    echo -e "❌ SSLH: \033[31mSTOPPED\033[0m"
fi

# Check Nginx
if systemctl is-active --quiet nginx; then
    echo -e "✅ Nginx: \033[32mRUNNING\033[0m (Port 80)"
else
    echo -e "❌ Nginx: \033[31mSTOPPED\033[0m"
fi

echo
echo "=== Detailed Port Status ==="
ss -tlnp 2>/dev/null | grep -E ":(7300|5300|444|8080|200|53|80|443|8443|8081|22)" | sort | while read line; do
    local port=$(echo "$line" | grep -o ":[0-9]*" | head -1 | cut -d: -f2)
    local service=$(echo "$line" | awk '{print $NF}' | cut -d'/' -f2)
    local pid=$(echo "$line" | awk '{print $NF}' | cut -d'/' -f1)
    echo "  Port $port: $service (PID: $pid)"
done || echo "ss command not available"

echo
echo "=== Firewall Status ==="
ufw status 2>/dev/null || echo "UFW not available"

echo
echo "=== SSL Certificate Status ==="
if [[ -n "$SSL_CERT_PATH" && -n "$SSL_CERT_DOMAIN" ]]; then
    echo "  Domain: $SSL_CERT_DOMAIN"
    echo "  Path: $SSL_CERT_PATH"
else
    echo "  No SSL certificate information available"
    # Try to detect certificates
    if [[ -f /etc/letsencrypt/live/*/fullchain.pem ]]; then
        cert_path=$(find /etc/letsencrypt/live/*/fullchain.pem | head -1)
        domain=$(basename $(dirname "$cert_path"))
        echo "  Detected Let's Encrypt certificate:"
        echo "    Domain: $domain"
        echo "    Path: $cert_path"
    elif [[ -f /etc/ssl/certs/*.crt ]]; then
        cert_path=$(find /etc/ssl/certs/*.crt | head -1)
        echo "  Detected SSL certificate:"
        echo "    Path: $cert_path"
    else
        echo "  No SSL certificates found"
    fi
fi

echo
echo "=== Bandwidth Usage ==="
if command -v /usr/local/bin/bandwidth_monitor.sh >/dev/null 2>&1; then
    /usr/local/bin/bandwidth_monitor.sh status
else
    echo "Bandwidth monitoring not available"
fi
EOF
    
    chmod +x /usr/local/bin/check-tunneling-status
    
    print_status "Status check script created: check-tunneling-status"
}

# Function to create connection info file
create_connection_info() {
    print_status "Creating connection information file..."
    
    cat > /root/tunneling-connection-info.txt << 'CONNECTION_INFO_EOF'
==========================================
    MAXIE VPS MANAGER - CONNECTION INFO
==========================================

Server IP: $(curl -s ifconfig.me 2>/dev/null || echo "Unable to determine")
Domain: ${DOMAIN:-"Not configured"}

=== TUNNELING PROTOCOLS ===

1. BadVPN (UDP Tunneling)
   Port: $BADVPN_PORT/udp
   Use: Gaming, multimedia streaming
   Status: $(systemctl is-active badvpn 2>/dev/null || echo "Unknown")

2. UDP-Custom (Custom UDP Proxy)
   Port: $UDP_CUSTOM_PORT/udp
   Use: Custom UDP proxy with exclusions
   Status: $(systemctl is-active udp-custom 2>/dev/null || echo "Unknown")

3. SSL Tunnel (SSL-encrypted SSH)
   Port: $SSL_TUNNEL_PORT/tcp
   Use: SSL-encrypted SSH tunneling
   Status: $(systemctl is-active stunnel4 2>/dev/null || echo "Unknown")

4. WebSocket Proxy (Multi-Protocol)
   SSH Ports: 80/tcp, 22/tcp, 8080/tcp, 2222/tcp
   SSL/TLS Ports: 443/tcp, 8443/tcp
   HTTP Ports: 8081/tcp, 8082/tcp
   Custom Proxy: 3128/tcp, 8083/tcp
   Use: Multi-protocol WebSocket proxy with SSH tunneling, SSL/TLS, and HTTP
   Status: $(systemctl is-active websocket-proxy 2>/dev/null || echo "Unknown")

5. SOCKS Proxy (SOCKS5)
   Port: $SOCKS_PORT/tcp
   Use: SOCKS5 proxy server
   Status: $(systemctl is-active 3proxy 2>/dev/null || echo "Unknown")

6. DNSTT (DNS Tunneling)
   Port: $DNSTT_PORT/udp
   Use: DNS tunneling for bypassing restrictions
   Status: $(systemctl is-active dnstt 2>/dev/null || echo "Unknown")

7. SSLH (SSL/SSH Multiplexer)
   Ports: 8443/tcp, 8081/tcp
   Use: SSL/SSH multiplexer
   Status: $(systemctl is-active sslh 2>/dev/null || echo "Unknown")

8. Nginx Proxy (Reverse Proxy)
   Port: 80/tcp
   Use: Reverse proxy with WebSocket support
   Status: $(systemctl is-active nginx 2>/dev/null || echo "Unknown")

9. Dropbear SSH (Lightweight SSH Server)
   Port: 22/tcp
   Use: Lightweight SSH server (more efficient than OpenSSH)
   Status: $(systemctl is-active dropbear 2>/dev/null || echo "Unknown")

=== MANAGEMENT ===

Status Check: check-tunneling-status
Bandwidth Monitor: /usr/local/bin/bandwidth_monitor.sh

=== SSL CERTIFICATES ===
CONNECTION_INFO_EOF

    # Add SSL certificate information if available
    if check_ssl_certificates; then
        cat >> /root/tunneling-connection-info.txt << 'SSL_CERT_INFO_EOF'
Active SSL Certificate:
  Domain: $SSL_CERT_DOMAIN
  Path: $SSL_CERT_PATH
  Expires: $(openssl x509 -enddate -noout -in "$SSL_CERT_PATH/fullchain.pem" 2>/dev/null | cut -d= -f2 || echo "Unknown")
SSL_CERT_INFO_EOF
    else
        cat >> /root/tunneling-connection-info.txt << 'SSL_CERT_NOT_CONFIGURED_EOF'
SSL Certificate: Not configured
  To configure: Use option 6 (SSL Certificate Management)
SSL_CERT_NOT_CONFIGURED_EOF
    fi

    cat >> /root/tunneling-connection-info.txt << 'USEFUL_COMMANDS_EOF'

=== USEFUL COMMANDS ===

Check all services status:
  check-tunneling-status

Check specific service:
  systemctl status [service-name]

View logs:
  journalctl -u [service-name] -f

Restart service:
  systemctl restart [service-name]

Check bandwidth usage:
  /usr/local/bin/bandwidth_monitor.sh status

SSL Certificate Management:
  Check certificates: check-ssl-certificates
  Check specific: check-ssl-certificates check
  Request new cert: Use option 6 in main menu
  Delete cert: Use option 6 in main menu

=== SECURITY NOTES ===

1. Configure firewall rules as needed
2. Monitor logs for suspicious activity
3. Keep system updated regularly
4. Check SSL certificate validity

=== SUPPORT ===

For issues and support, check:
- Service logs: journalctl -u [service-name]
- Firewall status: ufw status
- Port status: ss -tlnp
- Bandwidth usage: /usr/local/bin/bandwidth_monitor.sh status

Generated on: $(date)
EOF
    
    print_status "Connection information saved to /root/tunneling-connection-info.txt"
}

# Function to get user input
get_user_input() {
    print_header "Maxie VPS Manager - Tunneling Setup"
    echo
    echo "This script will install and configure tunneling protocols."
    echo "Please provide the following information:"
    echo
    
    read -p "Enter your domain name (or press Enter to skip): " DOMAIN
    read -p "Enter your email for SSL certificates (or press Enter to skip): " EMAIL
    
    echo
    echo "Configuration Summary:"
    echo "Domain: ${DOMAIN:-"Not configured"}"
    echo "Email: ${EMAIL:-"Not configured"}"
    echo "Firewall: $FIREWALL_ENABLE"
    echo
    
    read -p "Continue with setup? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Setup cancelled"
        exit 0
    fi
}

# Function to ask user if they want to install a specific protocol
ask_protocol_installation() {
    local protocol_name="$1"
    local install_function="$2"
    
    echo
    read -p "Do you want to install $protocol_name? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Installing $protocol_name..."
        $install_function
        if [[ $? -eq 0 ]]; then
            print_status "$protocol_name installed successfully"
            return 0
        else
            print_error "$protocol_name installation failed"
            return 1
        fi
    else
        print_status "Skipping $protocol_name installation"
        return 0
    fi
}

# Function to install all protocols with user confirmation
install_all_protocols() {
    print_header "Installing Tunneling Protocols"
    
    local all_installed=true
    
    # Ask for each protocol
    ask_protocol_installation "BadVPN" install_badvpn
    if [[ $? -ne 0 ]]; then all_installed=false; fi
    
    ask_protocol_installation "UDP-Custom" install_udp_custom
    if [[ $? -ne 0 ]]; then all_installed=false; fi
    
    ask_protocol_installation "SSL Tunnel" install_ssl_tunnel
    if [[ $? -ne 0 ]]; then all_installed=false; fi
    
    ask_protocol_installation "WebSocket Proxy" install_websocket_proxy
    if [[ $? -ne 0 ]]; then all_installed=false; fi
    
    ask_protocol_installation "SOCKS Proxy" install_socks_proxy
    if [[ $? -ne 0 ]]; then all_installed=false; fi
    
    ask_protocol_installation "DNSTT" install_dnstt
    if [[ $? -ne 0 ]]; then all_installed=false; fi
    
    ask_protocol_installation "SSLH" install_sslh
    if [[ $? -ne 0 ]]; then all_installed=false; fi
    
    ask_protocol_installation "Nginx Proxy" install_nginx_proxy
    if [[ $? -ne 0 ]]; then all_installed=false; fi
    
    ask_protocol_installation "Dropbear SSH" install_dropbear_ssh
    if [[ $? -ne 0 ]]; then all_installed=false; fi
    
    if [[ "$all_installed" == true ]]; then
        print_status "All selected protocols installed successfully"
    else
        print_warning "Some protocols failed to install. Check logs for details."
    fi
}

# Function to install individual protocol
install_individual_protocol() {
    print_header "Install Individual Protocol"
    echo
    echo "Available protocols:"
    echo "1. BadVPN (UDP Tunneling)"
    echo "2. UDP-Custom (Custom UDP Proxy)"
    echo "3. SSL Tunnel (SSL-encrypted SSH)"
    echo "4. WebSocket Proxy (WebSocket SSH)"
    echo "5. SOCKS Proxy (SOCKS5)"
    echo "6. DNSTT (DNS Tunneling)"
    echo "7. SSLH (SSL/SSH Multiplexer)"
    echo "8. Nginx Proxy (Reverse Proxy)"
    echo "9. Dropbear SSH (Lightweight SSH Server)"
    echo "10. Back to main menu"
    echo
    
    read -p "Select protocol to install (1-10): " choice
    
    case $choice in
        1) install_badvpn ;;
        2) install_udp_custom ;;
        3) install_ssl_tunnel ;;
        4) install_websocket_proxy ;;
        5) install_socks_proxy ;;
        6) install_dnstt ;;
        7) install_sslh ;;
        8) install_nginx_proxy ;;
        9) install_dropbear_ssh ;;
        10) return ;;
        *) print_error "Invalid choice"; return ;;
    esac
    
    # Verify installation
    if [[ $? -eq 0 ]]; then
        print_status "Protocol installed successfully"
        read -p "Press Enter to continue..."
    else
        print_error "Protocol installation failed"
        read -p "Press Enter to continue..."
    fi
}

# Function to finalize setup
finalize_setup() {
    print_header "Finalizing Setup"
    
    # Check SSL certificates
    if ! check_ssl_certificates; then
        if [[ -n "$DOMAIN" && -n "$EMAIL" ]]; then
            request_ssl_certificate
        fi
    fi
    
    # Setup bandwidth monitoring
    setup_bandwidth_monitoring
    
    # Create status script and connection info
    create_status_script
    create_ssl_management_script
    create_connection_info
    
    print_status "Setup completed successfully!"
    echo
    echo "=== NEXT STEPS ==="
    echo "1. Check service status: check-tunneling-status"
    echo "2. Check SSL certificates: check-ssl-certificates"
    echo "3. Configure your clients to use the tunneling protocols"
    echo "4. Review connection info: cat /root/tunneling-connection-info.txt"
    echo "5. Monitor bandwidth usage with iptables"
    echo
    echo "=== IMPORTANT ==="
    echo "All services are configured to start automatically on boot"
    echo "Firewall rules have been configured for all protocol ports"
    echo "Bandwidth monitoring resets daily at midnight (Africa/Nairobi timezone)"
    echo "SSL certificates will auto-renew every 90 days"
    echo
}

# Function to check service status with proper verification
check_service_status() {
    local service_name="$1"
    local display_name="$2"
    local port="$3"
    
    print_status "Checking $display_name service..."
    
    # Check if service is running
    if ! systemctl is-active --quiet "$service_name"; then
        print_warning "$display_name service is not running"
        return 1
    fi
    
    # Check if service is listening on the expected port
    if [[ -n "$port" ]]; then
        local ports=(${port//,/ })
        local port_listening=false
        local listening_ports=""
        
        for p in "${ports[@]}"; do
            if ss -tlnp 2>/dev/null | grep -q ":$p "; then
                port_listening=true
                listening_ports="$listening_ports $p"
            fi
        done
        
        if [[ "$port_listening" == false ]]; then
            print_warning "$display_name service is running but not listening on expected port(s): $port"
            return 1
        else
            print_status "$display_name is listening on port(s):$listening_ports"
        fi
    fi
    
    # Check if service process is actually running
    if ! pgrep -f "$service_name" >/dev/null; then
        print_warning "$display_name service shows as active but process not found"
        return 1
    fi
    
    # Additional checks for specific services
    case "$service_name" in
        "badvpn")
            # Check if BadVPN is actually accepting connections
            if ! timeout 5 bash -c "</dev/tcp/127.0.0.1/7300" 2>/dev/null; then
                print_warning "$display_name service is running but not accepting connections"
                return 1
            fi
            ;;
        "websocket-proxy")
            # Check if WebSocket proxy is responding on any of its ports
            local ws_ports=(8080 80 22)
            local ws_responding=false
            for p in "${ws_ports[@]}"; do
                if timeout 5 bash -c "</dev/tcp/127.0.0.1/$p" 2>/dev/null; then
                    ws_responding=true
                    print_status "$display_name responding on port $p"
                    break
                fi
            done
            if [[ "$ws_responding" == false ]]; then
                print_warning "$display_name service is running but not accepting connections on any port"
                return 1
            fi
            ;;
        "3proxy")
            # Check if 3proxy is responding
            if ! timeout 5 bash -c "</dev/tcp/127.0.0.1/200" 2>/dev/null; then
                print_warning "$display_name service is running but not accepting connections"
                return 1
            fi
            ;;
    esac
    
    print_status "$display_name service is running properly"
    return 0
}

# Function to show bandwidth usage display
show_bandwidth_usage_display() {
    echo "=== Current Bandwidth Usage ==="
    
    # Check if iptables rules exist
    if ! iptables -L -n | grep -q "bandwidth_monitor"; then
        print_warning "Bandwidth monitoring not set up. Run setup first."
        return
    fi
    
    # Show current bandwidth usage
    echo "User Bandwidth Usage:"
    iptables -L OUTPUT -n -v | grep "bandwidth_monitor" | while read line; do
        if [[ $line =~ ^[0-9]+ ]]; then
            bytes=$(echo $line | awk '{print $1}')
            user=$(echo $line | awk '{print $NF}')
            if [[ $bytes -gt 0 ]]; then
                echo "  $user: $(numfmt --to=iec $bytes)"
            fi
        fi
    done
    
    echo
    echo "Daily Bandwidth Usage (resets at midnight Africa/Nairobi):"
    if [[ -f /var/log/bandwidth_daily.log ]]; then
        cat /var/log/bandwidth_daily.log
    else
        echo "  No daily data available yet"
    fi
}

# Function to check all services status
check_all_services_status() {
    echo "=== Service Status Check ==="
    echo
    
    local all_running=true
    
    # Check BadVPN
    if check_service_status "badvpn" "BadVPN" "7300"; then
        echo -e "✅ BadVPN: \033[32mRUNNING\033[0m (Port 7300)"
    else
        echo -e "❌ BadVPN: \033[31mSTOPPED\033[0m"
        all_running=false
    fi
    
    # Check UDP-Custom
    if check_service_status "udp-custom" "UDP-Custom" "5300"; then
        echo -e "✅ UDP-Custom: \033[32mRUNNING\033[0m (Port 5300)"
    else
        echo -e "❌ UDP-Custom: \033[31mSTOPPED\033[0m"
        all_running=false
    fi
    
    # Check SSL Tunnel
    if check_service_status "stunnel4" "SSL Tunnel" "444"; then
        echo -e "✅ SSL Tunnel: \033[32mRUNNING\033[0m (Port 444)"
    else
        echo -e "❌ SSL Tunnel: \033[31mSTOPPED\033[0m"
        all_running=false
    fi
    
    # Check WebSocket Proxy
    if check_service_status "websocket-proxy" "WebSocket Proxy" "8080,80,22"; then
        echo -e "✅ WebSocket Proxy: \033[32mRUNNING\033[0m (Ports 8080, 80, 22)"
    else
        echo -e "❌ WebSocket Proxy: \033[31mSTOPPED\033[0m"
        all_running=false
    fi
    
    # Check SOCKS Proxy
    if check_service_status "3proxy" "SOCKS Proxy" "200"; then
        echo -e "✅ SOCKS Proxy: \033[32mRUNNING\033[0m (Port 200)"
    else
        echo -e "❌ SOCKS Proxy: \033[31mSTOPPED\033[0m"
        all_running=false
    fi
    
    # Check DNSTT
    if check_service_status "dnstt" "DNSTT" "53"; then
        echo -e "✅ DNSTT: \033[32mRUNNING\033[0m (Port 53)"
    else
        echo -e "❌ DNSTT: \033[31mSTOPPED\033[0m"
        all_running=false
    fi
    
    # Check SSLH
    if check_service_status "sslh" "SSLH" "8443,8081"; then
        echo -e "✅ SSLH: \033[32mRUNNING\033[0m (Ports 8443, 8081)"
    else
        echo -e "❌ SSLH: \033[31mSTOPPED\033[0m"
        all_running=false
    fi
    
    # Check Nginx
    if check_service_status "nginx" "Nginx" "80"; then
        echo -e "✅ Nginx: \033[32mRUNNING\033[0m (Port 80)"
    else
        echo -e "❌ Nginx: \033[31mSTOPPED\033[0m"
        all_running=false
    fi
    
    echo
    echo "=== Detailed Port Status ==="
    ss -tlnp 2>/dev/null | grep -E ":(7300|5300|444|8080|200|53|80|443|8443|8081|22)" | sort | while read line; do
        local port=$(echo "$line" | grep -o ":[0-9]*" | head -1 | cut -d: -f2)
        local service=$(echo "$line" | awk '{print $NF}' | cut -d'/' -f2)
        local pid=$(echo "$line" | awk '{print $NF}' | cut -d'/' -f1)
        echo "  Port $port: $service (PID: $pid)"
    done || echo "ss command not available"
    
    echo
    echo "=== Firewall Status ==="
    ufw status 2>/dev/null || echo "UFW not available"
    
    echo
    echo "=== SSL Certificate Status ==="
    if check_ssl_certificates; then
        echo "  Domain: $SSL_CERT_DOMAIN"
        echo "  Path: $SSL_CERT_PATH"
    else
        echo "  No valid SSL certificates found"
    fi
    
    if [[ "$all_running" == true ]]; then
        echo
        print_status "All services are running properly!"
    else
        echo
        print_warning "Some services are not running. Check logs for details."
    fi
}

# Function to show main menu
show_main_menu() {
    while true; do
        clear
        print_header "Maxie VPS Manager - Tunneling Setup"
        echo
        echo "1. Install All Protocols"
        echo "2. Check Service Status"
        echo "3. View Bandwidth Usage"
        echo "4. Install Individual Protocol"
        echo "5. View Connection Information"
        echo "6. SSL Certificate Management"
        echo "7. Exit"
        echo
        
        read -p "Select option (1-7): " choice
        
        case $choice in
            1) install_all_protocols ;;
            2) check_all_services ;;
            3) show_bandwidth_usage ;;
            4) install_individual_protocol ;;
            5) show_connection_info ;;
            6) ssl_certificate_menu ;;
            7) 
                print_status "Exiting..."
                exit 0
                ;;
            *) 
                print_error "Invalid choice"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Function to check all services
check_all_services() {
    print_header "Service Status Check"
    echo
    check_all_services_status
    echo
    read -p "Press Enter to continue..."
}

# Function to show bandwidth usage
show_bandwidth_usage() {
    print_header "Bandwidth Usage"
    echo
    show_bandwidth_usage_display
    echo
    read -p "Press Enter to continue..."
}

# Function to show connection info
show_connection_info() {
    print_header "Connection Information"
    echo
    if [[ -f /root/tunneling-connection-info.txt ]]; then
        cat /root/tunneling-connection-info.txt
    else
        print_warning "Connection information file not found. Run setup first."
    fi
    echo
    read -p "Press Enter to continue..."
}

# Function to show SSL certificate management menu
ssl_certificate_menu() {
    while true; do
        clear
        print_header "SSL Certificate Management"
        echo
        echo "1. Check SSL Certificates"
        echo "2. Request New SSL Certificate"
        echo "3. Delete Existing SSL Certificate"
        echo "4. Back to main menu"
        echo
        
        read -p "Select option (1-4): " choice
        
        case $choice in
            1) check_ssl_certificates; read -p "Press Enter to continue..." ;;
            2) 
                if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
                    print_warning "Domain and email are required to request a certificate."
                    read -p "Press Enter to continue..."
                else
                    request_ssl_certificate
                    read -p "Press Enter to continue..."
                fi
                ;;
            3) delete_ssl_certificate; read -p "Press Enter to continue..." ;;
            4) return ;;
            *) print_error "Invalid choice"; read -p "Press Enter to continue..." ;;
        esac
    done
}

# Main execution
main() {
    # Initialize log file
    touch "$LOG_FILE"
    echo "$(date): Starting Maxie VPS Manager tunneling setup" > "$LOG_FILE"
    
    check_root
    check_system
    get_user_input
    update_system
    configure_firewall
    
    # Show main menu instead of auto-installing
    show_main_menu
}

# Run main function
main "$@"
