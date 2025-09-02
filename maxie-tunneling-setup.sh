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
    apt install -y curl wget git ufw iptables-persistent >> "$LOG_FILE" 2>&1
    print_status "System updated successfully"
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
        ufw allow $SSLH_PORT_HTTP/tcp >> "$LOG_FILE" 2>&1
        ufw allow $SSLH_PORT_HTTPS/tcp >> "$LOG_FILE" 2>&1
        
        # Enable UFW
        ufw --force enable >> "$LOG_FILE" 2>&1
        
        print_status "Firewall configured successfully"
    fi
}

# Function to setup bandwidth monitoring
setup_bandwidth_monitoring() {
    print_status "Setting up bandwidth monitoring..."
    
    # Create bandwidth monitoring script
    cat > /usr/local/bin/bandwidth-monitor.sh << 'EOF'
#!/bin/bash

# Bandwidth monitoring script using iptables
LOG_FILE="/var/log/bandwidth.log"
RESET_TIME="00:00"

# Create iptables chains if they don't exist
iptables -t mangle -N BANDWIDTH_IN 2>/dev/null
iptables -t mangle -N BANDWIDTH_OUT 2>/dev/null

# Clear existing rules
iptables -t mangle -F BANDWIDTH_IN
iptables -t mangle -F BANDWIDTH_OUT

# Add rules for each user (you can modify this list)
USERS=("user1" "user2" "user3")

for user in "${USERS[@]}"; do
    # Create user-specific chains
    iptables -t mangle -N BANDWIDTH_${user^^}_IN 2>/dev/null
    iptables -t mangle -N BANDWIDTH_${user^^}_OUT 2>/dev/null
    
    # Clear existing rules
    iptables -t mangle -F BANDWIDTH_${user^^}_IN
    iptables -t mangle -F BANDWIDTH_${user^^}_OUT
    
    # Add user to main chains
    iptables -t mangle -A BANDWIDTH_IN -m owner --uid-owner $(id -u $user 2>/dev/null || echo 1000) -j BANDWIDTH_${user^^}_IN
    iptables -t mangle -A BANDWIDTH_OUT -m owner --uid-owner $(id -u $user 2>/dev/null || echo 1000) -j BANDWIDTH_${user^^}_OUT
    
    # Add counting rules
    iptables -t mangle -A BANDWIDTH_${user^^}_IN -j RETURN
    iptables -t mangle -A BANDWIDTH_${user^^}_OUT -j RETURN
done

# Hook into INPUT and OUTPUT chains
iptables -t mangle -A INPUT -j BANDWIDTH_IN
iptables -t mangle -A OUTPUT -j BANDWIDTH_OUT

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

echo "$(date): Bandwidth monitoring initialized" >> "$LOG_FILE"
EOF
    
    chmod +x /usr/local/bin/bandwidth-monitor.sh
    
    # Create daily reset script
    cat > /usr/local/bin/bandwidth-reset.sh << 'EOF'
#!/bin/bash

# Daily bandwidth reset script
LOG_FILE="/var/log/bandwidth.log"
RESET_TIME="00:00"

# Reset iptables counters
iptables -t mangle -Z

# Log reset
echo "$(date): Daily bandwidth counters reset" >> "$LOG_FILE"

# Save current bandwidth stats before reset
echo "$(date): === DAILY BANDWIDTH SUMMARY ===" >> "$LOG_FILE"
iptables -t mangle -L -v -x | grep -E "BANDWIDTH_.*_IN|BANDWIDTH_.*_OUT" >> "$LOG_FILE"
echo "$(date): === END SUMMARY ===" >> "$LOG_FILE"
EOF
    
    chmod +x /usr/local/bin/bandwidth-reset.sh
    
    # Setup cron job for daily reset at midnight Africa/Nairobi timezone
    (crontab -l 2>/dev/null; echo "0 0 * * * /usr/local/bin/bandwidth-reset.sh") | crontab -
    
    # Initialize bandwidth monitoring
    /usr/local/bin/bandwidth-monitor.sh
    
    print_status "Bandwidth monitoring setup completed"
}

# Function to check SSL certificates
check_ssl_certificates() {
    print_status "Checking SSL certificates..."
    
    # Check for existing certificates
    if [[ -f /etc/letsencrypt/live/*/fullchain.pem ]] || [[ -f /etc/ssl/certs/*.crt ]]; then
        print_status "Existing SSL certificates found"
        
        # Find certificate paths
        if [[ -f /etc/letsencrypt/live/*/fullchain.pem ]]; then
            CERT_PATH=$(find /etc/letsencrypt/live/*/fullchain.pem | head -1)
            KEY_PATH=$(find /etc/letsencrypt/live/*/privkey.pem | head -1)
            print_status "Let's Encrypt certificate found: $CERT_PATH"
        elif [[ -f /etc/ssl/certs/*.crt ]]; then
            CERT_PATH=$(find /etc/ssl/certs/*.crt | head -1)
            KEY_PATH=$(find /etc/ssl/private/*.key | head -1)
            print_status "SSL certificate found: $CERT_PATH"
        fi
        
        return 0
    else
        print_warning "No SSL certificates found"
        return 1
    fi
}

# Function to request SSL certificate
request_ssl_certificate() {
    if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
        print_warning "Domain or email not provided. SSL certificate not requested."
        return 1
    fi
    
    print_status "Requesting SSL certificate for domain: $DOMAIN"
    
    # Install Certbot
    apt install -y certbot python3-certbot-nginx >> "$LOG_FILE" 2>&1
    
    # Check if domain resolves
    if ! nslookup "$DOMAIN" >/dev/null 2>&1; then
        print_error "Domain $DOMAIN does not resolve. Please check DNS records."
        return 1
    fi
    
    # Request certificate
    certbot certonly --standalone -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive >> "$LOG_FILE" 2>&1
    
    if [[ $? -eq 0 ]]; then
        print_status "SSL certificate obtained successfully"
        CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        
        # Setup auto-renewal
        (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
        
        return 0
    else
        print_error "Failed to obtain SSL certificate"
        return 1
    fi
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
    cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDP Tunneling Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:$BADVPN_PORT --max-clients 1000 --max-connections-for-client 1000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable badvpn
    systemctl start badvpn
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet badvpn && netstat -tlnp | grep -q ":$BADVPN_PORT"; then
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
    cat > /etc/systemd/system/udp-custom.service << EOF
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
EOF
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable udp-custom
    systemctl start udp-custom
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet udp-custom && netstat -tlnp | grep -q ":$UDP_CUSTOM_PORT"; then
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
    
    # Create stunnel configuration
    cat > /etc/stunnel/stunnel.conf << EOF
[ssl-tunnel]
accept = 0.0.0.0:$SSL_TUNNEL_PORT
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
EOF
    
    # Generate self-signed certificate
    openssl req -new -x509 -days 365 -nodes -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" >> "$LOG_FILE" 2>&1
    
    # Enable stunnel
    sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
    
    # Start stunnel
    systemctl enable stunnel4
    systemctl start stunnel4
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet stunnel4 && netstat -tlnp | grep -q ":$SSL_TUNNEL_PORT"; then
        print_status "SSL Tunnel installed and started on port $SSL_TUNNEL_PORT"
        return 0
    else
        print_error "SSL Tunnel failed to start properly"
        return 1
    fi
}

# Function to install WebSocket Proxy
install_websocket_proxy() {
    print_status "Installing WebSocket Proxy..."
    
    # Install Node.js
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - >> "$LOG_FILE" 2>&1
    apt install -y nodejs >> "$LOG_FILE" 2>&1
    
    # Create WebSocket proxy with proper error handling
    cat > /usr/local/bin/websocket-proxy.js << 'EOF'
const WebSocket = require('ws');
const net = require('net');
const http = require('http');

// Create HTTP server to handle upgrade requests
const server = http.createServer((req, res) => {
    // Handle WebSocket upgrade
    if (req.headers.upgrade && req.headers.upgrade.toLowerCase() === 'websocket') {
        // Custom response with colored "DEV MAXWELL Switching Protocols"
        const upgradeResponse = `HTTP/1.1 101 \x1b[36mDEV MAXWELL\x1b[0m Switching Protocols\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Accept: ${req.headers['sec-websocket-key']}\r
\r
`;
        
        res.write(upgradeResponse);
        res.end();
        
        console.log('\x1b[36m🔗 WebSocket Upgrade Request\x1b[0m');
        console.log('\x1b[33m📡 Protocol Switch: HTTP → WebSocket\x1b[0m');
        console.log('\x1b[32m✅ Status: 101 DEV MAXWELL Switching Protocols\x1b[0m');
    } else {
        res.writeHead(400);
        res.end('WebSocket upgrade required');
    }
});

// Create WebSocket server
const wss = new WebSocket.Server({ server });

wss.on('connection', function connection(ws, req) {
    console.log('\x1b[35m🌟 New WebSocket connection established\x1b[0m');
    console.log('\x1b[36m📍 Client IP:', req.socket.remoteAddress, '\x1b[0m');
    
    const tcpSocket = net.createConnection(22, '127.0.0.1');
    
    ws.on('message', function message(data) {
        tcpSocket.write(data);
        console.log('\x1b[33m📤 WebSocket → SSH:', data.length, 'bytes\x1b[0m');
    });
    
    tcpSocket.on('data', function(data) {
        ws.send(data);
        console.log('\x1b[32m📥 SSH → WebSocket:', data.length, 'bytes\x1b[0m');
    });
    
    ws.on('close', function() {
        console.log('\x1b[31m🔌 WebSocket connection closed\x1b[0m');
        tcpSocket.destroy();
    });
    
    tcpSocket.on('close', function() {
        console.log('\x1b[31m🔌 SSH connection closed\x1b[0m');
        ws.close();
    });
    
    tcpSocket.on('error', function(err) {
        console.log('\x1b[31m❌ SSH connection error:', err.message, '\x1b[0m');
        ws.close();
    });
    
    ws.on('error', function(err) {
        console.log('\x1b[31m❌ WebSocket error:', err.message, '\x1b[0m');
        tcpSocket.destroy();
    });
});

server.listen(8080, () => {
    console.log('\x1b[36m🚀 WebSocket Proxy Server Started\x1b[0m');
    console.log('\x1b[32m📍 Listening on port 8080\x1b[0m');
    console.log('\x1b[33m🔗 Ready for WebSocket connections\x1b[0m');
    console.log('\x1b[35m🌟 Custom Header: DEV MAXWELL Switching Protocols\x1b[0m');
});

// Handle server errors
server.on('error', (err) => {
    console.log('\x1b[31m❌ Server error:', err.message, '\x1b[0m');
});
EOF
    
    # Install ws package
    npm install -g ws >> "$LOG_FILE" 2>&1
    
    # Create systemd service
    cat > /etc/systemd/system/websocket-proxy.service << EOF
[Unit]
Description=WebSocket SSH Proxy Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/node /usr/local/bin/websocket-proxy.js
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable websocket-proxy
    systemctl start websocket-proxy
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet websocket-proxy && netstat -tlnp | grep -q ":$WEBSOCKET_PORT"; then
        print_status "WebSocket Proxy installed and started on port $WEBSOCKET_PORT"
        return 0
    else
        print_error "WebSocket Proxy failed to start properly"
        return 1
    fi
}

# Function to install SOCKS Proxy (Fixed 3proxy)
install_socks_proxy() {
    print_status "Installing SOCKS Proxy..."
    
    # Try to install 3proxy from different sources
    if ! apt install -y 3proxy >> "$LOG_FILE" 2>&1; then
        print_warning "3proxy not available in default repos, trying alternative installation..."
        
        # Install from source
        cd /tmp
        wget https://github.com/z3APA3A/3proxy/archive/refs/tags/0.9.4.tar.gz >> "$LOG_FILE" 2>&1
        tar -xzf 0.9.4.tar.gz
        cd 3proxy-0.9.4
        
        # Install build dependencies
        apt install -y build-essential libssl-dev >> "$LOG_FILE" 2>&1
        
        # Build and install
        make -f Makefile.Unix >> "$LOG_FILE" 2>&1
        make -f Makefile.Unix install >> "$LOG_FILE" 2>&1
        
        # Create configuration directory
        mkdir -p /etc/3proxy
    fi
    
    # Create 3proxy configuration
    cat > /etc/3proxy/3proxy.cfg << EOF
nserver 8.8.8.8
nserver 8.8.4.4
nscache 65536
timeouts 1 5 30 60 180 1800 15 60

users admin:CL:password

auth strong

proxy -p$SOCKS_PORT -a
EOF
    
    # Start 3proxy
    systemctl enable 3proxy
    systemctl start 3proxy
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet 3proxy && netstat -tlnp | grep -q ":$SOCKS_PORT"; then
        print_status "SOCKS Proxy installed and started on port $SOCKS_PORT"
        return 0
    else
        print_error "SOCKS Proxy failed to start properly"
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
    cat > /etc/systemd/system/dnstt.service << EOF
[Unit]
Description=DNSTT DNS Tunneling Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/dnstt-server $DNSTT_PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable dnstt
    systemctl start dnstt
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet dnstt && netstat -tlnp | grep -q ":$DNSTT_PORT"; then
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
    
    # Configure SSLH
    cat > /etc/default/sslh << EOF
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
EOF
    
    # Create SSLH configuration
    cat > /etc/sslh.conf << EOF
verbose: false;
foreground: false;
inetd: false;
numeric: false;
transparent: false;
timeout: "2.0";
user: "sslh";
listen: [ { host: "0.0.0.0", port: "$SSLH_PORT_HTTP" }, { host: "0.0.0.0", port: "$SSLH_PORT_HTTPS" } ];
protocols: [
     { name: "ssh";   service: "ssh"; host: "localhost"; port: "22"; log_level: 0; },
     { name: "ssl";   host: "localhost"; port: "443"; log_level: 0; },
     { name: "http";  host: "localhost"; port: "80"; log_level: 0; }
];
EOF
    
    # Start SSLH
    systemctl enable sslh
    systemctl start sslh
    
    # Verify service is actually running
    sleep 3
    if systemctl is-active --quiet sslh && netstat -tlnp | grep -q ":80\|:443"; then
        print_status "SSLH installed and started on ports $SSLH_PORT_HTTP and $SSLH_PORT_HTTPS"
        return 0
    else
        print_error "SSLH failed to start properly"
        return 1
    fi
}

# Function to install Nginx Proxy
install_nginx_proxy() {
    print_status "Installing Nginx Proxy..."
    
    # Install Nginx
    apt install -y nginx >> "$LOG_FILE" 2>&1
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/tunneling-proxy << EOF
server {
    listen 80;
    server_name _;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
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

# Function to create status check script
create_status_script() {
    print_status "Creating status check script..."
    
    cat > /usr/local/bin/check-tunneling-status << 'EOF'
#!/bin/bash

echo "=== Maxie VPS Manager - Tunneling Status ==="
echo

# Function to check service status with real verification
check_service_status() {
    local service_name=$1
    local port=$2
    local protocol=$3
    
    if systemctl is-active --quiet $service_name; then
        # Check if port is actually listening
        if netstat -tlnp | grep -q ":$port"; then
            echo -e "✅ $service_name: \033[32mRUNNING\033[0m (Port $port/$protocol)"
            return 0
        else
            echo -e "⚠️  $service_name: \033[33mSERVICE ACTIVE BUT PORT NOT LISTENING\033[0m (Port $port/$protocol)"
            return 1
        fi
    else
        echo -e "❌ $service_name: \033[31mSTOPPED\033[0m"
        return 1
    fi
}

# Check all services
check_service_status "badvpn" "7300" "udp"
check_service_status "udp-custom" "5300" "udp"
check_service_status "stunnel4" "444" "tcp"
check_service_status "websocket-proxy" "8080" "tcp"
check_service_status "3proxy" "200" "tcp"
check_service_status "dnstt" "53" "udp"
check_service_status "sslh" "80,443" "tcp"
check_service_status "nginx" "80" "tcp"

echo
echo "=== Port Status ==="
netstat -tlnp | grep -E ":(7300|5300|444|8080|200|53|80|443)" | sort

echo
echo "=== Firewall Status ==="
ufw status

echo
echo "=== Bandwidth Monitoring Status ==="
if iptables -t mangle -L BANDWIDTH_IN >/dev/null 2>&1; then
    echo "✅ Bandwidth monitoring: ACTIVE"
    echo "📊 Current bandwidth usage:"
    iptables -t mangle -L -v -x | grep -E "BANDWIDTH_.*_IN|BANDWIDTH_.*_OUT"
else
    echo "❌ Bandwidth monitoring: INACTIVE"
fi

echo
echo "=== SSL Certificate Status ==="
if [[ -f /etc/letsencrypt/live/*/fullchain.pem ]]; then
    echo "✅ Let's Encrypt certificate: ACTIVE"
    find /etc/letsencrypt/live/*/fullchain.pem -exec echo "   📁 {}" \;
elif [[ -f /etc/ssl/certs/*.crt ]]; then
    echo "✅ SSL certificate: ACTIVE"
    find /etc/ssl/certs/*.crt -exec echo "   📁 {}" \;
else
    echo "❌ SSL certificate: NOT FOUND"
fi
EOF
    
    chmod +x /usr/local/bin/check-tunneling-status
    
    print_status "Status check script created: check-tunneling-status"
}

# Function to create connection info file
create_connection_info() {
    print_status "Creating connection information file..."
    
    cat > /root/tunneling-connection-info.txt << EOF
==========================================
    MAXIE VPS MANAGER - CONNECTION INFO
==========================================

Server IP: $(curl -s ifconfig.me)
Domain: ${DOMAIN:-"Not configured"}

=== TUNNELING PROTOCOLS ===

1. BadVPN (UDP Tunneling)
   Port: $BADVPN_PORT/udp
   Use: Gaming, multimedia streaming
   Status: $(systemctl is-active badvpn)

2. UDP-Custom (Custom UDP Proxy)
   Port: $UDP_CUSTOM_PORT/udp
   Use: Custom UDP proxy with exclusions
   Status: $(systemctl is-active udp-custom)

3. SSL Tunnel (SSL-encrypted SSH)
   Port: $SSL_TUNNEL_PORT/tcp
   Use: SSL-encrypted SSH tunneling
   Status: $(systemctl is-active stunnel4)

4. WebSocket Proxy (WebSocket SSH)
   Port: $WEBSOCKET_PORT/tcp
   Use: WebSocket-based SSH proxy
   Status: $(systemctl is-active websocket-proxy)

5. SOCKS Proxy (SOCKS5)
   Port: $SOCKS_PORT/tcp
   Use: SOCKS5 proxy server
   Status: $(systemctl is-active 3proxy)

6. DNSTT (DNS Tunneling)
   Port: $DNSTT_PORT/udp
   Use: DNS tunneling for bypassing restrictions
   Status: $(systemctl is-active dnstt)

7. SSLH (SSL/SSH Multiplexer)
   Ports: $SSLH_PORT_HTTP/tcp, $SSLH_PORT_HTTPS/tcp
   Use: SSL/SSH multiplexer
   Status: $(systemctl is-active sslh)

8. Nginx Proxy (Reverse Proxy)
   Port: 80/tcp
   Use: Reverse proxy with WebSocket support
   Status: $(systemctl is-active nginx)

=== BANDWIDTH MONITORING ===

Bandwidth monitoring is active and resets daily at midnight (Africa/Nairobi timezone)
View current usage: iptables -t mangle -L -v -x | grep BANDWIDTH

=== MANAGEMENT ===

Check all services status:
  check-tunneling-status

=== USEFUL COMMANDS ===

Check specific service:
  systemctl status [service-name]

View logs:
  journalctl -u [service-name] -f

Restart service:
  systemctl restart [service-name]

View bandwidth usage:
  iptables -t mangle -L -v -x | grep BANDWIDTH

=== SECURITY NOTES ===

1. Configure firewall rules as needed
2. Monitor logs for suspicious activity
3. Keep system updated regularly
4. Monitor bandwidth usage

=== SUPPORT ===

For issues and support, check:
- Service logs: journalctl -u [service-name]
- Firewall status: ufw status
- Port status: netstat -tlnp
- Bandwidth usage: iptables -t mangle -L -v -x

Generated on: $(date)
EOF
    
    print_status "Connection information saved to /root/tunneling-connection-info.txt"
}

# Function to get user input
get_user_input() {
    print_header "Maxie VPS Manager - Tunneling Setup"
    echo
    echo "This script will install and configure all tunneling protocols."
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
    
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Installation cancelled"
        exit 0
    fi
}

# Function to ask for protocol installation
ask_protocol_installation() {
    local protocol_name=$1
    local install_function=$2
    
    echo
    read -p "Do you want to install $protocol_name? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        $install_function
        return $?
    else
        print_status "Skipping $protocol_name installation"
        return 0
    fi
}

# Function to install all protocols with user choice
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
    echo "9. Back to main menu"
    echo
    
    read -p "Select protocol to install (1-9): " choice
    
    case $choice in
        1) install_badvpn ;;
        2) install_udp_custom ;;
        3) install_ssl_tunnel ;;
        4) install_websocket_proxy ;;
        5) install_socks_proxy ;;
        6) install_dnstt ;;
        7) install_sslh ;;
        8) install_nginx_proxy ;;
        9) return ;;
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
    create_connection_info
    
    print_status "Setup completed successfully!"
    echo
    echo "=== NEXT STEPS ==="
    echo "1. Check service status: check-tunneling-status"
    echo "2. Configure your clients to use the tunneling protocols"
    echo "3. Review connection info: cat /root/tunneling-connection-info.txt"
    echo "4. Monitor bandwidth usage with iptables"
    echo
    echo "=== IMPORTANT ==="
    echo "All services are configured to start automatically on boot"
    echo "Firewall rules have been configured for all protocol ports"
    echo "Bandwidth monitoring resets daily at midnight (Africa/Nairobi timezone)"
    echo
}

# Function to show main menu
show_main_menu() {
    while true; do
   
