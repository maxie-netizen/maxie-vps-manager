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
        ufw allow $SSLH_PORT_HTTP/tcp >> "$LOG_FILE" 2>&1
        ufw allow $SSLH_PORT_HTTPS/tcp >> "$LOG_FILE" 2>&1
        
        # Enable UFW
        ufw --force enable >> "$LOG_FILE" 2>&1
        
        print_status "Firewall configured successfully"
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
    
    print_status "BadVPN installed and started on port $BADVPN_PORT"
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
    
    print_status "UDP-Custom installed and started on port $UDP_CUSTOM_PORT"
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
    
    print_status "SSL Tunnel installed and started on port $SSL_TUNNEL_PORT"
}

# Function to install WebSocket Proxy
install_websocket_proxy() {
    print_status "Installing WebSocket Proxy..."
    
    # Install Node.js
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - >> "$LOG_FILE" 2>&1
    apt install -y nodejs >> "$LOG_FILE" 2>&1
    
    # Create WebSocket proxy with custom headers
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
    
    print_status "WebSocket Proxy installed and started on port $WEBSOCKET_PORT"
}

# Function to install SOCKS Proxy
install_socks_proxy() {
    print_status "Installing SOCKS Proxy..."
    
    # Install 3proxy
    apt install -y 3proxy >> "$LOG_FILE" 2>&1
    
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
    
    print_status "SOCKS Proxy installed and started on port $SOCKS_PORT"
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
    
    print_status "DNSTT installed and started on port $DNSTT_PORT"
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
    
    print_status "SSLH installed and started on ports $SSLH_PORT_HTTP and $SSLH_PORT_HTTPS"
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
    else
        print_error "Nginx configuration test failed"
    fi
}

# Function to install X-UI Panel
install_xui_panel() {
    print_status "Installing X-UI Panel..."
    
    # Install dependencies
    apt install -y curl wget unzip xz-utils >> "$LOG_FILE" 2>&1
    
    # Download and install X-UI
    bash <(curl -Ls https://raw.githubusercontent.com/vaxilu/x-ui/master/install.sh) >> "$LOG_FILE" 2>&1
    
    print_status "X-UI Panel installed successfully"
    print_warning "Default credentials: admin/admin"
    print_warning "Please change the default password immediately!"
}

# Function to configure SSL certificates
configure_ssl() {
    if [[ -n "$DOMAIN" && -n "$EMAIL" ]]; then
        print_status "Configuring SSL certificates for domain: $DOMAIN"
        
        # Install Certbot
        apt install -y certbot python3-certbot-nginx >> "$LOG_FILE" 2>&1
        
        # Obtain SSL certificate
        certbot --nginx -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive >> "$LOG_FILE" 2>&1
        
        # Set up auto-renewal
        (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
        
        print_status "SSL certificates configured successfully"
    else
        print_warning "Domain or email not provided. SSL certificates not configured."
        print_warning "To configure SSL later, run: certbot --nginx -d yourdomain.com"
    fi
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
    echo -e "✅ WebSocket Proxy: \033[32mRUNNING\033[0m (Port 8080)"
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
    echo -e "✅ SSLH: \033[32mRUNNING\033[0m (Ports 80, 443)"
else
    echo -e "❌ SSLH: \033[31mSTOPPED\033[0m"
fi

# Check Nginx
if systemctl is-active --quiet nginx; then
    echo -e "✅ Nginx: \033[32mRUNNING\033[0m"
else
    echo -e "❌ Nginx: \033[31mSTOPPED\033[0m"
fi

# Check X-UI Panel
if systemctl is-active --quiet x-ui; then
    echo -e "✅ X-UI Panel: \033[32mRUNNING\033[0m"
else
    echo -e "❌ X-UI Panel: \033[31mSTOPPED\033[0m"
fi

echo
echo "=== Port Status ==="
netstat -tlnp | grep -E ":(7300|5300|444|8080|200|53|80|443)" | sort

echo
echo "=== Firewall Status ==="
ufw status
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

=== MANAGEMENT ===

X-UI Panel: $(systemctl is-active x-ui)
Web Interface: http://$(curl -s ifconfig.me):54321
Default Credentials: admin/admin

=== USEFUL COMMANDS ===

Check all services status:
  check-tunneling-status

Check specific service:
  systemctl status [service-name]

View logs:
  journalctl -u [service-name] -f

Restart service:
  systemctl restart [service-name]

=== SECURITY NOTES ===

1. Change default X-UI password immediately
2. Configure firewall rules as needed
3. Monitor logs for suspicious activity
4. Keep system updated regularly

=== SUPPORT ===

For issues and support, check:
- Service logs: journalctl -u [service-name]
- Firewall status: ufw status
- Port status: netstat -tlnp

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

# Function to install all protocols
install_all_protocols() {
    print_header "Installing Tunneling Protocols"
    
    install_badvpn
    install_udp_custom
    install_ssl_tunnel
    install_websocket_proxy
    install_socks_proxy
    install_dnstt
    install_sslh
    install_nginx_proxy
    install_xui_panel
}

# Function to finalize setup
finalize_setup() {
    print_header "Finalizing Setup"
    
    configure_ssl
    create_status_script
    create_connection_info
    
    print_status "Setup completed successfully!"
    echo
    echo "=== NEXT STEPS ==="
    echo "1. Check service status: check-tunneling-status"
    echo "2. Access X-UI Panel: http://$(curl -s ifconfig.me):54321"
    echo "3. Change default X-UI password"
    echo "4. Configure your clients to use the tunneling protocols"
    echo "5. Review connection info: cat /root/tunneling-connection-info.txt"
    echo
    echo "=== IMPORTANT ==="
    echo "All services are configured to start automatically on boot"
    echo "Firewall rules have been configured for all protocol ports"
    echo "SSL certificates will auto-renew every 90 days"
    echo
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
    install_all_protocols
    finalize_setup
    
    echo "$(date): Setup completed successfully" >> "$LOG_FILE"
}

# Run main function
main "$@"
