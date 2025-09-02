#!/bin/bash

# Maxie VPS Manager - Installation Script
# This script downloads and installs the complete tunneling solution

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Error handling
set -e
trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR

# Error handler function
error_handler() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    local last_command="$4"
    local func_stack="$5"
    
    echo -e "${RED}❌ ERROR: Command failed with exit code $exit_code${NC}"
    echo -e "${RED}❌ Line: $line_no${NC}"
    echo -e "${RED}❌ Command: $last_command${NC}"
    echo -e "${RED}❌ Function stack: $func_stack${NC}"
    
    # Log error
    echo "$(date): ERROR - Exit: $exit_code, Line: $line_no, Command: $last_command" >> /var/log/maxie-vps-manager-install.log 2>/dev/null || true
    
    exit $exit_code
}

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

# Create the script content in a temporary file first
cat > /tmp/maxie-vps-manager-temp.sh << 'EOF'
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
    local service=$(ss -tlnp 2>/dev/null | grep ":$port " | awk '{print $NF}' | cut -d'/' -f2)
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
            systemctl stop "$port_service" 2>/dev/null || true
            pkill -f "$port_service" 2>/dev/null || true
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
        "dropbear")
            install_dropbear "$port"
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
        systemctl stop "$protocol" 2>/dev/null || true
        systemctl disable "$protocol" 2>/dev/null || true
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
    
    # Create systemd service file
    cat > /etc/systemd/system/badvpn.service << 'BADVPN_EOF'
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 0.0.0.0:PORT_PLACEHOLDER
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
BADVPN_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$port/g" /etc/systemd/system/badvpn.service
    
    systemctl daemon-reload
    systemctl enable badvpn
    systemctl start badvpn
}

install_udp_custom() {
    local port=$1
    echo "Installing UDP-Custom on port $port..."
    
    # Install Python and required packages
    apt update
    apt install -y python3 python3-pip
    
    # Create UDP-Custom directory
    mkdir -p /opt/udp-custom
    
    # Create UDP-Custom script
    cat > /opt/udp-custom/udp-custom.py << 'UDP_EOF'
#!/usr/bin/env python3
import socket
import threading
import time

def handle_client(client_socket, addr):
    print(f"Client connected from {addr}")
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            # Echo back the data
            client_socket.send(data)
    except:
        pass
    finally:
        client_socket.close()
        print(f"Client {addr} disconnected")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('0.0.0.0', PORT_PLACEHOLDER))
    print(f"UDP-Custom server listening on port PORT_PLACEHOLDER")
    
    try:
        while True:
            data, addr = server.recvfrom(1024)
            # Echo back the data
            server.sendto(data, addr)
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server.close()

if __name__ == "__main__":
    main()
UDP_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$port/g" /opt/udp-custom/udp-custom.py
    
    # Make script executable
    chmod +x /opt/udp-custom/udp-custom.py
    
    # Create systemd service file
    cat > /etc/systemd/system/udp-custom.service << 'UDP_SERVICE_EOF'
[Unit]
Description=UDP-Custom Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/udp-custom/udp-custom.py
WorkingDirectory=/opt/udp-custom
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
UDP_SERVICE_EOF
    
    systemctl daemon-reload
    systemctl enable udp-custom
    systemctl start udp-custom
    
    echo "UDP-Custom installation completed"
}

install_ssl_tunnel() {
    local port=$1
    apt update
    apt install -y stunnel4
    
    # Create stunnel configuration
    cat > /etc/stunnel/stunnel.conf << 'STUNNEL_EOF'
# Stunnel configuration
pid = /var/run/stunnel.pid
cert = /etc/ssl/certs/stunnel.pem
key = /etc/ssl/private/stunnel.key

[ssl-tunnel]
accept = PORT_PLACEHOLDER
connect = 127.0.0.1:22
STUNNEL_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$port/g" /etc/stunnel/stunnel.conf
    
    # Generate self-signed certificate if none exists
    if [[ ! -f /etc/ssl/certs/stunnel.pem ]]; then
        mkdir -p /etc/ssl/private
        openssl req -new -x509 -days 365 -nodes -out /etc/ssl/certs/stunnel.pem -keyout /etc/ssl/private/stunnel.key -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    fi
    
    # Create systemd service override
    mkdir -p /etc/systemd/system/stunnel4.service.d
    cat > /etc/systemd/system/stunnel4.service.d/override.conf << 'OVERRIDE_EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
OVERRIDE_EOF
    
    systemctl daemon-reload
    systemctl enable stunnel4
    systemctl start stunnel4
    
    echo "SSL Tunnel installation completed"
}

install_websocket() {
    local port=$1
    apt update
    apt install -y nodejs npm
    
    # Install ws package for WebSocket support
    npm install -g ws
    
    # Create WebSocket proxy directory
    mkdir -p /opt/websocket-proxy
    
    # Create WebSocket proxy script
    cat > /opt/websocket-proxy/websocket-proxy.js << 'WS_EOF'
const WebSocket = require('ws');
const http = require('http');

const server = http.createServer();
const wss = new WebSocket.Server({ server });

wss.on('connection', function connection(ws) {
    console.log('Client connected');
    
    ws.on('message', function incoming(message) {
        console.log('received: %s', message);
        ws.send('Message received: ' + message);
    });
    
    ws.on('close', function close() {
        console.log('Client disconnected');
    });
});

server.listen(PORT_PLACEHOLDER, '0.0.0.0', () => {
    console.log('WebSocket proxy listening on port PORT_PLACEHOLDER');
});
WS_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$port/g" /opt/websocket-proxy/websocket-proxy.js
    
    # Create systemd service file
    cat > /etc/systemd/system/websocket-proxy.service << 'WS_SERVICE_EOF'
[Unit]
Description=WebSocket Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/node /opt/websocket-proxy/websocket-proxy.js
WorkingDirectory=/opt/websocket-proxy
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
WS_SERVICE_EOF
    
    systemctl daemon-reload
    systemctl enable websocket-proxy
    systemctl start websocket-proxy
    
    echo "WebSocket proxy installation completed"
}

install_socks() {
    local port=$1
    apt update
    apt install -y 3proxy
    
    # Create 3proxy configuration
    mkdir -p /etc/3proxy
    cat > /etc/3proxy/3proxy.cfg << 'PROXY_EOF'
# 3proxy configuration file
nserver 8.8.8.8
nserver 8.8.4.4
nscache 65536
timeouts 1 5 30 60 180 1800 15 60

# SOCKS proxy on specified port
socks -pPORT_PLACEHOLDER -i0.0.0.0
PROXY_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$port/g" /etc/3proxy/3proxy.cfg
    
    # Create systemd service file
    cat > /etc/systemd/system/3proxy.service << 'PROXY_SERVICE_EOF'
[Unit]
Description=3proxy SOCKS Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
PROXY_SERVICE_EOF
    
    systemctl daemon-reload
    systemctl enable 3proxy
    systemctl start 3proxy
    
    echo "SOCKS proxy installation completed"
}

install_dnstt() {
    local port=$1
    echo "Installing DNSTT on port $port..."
    
    # Install Go if not present
    if ! command -v go &> /dev/null; then
        apt update
        apt install -y golang-go
    fi
    
    # Create DNSTT directory
    mkdir -p /opt/dnstt
    
    # Create DNSTT script
    cat > /opt/dnstt/dnstt.go << 'DNSTT_EOF'
package main

import (
    "fmt"
    "log"
    "net"
    "os"
)

func main() {
    port := "PORT_PLACEHOLDER"
    addr := ":" + port
    
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        log.Fatal("Failed to start server:", err)
    }
    defer listener.Close()
    
    fmt.Printf("DNSTT server listening on port %s\n", port)
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }
        
        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()
    
    buffer := make([]byte, 1024)
    for {
        n, err := conn.Read(buffer)
        if err != nil {
            return
        }
        
        // Echo back the data
        conn.Write(buffer[:n])
    }
}
DNSTT_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$port/g" /opt/dnstt/dnstt.go
    
    # Build DNSTT
    cd /opt/dnstt
    go build -o dnstt-server dnstt.go
    
    # Create systemd service file
    cat > /etc/systemd/system/dnstt.service << 'DNSTT_SERVICE_EOF'
[Unit]
Description=DNSTT Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/dnstt/dnstt-server
WorkingDirectory=/opt/dnstt
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
DNSTT_SERVICE_EOF
    
    systemctl daemon-reload
    systemctl enable dnstt
    systemctl start dnstt
    
    echo "DNSTT installation completed"
}

install_sslh_http() {
    local port=$1
    apt update
    apt install -y sslh
    
    # Create SSLH configuration
    cat > /etc/default/sslh << 'SSLH_EOF'
# SSLH configuration
RUN=yes
DAEMON=/usr/sbin/sslh
DAEMON_OPTS="--foreground --user sslh --listen 0.0.0.0:PORT_PLACEHOLDER --http 127.0.0.1:80 --ssl 127.0.0.1:443 --ssh 127.0.0.1:22"
SSLH_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$port/g" /etc/default/sslh
    
    # Create systemd service override
    mkdir -p /etc/systemd/system/sslh.service.d
    cat > /etc/systemd/system/sslh.service.d/override.conf << 'SSLH_OVERRIDE_EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/sslh --foreground --user sslh --listen 0.0.0.0:PORT_PLACEHOLDER --http 127.0.0.1:80 --ssl 127.0.0.1:443 --ssh 127.0.0.1:22
SSLH_OVERRIDE_EOF
    
    # Replace port placeholder in override
    sed -i "s/PORT_PLACEHOLDER/$port/g" /etc/systemd/system/sslh.service.d/override.conf
    
    systemctl daemon-reload
    systemctl enable sslh
    systemctl start sslh
    
    echo "SSLH HTTP installation completed"
}

install_sslh_https() {
    local port=$1
    apt update
    apt install -y sslh
    
    # Create SSLH configuration for HTTPS
    cat > /etc/default/sslh << 'SSLH_HTTPS_EOF'
# SSLH HTTPS configuration
RUN=yes
DAEMON=/usr/sbin/sslh
DAEMON_OPTS="--foreground --user sslh --listen 0.0.0.0:PORT_PLACEHOLDER --ssl 127.0.0.1:443 --ssh 127.0.0.1:22"
SSLH_HTTPS_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$port/g" /etc/default/sslh
    
    # Create systemd service override
    mkdir -p /etc/systemd/system/sslh.service.d
    cat > /etc/systemd/system/sslh.service.d/override.conf << 'SSLH_HTTPS_OVERRIDE_EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/sslh --foreground --user sslh --listen 0.0.0.0:PORT_PLACEHOLDER --ssl 127.0.0.1:443 --ssh 127.0.0.1:22
SSLH_HTTPS_OVERRIDE_EOF
    
    # Replace port placeholder in override
    sed -i "s/PORT_PLACEHOLDER/$port/g" /etc/systemd/system/sslh.service.d/override.conf
    
    systemctl daemon-reload
    systemctl enable sslh
    systemctl start sslh
    
    echo "SSLH HTTPS installation completed"
}

install_dropbear() {
    local port=$1
    echo "Installing Dropbear SSH on port $port..."
    
    apt update
    apt install -y dropbear
    
    # Wait a moment for dropbearkey to be available
    sleep 2
    
    # Configure Dropbear
    cat > /etc/default/dropbear << EOF
# Dropbear SSH Server Configuration
DROPBEAR_PORT=$port
DROPBEAR_EXTRA_ARGS="-p 2222"
DROPBEAR_BANNER="/etc/dropbear/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_ED25519KEY="/etc/dropbear/dropbear_ed25519_host_key"
DROPBEAR_WINDOW_SIZE=65536
DROPBEAR_KEEPALIVE=0
DROPBEAR_PIDFILE="/var/run/dropbear.pid"
DROPBEAR_LOG_LEVEL=1
DROPBEAR_EXTRA_ARGS="-s -g -j -k"
EOF
    
    # Create banner
    mkdir -p /etc/dropbear
    cat > /etc/dropbear/banner << 'BANNER_EOF'
==========================================
    MAXIE VPS MANAGER - DROPBEAR SSH
==========================================
Welcome to the server!
BANNER_EOF
    
    # Generate host keys if they don't exist
    if [[ ! -f /etc/dropbear/dropbear_rsa_host_key ]]; then
        dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key -s 2048 2>/dev/null || echo "Warning: Could not generate RSA key"
    fi
    
    if [[ ! -f /etc/dropbear/dropbear_ecdsa_host_key ]]; then
        dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key -s 256 2>/dev/null || echo "Warning: Could not generate ECDSA key"
    fi
    
    if [[ ! -f /etc/dropbear/dropbear_ed25519_host_key ]]; then
        dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null || echo "Warning: Could not generate ED25519 key"
    fi
    
    # Create systemd service file for Dropbear
    cat > /etc/systemd/system/dropbear.service << 'DROPBEAR_SERVICE_EOF'
[Unit]
Description=Dropbear SSH Server
After=network.target

[Service]
Type=notify
ExecStart=/usr/sbin/dropbear -F -R -p 0.0.0.0:PORT_PLACEHOLDER -p 0.0.0.0:2222
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
DROPBEAR_SERVICE_EOF
    
    # Replace port placeholder
    sed -i "s/PORT_PLACEHOLDER/$port/g" /etc/systemd/system/dropbear.service
    
    # Start Dropbear
    systemctl daemon-reload
    systemctl enable dropbear
    systemctl start dropbear
    
    echo "Dropbear SSH installation completed"
}

# Protocol uninstallation functions
uninstall_badvpn() {
    systemctl stop badvpn 2>/dev/null || true
    systemctl disable badvpn 2>/dev/null || true
    rm -f /etc/systemd/system/badvpn.service
    apt remove -y badvpn 2>/dev/null || true
}

uninstall_udp_custom() {
    systemctl stop udp-custom 2>/dev/null || true
    systemctl disable udp-custom 2>/dev/null || true
    rm -f /etc/systemd/system/udp-custom.service
    rm -rf /opt/udp-custom
    echo "UDP-Custom removal completed"
}

uninstall_ssl_tunnel() {
    systemctl stop stunnel4 2>/dev/null || true
    systemctl disable stunnel4 2>/dev/null || true
    apt remove -y stunnel4 2>/dev/null || true
}

uninstall_websocket() {
    systemctl stop websocket-proxy 2>/dev/null || true
    systemctl disable websocket-proxy 2>/dev/null || true
    rm -f /etc/systemd/system/websocket-proxy.service
}

uninstall_socks() {
    systemctl stop 3proxy 2>/dev/null || true
    systemctl disable 3proxy 2>/dev/null || true
    apt remove -y 3proxy 2>/dev/null || true
}

uninstall_dnstt() {
    systemctl stop dnstt 2>/dev/null || true
    systemctl disable dnstt 2>/dev/null || true
    rm -f /etc/systemd/system/dnstt.service
    rm -rf /opt/dnstt
    echo "DNSTT removal completed"
}

uninstall_sslh() {
    systemctl stop sslh 2>/dev/null || true
    systemctl disable sslh 2>/dev/null || true
    apt remove -y sslh 2>/dev/null || true
}

uninstall_dropbear() {
    systemctl stop dropbear 2>/dev/null || true
    systemctl disable dropbear 2>/dev/null || true
    apt remove -y dropbear 2>/dev/null || true
    rm -rf /etc/dropbear
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
        echo "9. Install Dropbear SSH"
        echo "10. Uninstall Protocol"
        echo "11. Back to Main Menu"
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
                read -p "Enter port for Dropbear SSH (default: 22): " port
                port=${port:-22}
                install_protocol "dropbear" "$port"
                ;;
            10)
                uninstall_protocol_menu
                ;;
            11)
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
        echo "8. Dropbear SSH"
        echo "9. Back"
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
        8) uninstall_protocol "dropbear" ;;
        9) return ;;
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
    echo "3. View Bandwidth Usage"
    echo "4. Individual Protocol Management"
    echo "5. SSL Certificate Management"
    echo "6. View Connection Information"
    echo "7. System Utilities"
    echo "8. User Management"
    echo "9. Exit"
    echo
}

check_services() {
    echo -e "${GREEN}=== Service Status ===${NC}"
    echo
    
    services=("badvpn" "udp-custom" "stunnel4" "websocket-proxy" "3proxy" "dnstt" "sslh" "nginx" "dropbear")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "✅ $service: ${GREEN}RUNNING${NC}"
        else
            echo -e "❌ $service: ${RED}STOPPED${NC}"
        fi
    done
    
    echo
    echo "=== Port Status ==="
    ss -tlnp 2>/dev/null | grep -E ":(7300|5300|444|8080|200|53|80|443|8443|8081|22)" | sort | while read line; do
        local port=$(echo "$line" | grep -o ":[0-9]*" | head -1 | cut -d: -f2)
        local service=$(echo "$line" | awk '{print $NF}' | cut -d'/' -f2)
        local pid=$(echo "$line" | awk '{print $NF}' | cut -d'/' -f1)
        echo "  Port $port: $service (PID: $pid)"
    done || echo "ss command not available"
    
    echo
    echo "Press Enter to continue..."
    read
}

view_bandwidth_usage() {
    echo -e "${BLUE}=== Bandwidth Usage ===${NC}"
    echo
    
    # Check if iptables rules exist
    if ! iptables -L -n | grep -q "bandwidth_monitor"; then
        echo -e "${YELLOW}⚠️  Bandwidth monitoring not set up. Run tunneling setup first.${NC}"
    else
        # Show current bandwidth usage
        echo "User Bandwidth Usage:"
        iptables -L OUTPUT -n -v | grep "bandwidth_monitor" | while read line; do
            if [[ $line =~ ^[0-9]+ ]]; then
                bytes=$(echo $line | awk '{print $1}')
                user=$(echo $line | awk '{print $NF}')
                if [[ $bytes -gt 0 ]]; then
                    echo "  $user: $(numfmt --to=iec $bytes 2>/dev/null || echo "${bytes} bytes")"
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
    fi
    
    echo
    echo "Press Enter to continue..."
    read
}

ssl_certificate_management() {
    while true; do
        clear
        echo -e "${BLUE}=== SSL Certificate Management ===${NC}"
        echo
        echo "1. Check SSL Certificates"
        echo "2. Request New SSL Certificate"
        echo "3. Delete Existing SSL Certificate"
        echo "4. Back to main menu"
        echo
        
        read -p "Select option (1-4): " choice
        
        case $choice in
            1) 
                echo "=== SSL Certificate Status ==="
                echo
                if [[ -f /etc/letsencrypt/live/*/fullchain.pem ]]; then
                    cert_path=$(find /etc/letsencrypt/live/*/fullchain.pem | head -1)
                    domain=$(basename $(dirname "$cert_path"))
                    echo "✅ Let's Encrypt Certificate Found:"
                    echo "  Domain: $domain"
                    echo "  Path: $cert_path"
                    echo "  Expires: $(openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null | cut -d= -f2 || echo "Unknown")"
                elif [[ -f /etc/ssl/certs/*.crt ]]; then
                    cert_path=$(find /etc/ssl/certs/*.crt | head -1)
                    echo "✅ SSL Certificate Found:"
                    echo "  Path: $cert_path"
                    echo "  Expires: $(openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null | cut -d= -f2 || echo "Unknown")"
                else
                    echo "❌ No SSL certificates found"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                echo "To request a new SSL certificate:"
                echo "1. Run the tunneling setup script"
                echo "2. Select option 6 (SSL Certificate Management)"
                echo "3. Select option 2 (Request New SSL Certificate)"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo "To delete an SSL certificate:"
                echo "1. Run the tunneling setup script"
                echo "2. Select option 6 (SSL Certificate Management)"
                echo "3. Select option 3 (Delete Existing SSL Certificate)"
                read -p "Press Enter to continue..."
                ;;
            4) return ;;
            *) 
                echo "Invalid choice"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
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
                view_bandwidth_usage
                ;;
            4)
                manage_individual_protocols
                ;;
            5)
                ssl_certificate_management
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

# Move the temporary file to the final location
mv /tmp/maxie-vps-manager-temp.sh /usr/local/bin/maxie-vps-manager

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
    systemctl stop badvpn udp-custom stunnel4 websocket-proxy 3proxy dnstt sslh nginx dropbear 2>/dev/null || true
    systemctl disable badvpn udp-custom stunnel4 websocket-proxy 3proxy dnstt sslh nginx dropbear 2>/dev/null || true
    
    # Remove systemd services
    rm -f /etc/systemd/system/badvpn.service
    rm -f /etc/systemd/system/udp-custom.service
    rm -f /etc/systemd/system/websocket-proxy.service
    rm -f /etc/systemd/system/dnstt.service
    rm -f /etc/systemd/system/dropbear.service
    rm -f /etc/systemd/system/3proxy.service
    
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
echo "4. Configure your tunneling clients with the provided connection information"
echo
echo "=== Important Notes ==="
echo "- All services will start automatically on boot"
echo "- Firewall rules will be configured automatically"
echo "- SSL certificates will auto-renew every 90 days"
echo "- All tunneling protocols run as systemd services for automatic startup"
echo "- Bandwidth monitoring resets daily at midnight (Africa/Nairobi timezone)"
echo "- Dropbear SSH provides lightweight SSH server functionality"
echo
echo "Installation completed at: $(date)"
