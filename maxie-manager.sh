#!/bin/bash

# Maxie VPS Manager - Advanced Multi-Protocol Manager

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Paths
CONFIG_DIR="/etc/maxie"
CONFIG_FILE="$CONFIG_DIR/config.conf"
SERVICES_FILE="$CONFIG_DIR/services.conf"
SCRIPTS_DIR="$CONFIG_DIR/scripts"
BANNER_DIR="$CONFIG_DIR/banners"
TEMPLATES_DIR="$CONFIG_DIR/templates"
BANDWIDTH_DB="$CONFIG_DIR/bandwidth.db"
SERVICES_STATUS="$CONFIG_DIR/services.status"
LOG_DIR="/var/log/maxie"

# Load configuration and scripts
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        echo -e "${RED}Configuration file missing! Reinstall the script.${NC}"
        exit 1
    fi
    
    if [ -f "$SERVICES_FILE" ]; then
        source "$SERVICES_FILE"
    fi
    
    # Load all component scripts
    for script in "$SCRIPTS_DIR"/*.sh; do
        if [ -f "$script" ]; then
            source "$script"
        fi
    done
}

# Display banner
show_banner() {
    if [ -f "$BANNER_DIR/welcome.ban" ] && [ "$BANNER_ENABLED" = "true" ]; then
        # Process banner with colors
        banner_content=$(sed \
            -e "s/\${RED}/$RED/g" \
            -e "s/\${GREEN}/$GREEN/g" \
            -e "s/\${YELLOW}/$YELLOW/g" \
            -e "s/\${BLUE}/$BLUE/g" \
            -e "s/\${CYAN}/$CYAN/g" \
            -e "s/\${MAGENTA}/$MAGENTA/g" \
            -e "s/\${NC}/$NC/g" \
            "$BANNER_DIR/welcome.ban")
        echo -e "$banner_content"
    fi
}

# Show protocol switch banner
show_switch_banner() {
    local protocol=$1
    local port=$2
    local status=$3
    
    if [ -f "$BANNER_DIR/switch.ban" ]; then
        content=$(sed \
            -e "s/\${protocol}/$protocol/g" \
            -e "s/\${port}/$port/g" \
            -e "s/\${status}/$status/g" \
            -e "s/\${RED}/$RED/g" \
            -e "s/\${GREEN}/$GREEN/g" \
            -e "s/\${YELLOW}/$YELLOW/g" \
            -e "s/\${BLUE}/$BLUE/g" \
            -e "s/\${CYAN}/$CYAN/g" \
            -e "s/\${MAGENTA}/$MAGENTA/g" \
            -e "s/\${NC}/$NC/g" \
            "$BANNER_DIR/switch.ban")
        echo -e "$content"
    else
        echo -e "${GREEN}╔══════════════════════════════════════════╗"
        echo -e "║${YELLOW}          101 Switching Protocols         ${GREEN}║"
        echo -e "║${CYAN}    Protocol: $protocol - Port: $port       ${GREEN}║"
        echo -e "║${MAGENTA}         Status: $status                 ${GREEN}║"
        echo -e "╚══════════════════════════════════════════╝${NC}"
    fi
}

# Error handling function
handle_error() {
    local error_msg=$1
    local service_name=$2
    
    echo -e "${RED}Error: $error_msg${NC}"
    echo -e "${YELLOW}Failed to configure $service_name${NC}"
    read -p "Press Enter to continue..."
    return 1
}

# Port conflict checking
check_port_conflict() {
    local port=$1
    local service_name=$2
    
    if lsof -i :"$port" >/dev/null 2>&1; then
        echo -e "${RED}Port $port is already in use!${NC}"
        echo -e "${YELLOW}Please free port $port for $service_name to work properly.${NC}"
        echo -e "Current process using port $port:"
        lsof -i :"$port" | awk 'NR==2 {print $1 " (PID:" $2 ")"}'
        read -p "Press Enter to return to main menu..."
        return 1
    fi
    return 0
}

# Install all services
install_all_services() {
    echo -e "${CYAN}Installing all services...${NC}"
    
    # Check and install each service based on config
    if [ "$SSH" = "1" ]; then
        setup_ssh
    fi
    
    if [ "$DROPBEAR" = "1" ]; then
        setup_dropbear
    fi
    
    if [ "$V2RAY" = "1" ]; then
        setup_v2ray
    fi
    
    if [ "$SSL_TLS" = "1" ]; then
        setup_ssl_tls
    fi
    
    if [ "$STUNNEL" = "1" ]; then
        setup_stunnel
    fi
    
    if [ "$WEBSOCKET" = "1" ]; then
        setup_websocket
    fi
    
    if [ "$BANDWIDTH_MONITORING" = "1" ]; then
        setup_bandwidth_monitoring
    fi
    
    echo -e "${GREEN}All services installed successfully!${NC}"
}

# Service status monitoring
check_service_status() {
    local service_name=$1
    local display_name=$2
    
    if systemctl is-active --quiet "$service_name"; then
        echo -e "$display_name: ${GREEN}Active${NC}"
        return 0
    else
        echo -e "$display_name: ${RED}Not Running${NC}"
        return 1
    fi
}

# Monitor all services
monitor_services() {
    echo -e "${CYAN}Service Status:${NC}"
    echo -e "══════════════════════════════════════════"
    
    check_service_status "ssh" "SSH"
    check_service_status "dropbear" "Dropbear"
    check_service_status "v2ray" "V2Ray"
    check_service_status "stunnel4" "Stunnel"
    check_service_status "sslh" "SSLH"
    check_service_status "nginx" "Nginx"
    
    # Check WebSocket manually if not a system service
    if netstat -tuln | grep -q ":2096"; then
        echo -e "WebSocket: ${GREEN}Active${NC}"
    else
        echo -e "WebSocket: ${RED}Not Running${NC}"
    fi
    
    echo -e "══════════════════════════════════════════"
}

# System resource monitoring
system_stats() {
    echo -e "${CYAN}System Resources:${NC}"
    echo -e "══════════════════════════════════════════"
    
    # CPU usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
    echo -e "CPU Usage: ${YELLOW}$cpu_usage%${NC}"
    
    # Memory usage
    mem_usage=$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')
    echo -e "Memory Usage: ${YELLOW}$mem_usage${NC}"
    
    # Disk usage
    disk_usage=$(df -h / | awk 'NR==2{print $5}')
    echo -e "Disk Usage: ${YELLOW}$disk_usage${NC}"
    
    # Uptime
    uptime_info=$(uptime -p)
    echo -e "Uptime: ${YELLOW}$uptime_info${NC}"
    
    # Bandwidth usage
    echo -e "Bandwidth Monitoring: ${GREEN}Active${NC}"
    
    echo -e "══════════════════════════════════════════"
}

# SSL setup with domain verification
setup_ssl_certificate() {
    if [ "$DOMAIN" = "your-domain.com" ] || [ -z "$DOMAIN" ]; then
        read -p "Enter your domain name: " domain
        read -p "Enter your email for SSL certificates: " email
        sed -i "s/^DOMAIN=.*/DOMAIN=$domain/" "$CONFIG_FILE"
        sed -i "s/^EMAIL=.*/EMAIL=$email/" "$CONFIG_FILE"
        load_config
    fi
    
    # Verify DNS
    local ip=$(curl -s ifconfig.me)
    local dns_ip=$(dig +short "$DOMAIN")
    
    if [ "$dns_ip" != "$ip" ]; then
        echo -e "${YELLOW}Warning: DNS may not be properly configured!${NC}"
        echo -e "Domain $DOMAIN points to: $dns_ip"
        echo -e "Your server IP is: $ip"
        read -p "Continue anyway? (y/N): " continue_anyway
        if [ "$continue_anyway" != "y" ] && [ "$continue_anyway" != "Y" ]; then
            return 1
        fi
    fi
    
    # Install Certbot and get SSL certificate
    apt install -y certbot
    certbot certonly --standalone --noninteractive --agree-tos \
        --email "$EMAIL" -d "$DOMAIN" \
        --pre-hook "systemctl stop nginx" \
        --post-hook "systemctl start nginx"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}SSL certificate obtained successfully!${NC}"
        show_switch_banner "SSL/TLS" "443" "Secure"
        return 0
    else
        echo -e "${RED}Failed to obtain SSL certificate!${NC}"
        return 1
    fi
}

# Uninstall function
uninstall_manager() {
    echo -e "${RED}Uninstalling Maxie VPS Manager...${NC}"
    read -p "Are you sure you want to uninstall? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        return
    fi
    
    # Stop all services
    echo -e "${YELLOW}Stopping services...${NC}"
    systemctl stop dropbear v2ray stunnel4 sslh nginx
    
    # Remove iptables rules
    echo -e "${YELLOW}Cleaning up iptables...${NC}"
    iptables -t mangle -F MAXIE_INPUT 2>/dev/null
    iptables -t mangle -F MAXIE_OUTPUT 2>/dev/null
    iptables -t mangle -D PREROUTING -j MAXIE_INPUT 2>/dev/null
    iptables -t mangle -D OUTPUT -j MAXIE_OUTPUT 2>/dev/null
    iptables -t mangle -X MAXIE_INPUT 2>/dev/null
    iptables -t mangle -X MAXIE_OUTPUT 2>/dev/null
    
    # Remove cron jobs
    echo -e "${YELLOW}Removing cron jobs...${NC}"
    crontab -l | grep -v '/usr/local/bin/maxie' | crontab -
    
    # Remove files
    echo -e "${YELLOW}Removing files...${NC}"
    rm -rf /etc/maxie
    rm -f /usr/local/bin/maxie
    
    echo -e "${GREEN}Maxie VPS Manager has been completely uninstalled.${NC}"
}

# Main menu
main_menu() {
    load_config
    
    while true; do
        clear
        show_banner
        echo -e "${CYAN}╔══════════════════════════════════════════╗"
        echo -e "║${GREEN}               MAIN MENU                  ${CYAN}║"
        echo -e "╠══════════════════════════════════════════╣"
        echo -e "║${YELLOW} 1. Install All Services                 ${CYAN}║"
        echo -e "║${YELLOW} 2. User Management                     ${CYAN}║"
        echo -e "║${YELLOW} 3. Bandwidth Monitoring                ${CYAN}║"
        echo -e "║${YELLOW} 4. System Statistics                   ${CYAN}║"
        echo -e "║${YELLOW} 5. Service Status                      ${CYAN}║"
        echo -e "║${YELLOW} 6. Setup SSL Certificate               ${CYAN}║"
        echo -e "║${YELLOW} 7. Uninstall Manager                   ${CYAN}║"
        echo -e "║${YELLOW} 8. Exit                                ${CYAN}║"
        echo -e "╚══════════════════════════════════════════╝${NC}"
        
        read -p "Choose an option: " choice
        
        case $choice in
            1) install_all_services ;;
            2) user_management_menu ;;
            3) bandwidth_monitoring_menu ;;
            4) system_stats ;;
            5) monitor_services ;;
            6) setup_ssl_certificate ;;
            7) uninstall_manager ;;
            8) exit 0 ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# Initialize
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo -i${NC}"
    exit 1
fi

# Handle command line arguments
case "${1:-}" in
    "update-bandwidth") update_bandwidth_stats ;;
    "check-expiry") check_user_expiry ;;
    "setup-ssl") setup_ssl_certificate ;;
    "uninstall") uninstall_manager ;;
    "status") monitor_services ;;
    "stats") system_stats ;;
    *) main_menu ;;
esac