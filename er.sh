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

# Load configuration
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
    
    # Load component scripts
    for script in "$SCRIPTS_DIR"/*.sh; do
        if [ -f "$script" ]; then
            source "$script"
        fi
    done
    
    # Check and install each service based on config
    if [ "$SSH" = "1" ]; then
        setup_ssh
        read -p "Press Enter to continue..."
    fi
    
    if [ "$DROPBEAR" = "1" ]; then
        setup_dropbear
        read -p "Press Enter to continue..."
    fi
    
    if [ "$V2RAY" = "1" ]; then
        setup_v2ray
        read -p "Press Enter to continue..."
    fi
    
    if [ "$SSL_TLS" = "1" ]; then
        setup_ssl_tls
        read -p "Press Enter to continue..."
    fi
    
    if [ "$STUNNEL" = "1" ]; then
        setup_stunnel
        read -p "Press Enter to continue..."
    fi
    
    if [ "$WEBSOCKET" = "1" ]; then
        setup_websocket
        read -p "Press Enter to continue..."
    fi
    
    if [ "$BANDWIDTH_MONITORING" = "1" ]; then
        setup_bandwidth_monitoring
        read -p "Press Enter to continue..."
    fi
    
    echo -e "${GREEN}All services installed successfully!${NC}"
    read -p "Press Enter to return to main menu..."
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
    read -p "Press Enter to return to main menu..."
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
    read -p "Press Enter to return to main menu..."
}

# SSL setup with domain verification
setup_ssl_certificate() {
    # Load SSL script
    if [ -f "$SCRIPTS_DIR/ssl-tls.sh" ]; then
        source "$SCRIPTS_DIR/ssl-tls.sh"
        setup_ssl_tls
    else
        echo -e "${RED}SSL script not found!${NC}"
    fi
    read -p "Press Enter to return to main menu..."
}

# User management menu
user_management_menu() {
    echo -e "${CYAN}User Management${NC}"
    echo -e "══════════════════════════════════════════"
    echo -e "1. Create User"
    echo -e "2. Delete User"
    echo -e "3. List Users"
    echo -e "4. Back to Main Menu"
    echo -e "══════════════════════════════════════════"
    
    read -p "Choose an option: " choice
    
    case $choice in
        1)
            echo -e "${CYAN}Creating new user...${NC}"
            read -p "Enter username: " username
            read -s -p "Enter password: " password
            echo
            read -p "Enter bandwidth limit (e.g., 50MB, 10GB): " bandwidth_limit
            read -p "Enter expiry days (e.g., 7, 30): " expiry_days
            
            # Create user (simplified version)
            useradd -m -s /bin/false "$username"
            echo "$username:$password" | chpasswd
            expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
            echo "$username:0:0:$bandwidth_limit:$expiry_date" >> "$BANDWIDTH_DB"
            
            echo -e "${GREEN}User $username created successfully!${NC}"
            echo -e "Expiry date: $expiry_date | Bandwidth limit: $bandwidth_limit"
            ;;
        2)
            echo -e "${CYAN}Deleting user...${NC}"
            read -p "Enter username to delete: " username
            if id "$username" &>/dev/null; then
                userdel -r "$username" 2>/dev/null
                sed -i "/^$username:/d" "$BANDWIDTH_DB"
                echo -e "${GREEN}User $username deleted successfully!${NC}"
            else
                echo -e "${RED}User $username not found!${NC}"
            fi
            ;;
        3)
            echo -e "${CYAN}User List:${NC}"
            if [ -s "$BANDWIDTH_DB" ]; then
                echo -e "Username     Bandwidth Limit     Expiry Date"
                echo -e "══════════════════════════════════════════"
                while IFS=: read -r user _ _ limit expiry; do
                    echo -e "$user     $limit     $expiry"
                done < "$BANDWIDTH_DB"
            else
                echo -e "${YELLOW}No users found.${NC}"
            fi
            ;;
        4)
            return
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
    user_management_menu
}

# Bandwidth monitoring menu
bandwidth_monitoring_menu() {
    echo -e "${CYAN}Bandwidth Monitoring${NC}"
    echo -e "══════════════════════════════════════════"
    echo -e "1. View Bandwidth Usage"
    echo -e "2. Set Bandwidth Limits"
    echo -e "3. Reset Bandwidth Counters"
    echo -e "4. Back to Main Menu"
    echo -e "══════════════════════════════════════════"
    
    read -p "Choose an option: " choice
    
    case $choice in
        1)
            echo -e "${CYAN}Bandwidth Usage:${NC}"
            if [ -s "$BANDWIDTH_DB" ]; then
                echo -e "Username     Download     Upload     Limit"
                echo -e "══════════════════════════════════════════"
                while IFS=: read -r user download upload limit expiry; do
                    echo -e "$user     ${download}MB     ${upload}MB     $limit"
                done < "$BANDWIDTH_DB"
            else
                echo -e "${YELLOW}No bandwidth data available.${NC}"
            fi
            ;;
        2)
            echo -e "${CYAN}Set Bandwidth Limits${NC}"
            read -p "Enter username: " username
            if grep -q "^$username:" "$BANDWIDTH_DB"; then
                read -p "Enter new bandwidth limit (e.g., 50MB, 10GB): " new_limit
                sed -i "s/^$username:.*:.*:.*:.*/$username:0:0:$new_limit:$expiry/" "$BANDWIDTH_DB"
                echo -e "${GREEN}Bandwidth limit updated for $username!${NC}"
            else
                echo -e "${RED}User $username not found!${NC}"
            fi
            ;;
        3)
            echo -e "${CYAN}Resetting bandwidth counters...${NC}"
            while IFS=: read -r user _ _ limit expiry; do
                sed -i "s/^$user:.*:.*:.*:.*/$user:0:0:$limit:$expiry/" "$BANDWIDTH_DB"
            done < "$BANDWIDTH_DB"
            echo -e "${GREEN}Bandwidth counters reset!${NC}"
            ;;
        4)
            return
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
    bandwidth_monitoring_menu
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
    systemctl stop dropbear v2ray stunnel4 sslh nginx 2>/dev/null
    
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
    read -p "Press Enter to exit..."
    exit 0
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
            8) 
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *) 
                echo -e "${RED}Invalid option!${NC}"
                sleep 1
                ;;
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
    "update-bandwidth") 
        echo -e "${CYAN}Updating bandwidth statistics...${NC}"
        # Add bandwidth update logic here
        ;;
    "check-expiry") 
        echo -e "${CYAN}Checking user expiry...${NC}"
        # Add expiry check logic here
        ;;
    "setup-ssl") 
        setup_ssl_certificate
        ;;
    "uninstall") 
        uninstall_manager
        ;;
    "status") 
        monitor_services
        ;;
    "stats") 
        system_stats
        ;;
    *) 
        main_menu
        ;;
esac
