#!/bin/bash

# Maxie VPS Manager - System Utilities Script
# Handles backup, restore, monitoring, and maintenance functions

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
BACKUP_DIR="/backup"
LOG_FILE="/var/log/maxie-vps-manager.log"
RETENTION_DAYS=30

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

# Function to create system backup
create_system_backup() {
    local backup_name="system-backup-$(date +%Y%m%d-%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    print_status "Creating system backup: $backup_name"
    
    # Create backup directory
    mkdir -p "$backup_path"
    
    # Backup important system files
    print_status "Backing up system configuration..."
    
    # Backup user data
    if [[ -d "/home" ]]; then
        tar -czf "$backup_path/users.tar.gz" -C /home . 2>/dev/null
        print_status "User data backed up"
    fi
    
    # Backup configuration files
    tar -czf "$backup_path/config.tar.gz" \
        /etc/ssh \
        /etc/nginx \
        /etc/stunnel \
        /etc/3proxy \
        /etc/maxie-vps-manager \
        2>/dev/null
    print_status "Configuration files backed up"
    
    # Backup service files
    tar -czf "$backup_path/services.tar.gz" \
        /etc/systemd/system/badvpn.service \
        /etc/systemd/system/udp-custom.service \
        /etc/systemd/system/websocket-proxy.service \
        /etc/systemd/system/dnstt.service \
        2>/dev/null
    print_status "Service files backed up"
    
    # Create backup manifest
    cat > "$backup_path/manifest.txt" << EOF
Maxie VPS Manager System Backup
Created: $(date)
Backup Name: $backup_name
Contents:
- User data
- Configuration files
- Service files
- System information

System Info:
$(uname -a)
$(cat /etc/os-release 2>/dev/null)
EOF
    
    # Compress entire backup
    cd "$BACKUP_DIR"
    tar -czf "$backup_name.tar.gz" "$backup_name"
    rm -rf "$backup_name"
    
    print_status "System backup completed: $BACKUP_DIR/$backup_name.tar.gz"
    return 0
}

# Function to restore system from backup
restore_system_backup() {
    local backup_file="$1"
    
    if [[ -z "$backup_file" ]]; then
        print_error "Backup file is required"
        return 1
    fi
    
    if [[ ! -f "$backup_file" ]]; then
        print_error "Backup file $backup_file not found"
        return 1
    fi
    
    print_status "Restoring system from backup: $backup_file"
    
    # Create temporary restore directory
    local restore_dir="/tmp/maxie-restore-$$"
    mkdir -p "$restore_dir"
    
    # Extract backup
    tar -xzf "$backup_file" -C "$restore_dir"
    
    # Find the extracted directory
    local extracted_dir=$(ls "$restore_dir" | head -1)
    if [[ -z "$extracted_dir" ]]; then
        print_error "Invalid backup file format"
        rm -rf "$restore_dir"
        return 1
    fi
    
    local backup_path="$restore_dir/$extracted_dir"
    
    # Check if manifest exists
    if [[ ! -f "$backup_path/manifest.txt" ]]; then
        print_error "Backup manifest not found. Invalid backup file."
        rm -rf "$restore_dir"
        return 1
    fi
    
    print_status "Backup manifest found. Starting restore..."
    
    # Restore user data
    if [[ -f "$backup_path/users.tar.gz" ]]; then
        print_status "Restoring user data..."
        tar -xzf "$backup_path/users.tar.gz" -C /home
        chown -R root:root /home
        print_status "User data restored"
    fi
    
    # Restore configuration files
    if [[ -f "$backup_path/config.tar.gz" ]]; then
        print_status "Restoring configuration files..."
        tar -xzf "$backup_path/config.tar.gz" -C /
        print_status "Configuration files restored"
    fi
    
    # Restore service files
    if [[ -f "$backup_path/services.tar.gz" ]]; then
        print_status "Restoring service files..."
        tar -xzf "$backup_path/services.tar.gz" -C /
        systemctl daemon-reload
        print_status "Service files restored"
    fi
    
    # Cleanup
    rm -rf "$restore_dir"
    
    print_status "System restore completed successfully"
    print_warning "You may need to restart services: systemctl restart [service-name]"
    return 0
}

# Function to check system status
check_system_status() {
    echo -e "${BLUE}=== System Status ===${NC}"
    echo
    
    # System information
    echo -e "${GREEN}System Information:${NC}"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "Uptime: $(uptime -p)"
    echo
    
    # Resource usage
    echo -e "${GREEN}Resource Usage:${NC}"
    echo "CPU Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "Memory: $(free -h | awk 'NR==2{printf "%.1f%%", $3*100/$2}') used"
    echo "Disk: $(df -h / | awk 'NR==2{printf "%.1f%%", $5}') used"
    echo
    
    # Service status
    echo -e "${GREEN}Service Status:${NC}"
    local services=("badvpn" "udp-custom" "stunnel4" "websocket-proxy" "3proxy" "dnstt" "sslh" "nginx" "x-ui")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "✅ $service: ${GREEN}RUNNING${NC}"
        else
            echo -e "❌ $service: ${RED}STOPPED${NC}"
        fi
    done
    
    echo
    
    # Port status
    echo -e "${GREEN}Port Status:${NC}"
    local ports=(7300 5300 444 8080 200 53 80 443)
    for port in "${ports[@]}"; do
        if netstat -tlnp | grep -q ":$port "; then
            echo -e "✅ Port $port: ${GREEN}LISTENING${NC}"
        else
            echo -e "❌ Port $port: ${RED}NOT LISTENING${NC}"
        fi
    done
    
    echo
    
    # Firewall status
    echo -e "${GREEN}Firewall Status:${NC}"
    if command -v ufw &> /dev/null; then
        ufw status | head -5
    else
        echo "UFW not installed"
    fi
    
    echo
}

# Function to monitor system resources
monitor_resources() {
    echo -e "${BLUE}=== Resource Monitoring ===${NC}"
    echo "Press Ctrl+C to stop monitoring"
    echo
    
    while true; do
        clear
        echo -e "${BLUE}=== Resource Monitoring ===${NC}"
        echo "Updated: $(date)"
        echo
        
        # CPU and Memory
        echo -e "${GREEN}CPU & Memory:${NC}"
        echo "CPU Load: $(uptime | awk -F'load average:' '{print $2}')"
        echo "Memory: $(free -h | awk 'NR==2{printf "%s/%s (%.1f%%)", $3, $2, $3*100/$2}')"
        echo
        
        # Disk usage
        echo -e "${GREEN}Disk Usage:${NC}"
        df -h / | awk 'NR==2{printf "Root: %s/%s (%s)\n", $3, $2, $5}'
        if [[ -d "/home" ]]; then
            df -h /home | awk 'NR==2{printf "Home: %s/%s (%s)\n", $3, $2, $5}'
        fi
        echo
        
        # Network connections
        echo -e "${GREEN}Network Connections:${NC}"
        echo "Active connections: $(netstat -an | grep ESTABLISHED | wc -l)"
        echo "Listening ports: $(netstat -tlnp | wc -l)"
        echo
        
        # Top processes
        echo -e "${GREEN}Top Processes (by CPU):${NC}"
        ps aux --sort=-%cpu | head -6 | awk '{printf "%-20s %-8s %-8s %s\n", $11, $2, $3, $9}'
        
        sleep 2
    done
}

# Function to cleanup old backups
cleanup_old_backups() {
    print_status "Cleaning up old backups (older than $RETENTION_DAYS days)..."
    
    local current_time=$(date +%s)
    local cutoff_time=$((current_time - RETENTION_DAYS * 24 * 60 * 60))
    local cleaned_count=0
    
    if [[ -d "$BACKUP_DIR" ]]; then
        for backup_file in "$BACKUP_DIR"/*.tar.gz; do
            if [[ -f "$backup_file" ]]; then
                local file_time=$(stat -c %Y "$backup_file")
                if [[ $file_time -lt $cutoff_time ]]; then
                    print_warning "Removing old backup: $(basename "$backup_file")"
                    rm -f "$backup_file"
                    ((cleaned_count++))
                fi
            fi
        done
    fi
    
    print_status "Cleanup completed. Removed $cleaned_count old backups."
}

# Function to update system
update_system() {
    print_status "Updating system packages..."
    
    # Update package list
    apt update
    
    if [[ $? -eq 0 ]]; then
        # Check for available updates
        local updates=$(apt list --upgradable 2>/dev/null | grep -v "WARNING" | wc -l)
        
        if [[ $updates -gt 0 ]]; then
            print_status "Found $updates available updates. Installing..."
            apt upgrade -y
            
            if [[ $? -eq 0 ]]; then
                print_status "System update completed successfully"
            else
                print_error "System update failed"
                return 1
            fi
        else
            print_status "System is already up to date"
        fi
    else
        print_error "Failed to update package list"
        return 1
    fi
    
    return 0
}

# Function to check for script updates
check_for_updates() {
    print_status "Checking for Maxie VPS Manager updates..."
    
    # This would typically check against a remote repository
    # For now, we'll just show a message
    print_status "Update check completed"
    print_warning "Manual updates can be performed by re-running the installation script"
}

# Function to show system utilities menu
show_menu() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    SYSTEM UTILITIES MENU${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
    echo "1. Create System Backup"
    echo "2. Restore System Backup"
    echo "3. Check System Status"
    echo "4. Monitor Resources"
    echo "5. Cleanup Old Backups"
    echo "6. Update System"
    echo "7. Check for Updates"
    echo "8. Exit"
    echo
}

# Main menu loop
main() {
    while true; do
        show_menu
        read -p "Choose option: " choice
        
        case $choice in
            1)
                create_system_backup
                ;;
            2)
                read -p "Enter backup file path: " backup_file
                restore_system_backup "$backup_file"
                ;;
            3)
                check_system_status
                ;;
            4)
                monitor_resources
                ;;
            5)
                cleanup_old_backups
                ;;
            6)
                update_system
                ;;
            7)
                check_for_updates
                ;;
            8)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
        
        echo "Press Enter to continue..."
        read
    done
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Run main function
main "$@"
