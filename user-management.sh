#!/bin/bash

# Maxie VPS Manager - User Management Script
# Handles SSH user creation, deletion, and management

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
BACKUP_DIR="/backup/users"
LOG_FILE="/var/log/maxie-vps-manager.log"

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

# Function to create user
create_user() {
    local username="$1"
    local password="$2"
    local expiry_days="$3"
    
    if [[ -z "$username" || -z "$password" ]]; then
        print_error "Username and password are required"
        return 1
    fi
    
    # Check if user exists
    if id "$username" &>/dev/null; then
        print_error "User $username already exists"
        return 1
    fi
    
    # Create user
    useradd -m -s /bin/bash "$username"
    if [[ $? -eq 0 ]]; then
        # Set password
        echo "$username:$password" | chpasswd
        
        # Set expiry date
        if [[ -n "$expiry_days" ]]; then
            local expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
            chage -E "$expiry_date" "$username"
            print_status "User $username created with expiry date: $expiry_date"
        else
            print_status "User $username created without expiry"
        fi
        
        # Create SSH directory
        mkdir -p "/home/$username/.ssh"
        chown "$username:$username" "/home/$username/.ssh"
        chmod 700 "/home/$username/.ssh"
        
        # Backup user info
        echo "Username: $username" > "$BACKUP_DIR/$username.info"
        echo "Created: $(date)" >> "$BACKUP_DIR/$username.info"
        echo "Expiry: ${expiry_date:-"Never"}" >> "$BACKUP_DIR/$username.info"
        
        return 0
    else
        print_error "Failed to create user $username"
        return 1
    fi
}

# Function to delete user
delete_user() {
    local username="$1"
    
    if [[ -z "$username" ]]; then
        print_error "Username is required"
        return 1
    fi
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        print_error "User $username does not exist"
        return 1
    fi
    
    # Backup user data
    if [[ -d "/home/$username" ]]; then
        tar -czf "$BACKUP_DIR/$username-$(date +%Y%m%d-%H%M%S).tar.gz" -C /home "$username" 2>/dev/null
        print_status "User data backed up to $BACKUP_DIR"
    fi
    
    # Kill user processes
    pkill -u "$username" 2>/dev/null
    
    # Remove user and home directory
    userdel -r "$username"
    if [[ $? -eq 0 ]]; then
        print_status "User $username deleted successfully"
        return 0
    else
        print_error "Failed to delete user $username"
        return 1
    fi
}

# Function to lock/unlock user
toggle_user_lock() {
    local username="$1"
    local action="$2"
    
    if [[ -z "$username" || -z "$action" ]]; then
        print_error "Username and action (lock/unlock) are required"
        return 1
    fi
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        print_error "User $username does not exist"
        return 1
    fi
    
    case "$action" in
        "lock")
            usermod -L "$username"
            print_status "User $username locked"
            ;;
        "unlock")
            usermod -U "$username"
            print_status "User $username unlocked"
            ;;
        *)
            print_error "Invalid action. Use 'lock' or 'unlock'"
            return 1
            ;;
    esac
    
    return 0
}

# Function to list users
list_users() {
    echo -e "${BLUE}=== User List ===${NC}"
    echo
    
    # Get all users with home directories
    local users=$(awk -F: '$3 >= 1000 && $3 != 65534 && $6 != "/nonexistent" {print $1}' /etc/passwd)
    
    if [[ -z "$users" ]]; then
        echo "No users found"
        return
    fi
    
    printf "%-15s %-10s %-15s %-20s\n" "Username" "Status" "Expiry" "Last Login"
    echo "------------------------------------------------------------"
    
    for user in $users; do
        local status="Active"
        local expiry="Never"
        local last_login="Never"
        
        # Check if account is locked
        if passwd -S "$user" | grep -q "L"; then
            status="Locked"
        fi
        
        # Get expiry date
        local expiry_info=$(chage -l "$user" | grep "Account expires")
        if [[ "$expiry_info" != *"never"* ]]; then
            expiry=$(echo "$expiry_info" | awk '{print $4}')
        fi
        
        # Get last login
        if [[ -f "/var/log/wtmp" ]]; then
            last_login=$(last "$user" -1 2>/dev/null | head -1 | awk '{print $4, $5, $6, $7}')
            if [[ "$last_login" == "" ]]; then
                last_login="Never"
            fi
        fi
        
        printf "%-15s %-10s %-15s %-20s\n" "$user" "$status" "$expiry" "$last_login"
    done
    
    echo
}

# Function to renew user account
renew_user() {
    local username="$1"
    local days="$2"
    
    if [[ -z "$username" || -z "$days" ]]; then
        print_error "Username and number of days are required"
        return 1
    fi
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        print_error "User $username does not exist"
        return 1
    fi
    
    # Set new expiry date
    local new_expiry=$(date -d "+$days days" +%Y-%m-%d)
    chage -E "$new_expiry" "$username"
    
    if [[ $? -eq 0 ]]; then
        print_status "User $username renewed until $new_expiry"
        
        # Update backup info
        if [[ -f "$BACKUP_DIR/$username.info" ]]; then
            sed -i "s/Expiry:.*/Expiry: $new_expiry/" "$BACKUP_DIR/$username.info"
        fi
        
        return 0
    else
        print_error "Failed to renew user $username"
        return 1
    fi
}

# Function to backup user
backup_user() {
    local username="$1"
    
    if [[ -z "$username" ]]; then
        print_error "Username is required"
        return 1
    fi
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        print_error "User $username does not exist"
        return 1
    fi
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    # Backup user data
    local backup_file="$BACKUP_DIR/$username-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$backup_file" -C /home "$username" 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        print_status "User $username backed up to $backup_file"
        return 0
    else
        print_error "Failed to backup user $username"
        return 1
    fi
}

# Function to restore user
restore_user() {
    local backup_file="$1"
    
    if [[ -z "$backup_file" ]]; then
        print_error "Backup file is required"
        return 1
    fi
    
    if [[ ! -f "$backup_file" ]]; then
        print_error "Backup file $backup_file not found"
        return 1
    fi
    
    # Extract username from backup file
    local username=$(tar -tzf "$backup_file" | head -1 | cut -d'/' -f1)
    
    if [[ -z "$username" ]]; then
        print_error "Could not determine username from backup file"
        return 1
    fi
    
    # Check if user already exists
    if id "$username" &>/dev/null; then
        print_error "User $username already exists. Please delete first or use different username."
        return 1
    fi
    
    # Create user
    useradd -m -s /bin/bash "$username"
    
    # Restore data
    tar -xzf "$backup_file" -C /home
    chown -R "$username:$username" "/home/$username"
    
    print_status "User $username restored from backup"
    return 0
}

# Function to cleanup expired users
cleanup_expired_users() {
    print_status "Cleaning up expired users..."
    
    local current_date=$(date +%s)
    local users=$(awk -F: '$3 >= 1000 && $3 != 65534 && $6 != "/nonexistent" {print $1}' /etc/passwd)
    local cleaned_count=0
    
    for user in $users; do
        local expiry_info=$(chage -l "$user" | grep "Account expires")
        
        if [[ "$expiry_info" != *"never"* ]]; then
            local expiry_date=$(echo "$expiry_info" | awk '{print $4}')
            local expiry_timestamp=$(date -d "$expiry_date" +%s 2>/dev/null)
            
            if [[ -n "$expiry_timestamp" && $expiry_timestamp -lt $current_date ]]; then
                print_warning "User $user has expired. Removing..."
                delete_user "$user"
                if [[ $? -eq 0 ]]; then
                    ((cleaned_count++))
                fi
            fi
        fi
    done
    
    print_status "Cleanup completed. Removed $cleaned_count expired users."
}

# Function to show user management menu
show_menu() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    USER MANAGEMENT MENU${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
    echo "1. Create User"
    echo "2. Delete User"
    echo "3. Lock/Unlock User"
    echo "4. List Users"
    echo "5. Renew User Account"
    echo "6. Backup User"
    echo "7. Restore User"
    echo "8. Cleanup Expired Users"
    echo "9. Exit"
    echo
}

# Main menu loop
main() {
    while true; do
        show_menu
        read -p "Choose option: " choice
        
        case $choice in
            1)
                read -p "Enter username: " username
                read -s -p "Enter password: " password
                echo
                read -p "Enter expiry days (or press Enter for no expiry): " expiry_days
                create_user "$username" "$password" "$expiry_days"
                ;;
            2)
                read -p "Enter username to delete: " username
                read -p "Are you sure? (y/N): " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    delete_user "$username"
                fi
                ;;
            3)
                read -p "Enter username: " username
                read -p "Action (lock/unlock): " action
                toggle_user_lock "$username" "$action"
                ;;
            4)
                list_users
                ;;
            5)
                read -p "Enter username: " username
                read -p "Enter days to extend: " days
                renew_user "$username" "$days"
                ;;
            6)
                read -p "Enter username to backup: " username
                backup_user "$username"
                ;;
            7)
                read -p "Enter backup file path: " backup_file
                restore_user "$backup_file"
                ;;
            8)
                cleanup_expired_users
                ;;
            9)
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
