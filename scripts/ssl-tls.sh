#!/bin/bash

# SSL/TLS Configuration Script

setup_ssl_tls() {
    echo -e "${CYAN}Setting up SSL/TLS...${NC}"
    
    # Check if domain is configured
    if [ "$DOMAIN" = "your-domain.com" ] || [ -z "$DOMAIN" ]; then
        echo -e "${YELLOW}No domain configured. Please set up your domain first.${NC}"
        read -p "Enter your domain name: " domain
        read -p "Enter your email for SSL certificates: " email
        sed -i "s/^DOMAIN=.*/DOMAIN=$domain/" "$CONFIG_FILE"
        sed -i "s/^EMAIL=.*/EMAIL=$email/" "$CONFIG_FILE"
        load_config
    fi
    
    # Verify DNS
    echo -e "${CYAN}Verifying DNS configuration...${NC}"
    local ip=$(curl -s ifconfig.me)
    local dns_ip=$(dig +short "$DOMAIN" | head -n1)
    
    if [ "$dns_ip" != "$ip" ]; then
        echo -e "${YELLOW}Warning: DNS may not be properly configured!${NC}"
        echo -e "Domain $DOMAIN points to: $dns_ip"
        echo -e "Your server IP is: $ip"
        echo -e "${YELLOW}For SSL certificates to work, your domain must point to your server IP.${NC}"
        read -p "Continue anyway? (y/N): " continue_anyway
        if [ "$continue_anyway" != "y" ] && [ "$continue_anyway" != "Y" ]; then
            return 1
        fi
    fi
    
    # Install Certbot if not installed
    if ! command -v certbot &> /dev/null; then
        echo -e "${CYAN}Installing Certbot...${NC}"
        apt update
        apt install -y certbot
    fi
    
    # Check if nginx is installed for pre-hook
    local pre_hook=""
    local post_hook=""
    
    if systemctl is-active --quiet nginx 2>/dev/null || dpkg -l | grep -q nginx; then
        pre_hook="--pre-hook \"systemctl stop nginx\""
        post_hook="--post-hook \"systemctl start nginx\""
    fi
    
    # Obtain SSL certificate
    echo -e "${CYAN}Obtaining SSL certificate for $DOMAIN...${NC}"
    
    # Try standalone method first
    if eval "certbot certonly --standalone --noninteractive --agree-tos \
        --email \"$EMAIL\" -d \"$DOMAIN\" \
        $pre_hook $post_hook"; then
        echo -e "${GREEN}SSL certificate obtained successfully!${NC}"
        show_switch_banner "SSL/TLS" "443" "Secure"
        return 0
    else
        echo -e "${YELLOW}Standalone method failed. Trying alternative methods...${NC}"
        
        # Try webroot method as fallback
        if [ -d "/var/www/html" ]; then
            echo -e "${CYAN}Trying webroot method...${NC}"
            if certbot certonly --webroot --noninteractive --agree-tos \
                --email "$EMAIL" -d "$DOMAIN" \
                -w /var/www/html; then
                echo -e "${GREEN}SSL certificate obtained successfully using webroot method!${NC}"
                show_switch_banner "SSL/TLS" "443" "Secure"
                return 0
            fi
        fi
        
        # Try manual method as last resort
        echo -e "${YELLOW}Automatic methods failed. Trying manual mode...${NC}"
        echo -e "${CYAN}You need to add a DNS TXT record to verify domain ownership.${NC}"
        echo -e "Press any key to continue with manual verification..."
        read -n 1 -s
        
        if certbot certonly --manual --preferred-challenges dns \
            --noninteractive --agree-tos \
            --email "$EMAIL" -d "$DOMAIN"; then
            echo -e "${GREEN}SSL certificate obtained successfully using manual method!${NC}"
            show_switch_banner "SSL/TLS" "443" "Secure"
            return 0
        else
            handle_error "All SSL certificate methods failed" "SSL/TLS"
            echo -e "${YELLOW}You can try setting up SSL manually later from the menu.${NC}"
            return 1
        fi
    fi
}

# Alternative SSL setup without nginx dependency
setup_ssl_alternative() {
    echo -e "${CYAN}Setting up SSL using alternative method...${NC}"
    
    # Create webroot directory if it doesn't exist
    mkdir -p /var/www/html
    
    # Install nginx temporarily for webroot method
    if ! command -v nginx &> /dev/null; then
        echo -e "${CYAN}Installing nginx for webroot method...${NC}"
        apt install -y nginx
        systemctl stop nginx
    fi
    
    # Use webroot method
    if certbot certonly --webroot --noninteractive --agree-tos \
        --email "$EMAIL" -d "$DOMAIN" \
        -w /var/www/html; then
        echo -e "${GREEN}SSL certificate obtained successfully!${NC}"
        
        # Remove nginx if it was installed just for this
        if ! systemctl is-enabled --quiet nginx 2>/dev/null; then
            apt remove -y nginx
            rm -rf /etc/nginx
        fi
        
        show_switch_banner "SSL/TLS" "443" "Secure"
        return 0
    else
        handle_error "Failed to obtain SSL certificate" "SSL/TLS"
        return 1
    fi
}

# Check SSL certificate status
check_ssl_status() {
    if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        echo -e "${GREEN}SSL certificate is valid and installed${NC}"
        
        # Check expiration date
        local exp_date=$(openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" -noout -enddate | cut -d= -f2)
        echo -e "Expiration date: ${YELLOW}$exp_date${NC}"
        
        # Check days until expiration
        local current_epoch=$(date +%s)
        local exp_epoch=$(date -d "$exp_date" +%s)
        local days_left=$(( (exp_epoch - current_epoch) / 86400 ))
        
        if [ "$days_left" -lt 7 ]; then
            echo -e "${RED}Warning: SSL certificate expires in $days_left days!${NC}"
        else
            echo -e "Days until expiration: ${GREEN}$days_left${NC}"
        fi
        
        return 0
    else
        echo -e "${RED}No SSL certificate found for $DOMAIN${NC}"
        return 1
    fi
}

# Renew SSL certificates
renew_ssl() {
    echo -e "${CYAN}Renewing SSL certificates...${NC}"
    
    if certbot renew --quiet; then
        echo -e "${GREEN}SSL certificates renewed successfully!${NC}"
        return 0
    else
        handle_error "Failed to renew SSL certificates" "SSL Renewal"
        return 1
    fi
}

# Setup auto-renewal cron job
setup_ssl_auto_renewal() {
    echo -e "${CYAN}Setting up SSL auto-renewal...${NC}"
    
    # Remove existing cron jobs for certbot
    crontab -l | grep -v 'certbot renew' | crontab -
    
    # Add new cron job (run daily at 3 AM)
    (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook \"systemctl reload nginx 2>/dev/null || true\"") | crontab -
    
    echo -e "${GREEN}SSL auto-renewal configured!${NC}"
    echo -e "Certificates will be renewed automatically daily at 3 AM"
}
