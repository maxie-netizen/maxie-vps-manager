#!/bin/bash

# SSH WebSocket Configuration Script

setup_websocket() {
    echo -e "${CYAN}Setting up SSH WebSocket...${NC}"
    
    # Check port conflict
    check_port_conflict "$WS_PORT" "WebSocket" || return 1
    
    # Install required packages
    apt install -y nginx
    
    # Create WebSocket configuration
    cat > /etc/nginx/sites-available/websocket << EOF
server {
    listen $WS_PORT;
    server_name $DOMAIN;
    
    location / {
        proxy_pass http://127.0.0.1:$SSH_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
}
EOF
    
    # Enable configuration
    ln -sf /etc/nginx/sites-available/websocket /etc/nginx/sites-enabled/
    
    # Test and reload nginx
    nginx -t
    if [ $? -eq 0 ]; then
        systemctl reload nginx
        echo -e "${GREEN}SSH WebSocket configured successfully!${NC}"
        show_switch_banner "SSH WebSocket" "$WS_PORT" "Active"
        return 0
    else
        handle_error "Nginx configuration test failed" "WebSocket"
        return 1
    fi
}