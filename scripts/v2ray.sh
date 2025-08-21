#!/bin/bash

# V2Ray Configuration Script

setup_v2ray() {
    echo -e "${CYAN}Setting up V2Ray...${NC}"
    
    # Check port conflict
    check_port_conflict "$VMESS_PORT" "V2Ray VMESS" || return 1
    check_port_conflict "$VLESS_PORT" "V2Ray VLESS" || return 1
    check_port_conflict "$TROJAN_PORT" "V2Ray Trojan" || return 1
    
    # Install V2Ray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    if [ $? -ne 0 ]; then
        handle_error "Failed to install V2Ray" "V2Ray"
        return 1
    fi
    
    # Generate UUIDs
    VMESS_UUID=$(cat /proc/sys/kernel/random/uuid)
    VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # Create V2Ray configuration from template
    if [ -f "$TEMPLATES_DIR/v2ray-config.json" ]; then
        cp "$TEMPLATES_DIR/v2ray-config.json" /usr/local/etc/xray/config.json
        
        # Replace placeholders
        sed -i \
            -e "s|\${VMESS_PORT}|$VMESS_PORT|g" \
            -e "s|\${VLESS_PORT}|$VLESS_PORT|g" \
            -e "s|\${TROJAN_PORT}|$TROJAN_PORT|g" \
            -e "s|\${VMESS_UUID}|$VMESS_UUID|g" \
            -e "s|\${VLESS_UUID}|$VLESS_UUID|g" \
            -e "s|\${TROJAN_PASSWORD}|$TROJAN_PASSWORD|g" \
            -e "s|\${XRAY_PATH}|$XRAY_PATH|g" \
            -e "s|\${DOMAIN}|$DOMAIN|g" \
            /usr/local/etc/xray/config.json
    else
        # Fallback configuration
        cat > /usr/local/etc/xray/config.json << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "port": $VMESS_PORT,
            "protocol": "vmess",
            "settings": {
                "clients": [{"id": "$VMESS_UUID", "alterId": 0}]
            },
            "streamSettings": {"network": "tcp"}
        },
        {
            "port": $VLESS_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "$VLESS_UUID", "flow": "xtls-rprx-direct"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": "$XRAY_PATH"},
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{
                        "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                        "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                    }]
                }
            }
        },
        {
            "port": $TROJAN_PORT,
            "protocol": "trojan",
            "settings": {
                "clients": [{"password": "$TROJAN_PASSWORD"}]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{
                        "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                        "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                    }]
                }
            }
        }
    ],
    "outbounds": [{"protocol": "freedom"}]
}
EOF
    fi
    
    # Start and enable V2Ray
    systemctl enable xray
    systemctl restart xray
    
    if systemctl is-active --quiet xray; then
        echo -e "${GREEN}V2Ray configured successfully!${NC}"
        show_switch_banner "V2Ray" "$VMESS_PORT/$VLESS_PORT/$TROJAN_PORT" "Active"
        
        # Save credentials
        sed -i "s/^TROJAN_PASSWORD=.*/TROJAN_PASSWORD=$TROJAN_PASSWORD/" "$CONFIG_FILE"
        echo "VMESS_UUID=$VMESS_UUID" >> "$CONFIG_FILE"
        echo "VLESS_UUID=$VLESS_UUID" >> "$CONFIG_FILE"
        
        return 0
    else
        handle_error "V2Ray service failed to start" "V2Ray"
        return 1
    fi
}