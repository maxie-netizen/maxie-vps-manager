# 🚀 Maxie VPS Manager - Complete SSH & Protocol Management Solution

A comprehensive, all-in-one management script for Ubuntu VPS servers that provides complete control over SSH users, tunneling protocols, SSL certificates, and system utilities through an intuitive menu-driven interface.

## ✨ Features

### 👤 Complete SSH User Management
- **User Creation** - Create users with custom expiration dates and access controls
- **User Deletion** - Delete users with complete home directory cleanup
- **Account Control** - Lock/unlock accounts for temporary access control
- **User Monitoring** - User listing with expiry status and account state
- **Account Renewal** - Account renewal for extending user access
- **Auto Cleanup** - Automatic cleanup of expired accounts

### 🌐 Protocol & Tunneling Support
- **BadVPN (UDP 7300)** - UDP tunneling for gaming and multimedia
- **UDP-Custom (Port 5300)** - Custom UDP proxy with exclusion support
- **SSL Tunnel (Port 444)** - SSL-encrypted SSH tunneling
- **WebSocket Proxy (Port 8080)** - WebSocket-based SSH proxy
- **SOCKS Proxy (Port 200)** - SOCKS5 proxy server
- **DNSTT (Port 53)** - DNS tunneling for bypassing restrictions
- **SSLH (Ports 80 & 443)** - SSL/SSH multiplexer
- **Nginx Proxy** - Reverse proxy with WebSocket support

### 📊 Panel Management
- **X-UI Panel** - Web-based management interface for multiple protocols
- Easy installation and removal process
- Default credentials: admin/admin (with password change reminder)

### 🔐 SSL Certificate Management
- **Let's Encrypt Integration** - Free SSL certificates with automatic renewal
- **Multi-domain Support** - Wildcard certificate capability
- **Web Server Integration** - Automatic nginx configuration

### 🛠 System Utilities
- **Backup System** - Complete user data backup and restore functionality
- **Status Monitoring** - Real-time protocol status checking
- **Firewall Management** - Automatic UFW configuration

## 🖥 System Requirements

- **OS**: Ubuntu 20.04/22.04/24.04 (other Debian-based distros may work)
- **Architecture**: AMD64/x86_64, ARM64 (experimental)
- **RAM**: Minimum 512MB (1GB recommended)
- **Storage**: 10GB minimum
- **Root Access**: Required for installation and management

## 📋 Installation

### One-Command Installation (Recommended)
```bash
curl -sSL https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/install.sh | bash
```

### Manual Installation
```bash
# Download the manager
wget https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/maxie-tunneling-setup.sh

# Make it executable
chmod +x maxie-tunneling-setup.sh

# Run the manager
./maxie-tunneling-setup.sh
```

## 🎯 Usage

### Starting the Manager
```bash
# After installation, simply run:
maxie-vps-manager
```

### Main Menu Options
1. **Install All Tunneling Protocols** - Complete setup of all services
2. **Check Service Status** - View active services and ports
3. **Manage Individual Services** - Start/stop/restart specific services
4. **Configure SSL Certificates** - SSL certificate setup
5. **View Connection Information** - Display connection details
6. **Update System** - System package updates
7. **Exit** - Close the application

## 🔧 Technical Details

### Directory Structure
```
/etc/maxie-vps-manager/     # Configuration files
/usr/local/bin/             # Main script location
/var/log/maxie-vps-manager.log  # Log file
/backup/users/              # User backup storage
/opt/maxie-vps-manager/     # Installation directory
```

### Service Management
All protocols run as systemd services for:
- Automatic startup on boot
- Process monitoring and restarting
- Logging through journalctl

### Security Features
- Non-root user operation where possible
- Firewall (UFW) integration for port management
- Secure certificate handling
- User isolation with home directory permissions

## 📁 File Structure

```
maxie-vps-manager/
├── install.sh                 # Main installation script
├── maxie-tunneling-setup.sh  # Complete tunneling protocol setup
├── user-management.sh        # SSH user management functions
├── system-utils.sh           # System utilities and monitoring
├── config.conf               # Configuration file
├── README.md                 # This file
└── LICENSE                   # MIT License
```

## 🚀 Quick Start

1. **Install the Manager**
   ```bash
   curl -sSL https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/install.sh | bash
   ```

2. **Run the Manager**
   ```bash
   maxie-vps-manager
   ```

3. **Install Protocols**
   - Choose option 1 from the main menu
   - Follow the prompts to configure your domain and email
   - Wait for all services to install and start

4. **Access X-UI Panel**
   - Open http://your-server-ip:54321 in your browser
   - Login with admin/admin
   - **IMPORTANT**: Change the default password immediately!

5. **Configure Clients**
   - Use the connection information displayed after installation
   - Configure your tunneling clients with the provided ports and protocols

## 🔍 Monitoring & Management

### Check Service Status
```bash
check-tunneling-status
```

### View Logs
```bash
# General logs
tail -f /var/log/maxie-vps-manager.log

# Service-specific logs
journalctl -u badvpn -f
journalctl -u udp-custom -f
journalctl -u stunnel4 -f
```

### Backup & Restore
```bash
# Create backup
maxie-vps-manager
# Choose option 6 (System Utilities) then option 1 (Create System Backup)

# Restore from backup
maxie-vps-manager
# Choose option 6 (System Utilities) then option 2 (Restore System Backup)
```

## 🐛 Troubleshooting

### Common Issues

**Port conflicts**: The script will detect used ports and warn you
**Installation failures**: Check internet connection and DNS settings
**Certificate errors**: Ensure your domain points to the server IP

### Debug Mode
Enable debug logging by editing `/etc/maxie-vps-manager/config`:
```bash
LOG_LEVEL=DEBUG
```

### Getting Help
1. Check the logs: `/var/log/maxie-vps-manager.log`
2. Verify service status: `systemctl status [service-name]`
3. Check firewall: `ufw status`
4. Verify ports: `netstat -tlnp`

## 🔄 Updates and Maintenance

### Automatic Updates
The manager can check for updates from the main menu:
- System Utilities → Check for Updates

### Manual Update
```bash
# Re-run the installation script
bash <(curl -sSL https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/install.sh)
```

### Backup and Migration
- Regular backups are recommended before major changes
- Backup files can be transferred to new servers
- Restore process maintains user permissions and configurations

## 📝 Customization

### Configuration File
Edit `/etc/maxie-vps-manager/config` to customize:
- Default ports for protocols
- Backup retention policies
- Logging levels
- User management settings

### Adding New Protocols
Advanced users can extend functionality by:
- Adding new protocol functions to the script
- Creating appropriate systemd service files
- Implementing status checking logic

## 🌟 Benefits

- **Time Saving**: Manage all VPS services through one interface
- **User Friendly**: Intuitive menu system without complex commands
- **Comprehensive**: Everything from user management to SSL certificates
- **Secure**: Built-in security practices and automatic hardening
- **Open Source**: Free to use, modify, and distribute

## 📞 Support

- **Documentation**: GitHub Wiki
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

## 📜 License

**MIT License** - Feel free to use and modify for personal and commercial projects.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Disclaimer

This software is provided "as is" without warranty. Use at your own risk. The authors are not responsible for any damage or data loss that may occur from using this software.

## 🔗 Links

- **GitHub Repository**: [maxie-netizen/maxie-vps-manager](https://github.com/maxie-netizen/maxie-vps-manager)
- **Issues**: [GitHub Issues](https://github.com/maxie-netizen/maxie-vps-manager/issues)
- **Wiki**: [GitHub Wiki](https://github.com/maxie-netizen/maxie-vps-manager/wiki)

---

**Built with ❤️ for the VPS community**

*Maxie VPS Manager - Making VPS management simple and efficient*
