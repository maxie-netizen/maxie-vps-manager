# 🚀 One-Command Installation for Maxie VPS Manager

## Quick Install (Ubuntu 22.04+)

```bash
curl -sSL https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/install.sh | bash
```

## Alternative Installation Methods

### Method 1: Direct curl
```bash
curl -sSL https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/install.sh | bash
```

### Method 2: wget
```bash
wget -qO- https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/install.sh | bash
```

### Method 3: Download and run
```bash
wget https://raw.githubusercontent.com/maxie-netizen/maxie-vps-manager/main/install.sh
chmod +x install.sh
./install.sh
```

## After Installation

```bash
# Run the manager
maxie-vps-manager

# Choose option 1 to install all tunneling protocols
# Configure your domain and SSL certificates
# Access X-UI Panel at http://your-ip:54321
```

## System Requirements

- Ubuntu 20.04/22.04/24.04 (recommended)
- Root access
- Minimum 512MB RAM
- 10GB storage
- Internet connection
