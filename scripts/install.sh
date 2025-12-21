#!/bin/bash
# TorForge Installation Script
# Automated installer for Linux systems

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║              🧅 TorForge Installation Script                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        OS=$(uname -s)
    fi
    echo -e "${YELLOW}Detected OS: ${OS} ${VERSION}${NC}"
}

# Install dependencies
install_deps() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    
    case $OS in
        debian|ubuntu|kali)
            apt-get update
            apt-get install -y tor iptables curl
            ;;
        fedora|rhel|centos)
            dnf install -y tor iptables curl
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm tor iptables curl
            ;;
        *)
            echo -e "${RED}Unsupported OS. Please install tor and iptables manually.${NC}"
            ;;
    esac
}

# Download latest release
download_binary() {
    echo -e "${YELLOW}Downloading TorForge...${NC}"
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            BINARY="torforge-linux-amd64"
            ;;
        aarch64)
            BINARY="torforge-linux-arm64"
            ;;
        *)
            echo -e "${RED}Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac
    
    # For now, build from source if binary not available
    if [ -f "./build/torforge" ]; then
        cp ./build/torforge /usr/local/bin/torforge
    elif [ -f "./torforge" ]; then
        cp ./torforge /usr/local/bin/torforge
    else
        echo -e "${YELLOW}Building from source...${NC}"
        if command -v go &> /dev/null; then
            make build
            cp ./build/torforge /usr/local/bin/torforge
        else
            echo -e "${RED}Go not installed. Please install Go 1.23+ or download pre-built binary.${NC}"
            exit 1
        fi
    fi
    
    chmod +x /usr/local/bin/torforge
    echo -e "${GREEN}TorForge installed to /usr/local/bin/torforge${NC}"
}

# Setup configuration
setup_config() {
    echo -e "${YELLOW}Setting up configuration...${NC}"
    
    mkdir -p /etc/torforge
    mkdir -p /var/lib/torforge
    mkdir -p /var/log/torforge
    
    if [ ! -f /etc/torforge/torforge.yaml ]; then
        if [ -f ./configs/example-config.yaml ]; then
            cp ./configs/example-config.yaml /etc/torforge/torforge.yaml
        else
            cat > /etc/torforge/torforge.yaml << 'EOF'
tor:
  data_dir: /var/lib/torforge
bypass:
  enabled: true
  cidrs:
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "192.168.0.0/16"
security:
  kill_switch: true
  dns_leak_protection: true
EOF
        fi
        echo -e "${GREEN}Configuration created at /etc/torforge/torforge.yaml${NC}"
    fi
}

# Install systemd service
install_service() {
    echo -e "${YELLOW}Installing systemd service...${NC}"
    
    if [ -f ./systemd/torforge.service ]; then
        cp ./systemd/torforge.service /etc/systemd/system/
    else
        cat > /etc/systemd/system/torforge.service << 'EOF'
[Unit]
Description=TorForge - Advanced Transparent Tor Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/torforge tor
ExecStop=/usr/local/bin/torforge stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    systemctl daemon-reload
    echo -e "${GREEN}Systemd service installed${NC}"
}

# Verify installation
verify_install() {
    echo -e "${YELLOW}Verifying installation...${NC}"
    
    if /usr/local/bin/torforge --version &> /dev/null; then
        VERSION=$(/usr/local/bin/torforge --version 2>&1 | head -1)
        echo -e "${GREEN}✓ TorForge installed successfully: $VERSION${NC}"
    else
        echo -e "${RED}✗ TorForge installation failed${NC}"
        exit 1
    fi
    
    if command -v tor &> /dev/null; then
        echo -e "${GREEN}✓ Tor is installed${NC}"
    else
        echo -e "${RED}✗ Tor is not installed${NC}"
    fi
    
    if command -v iptables &> /dev/null; then
        echo -e "${GREEN}✓ iptables is available${NC}"
    else
        echo -e "${RED}✗ iptables is not available${NC}"
    fi
}

# Print usage
print_usage() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Installation complete!${NC}"
    echo ""
    echo -e "Usage:"
    echo -e "  ${YELLOW}sudo torforge tor${NC}          - Start transparent proxy"
    echo -e "  ${YELLOW}sudo torforge status${NC}       - Show dashboard"
    echo -e "  ${YELLOW}sudo torforge stop${NC}         - Stop and restore network"
    echo ""
    echo -e "To enable auto-start:"
    echo -e "  ${YELLOW}sudo systemctl enable torforge${NC}"
    echo ""
    echo -e "Configuration: /etc/torforge/torforge.yaml"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

# Main
detect_os
install_deps
download_binary
setup_config
install_service
verify_install
print_usage
