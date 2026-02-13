#!/bin/bash
#
# EvilGinx2 + EvilPuppet — Debian Setup Script
#
# Installs everything needed to build and run evilginx with EvilPuppet on Debian 11/12.
# Run as root or with sudo:
#
#   chmod +x setup-debian.sh
#   sudo ./setup-debian.sh
#
set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║   EvilGinx2 + EvilPuppet — Debian Setup     ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "  ${GREEN}[+]${NC} $*"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $*"; }
error()   { echo -e "  ${RED}[-]${NC} $*"; }
step()    { echo -e "\n${BOLD}==> $*${NC}"; }

banner

# ─── Preflight ───────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root (use sudo)."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/evilginx"
GO_VERSION="1.22.5"
GO_ARCH="amd64"

# Detect architecture
MACHINE=$(uname -m)
case "$MACHINE" in
    x86_64)  GO_ARCH="amd64" ;;
    aarch64) GO_ARCH="arm64" ;;
    armv*)   GO_ARCH="armv6l" ;;
    *)       error "Unsupported architecture: $MACHINE"; exit 1 ;;
esac

# ─── Step 1: System packages ────────────────────────────────────────
step "Installing system dependencies"
apt-get update -qq
apt-get install -y -qq \
    build-essential \
    wget \
    curl \
    git \
    ca-certificates \
    gnupg \
    unzip \
    > /dev/null 2>&1
info "Base packages installed"

# ─── Step 2: Install Go (if not present or too old) ─────────────────
step "Checking Go installation"
NEED_GO=true
if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
    REQUIRED="1.22"
    if [ "$(printf '%s\n' "$REQUIRED" "$CURRENT_GO" | sort -V | head -n1)" = "$REQUIRED" ]; then
        info "Go $CURRENT_GO already installed (>= $REQUIRED) — skipping"
        NEED_GO=false
    else
        warn "Go $CURRENT_GO is too old (need >= $REQUIRED) — upgrading"
    fi
fi

if $NEED_GO; then
    info "Installing Go $GO_VERSION ($GO_ARCH)..."
    GO_TAR="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    wget -q "https://go.dev/dl/${GO_TAR}" -O "/tmp/${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"

    # Make Go available system-wide
    if ! grep -q '/usr/local/go/bin' /etc/profile.d/go.sh 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
        chmod +x /etc/profile.d/go.sh
    fi
    export PATH=$PATH:/usr/local/go/bin
    info "Go $(go version | grep -oP 'go\K[0-9]+\.[0-9]+\.[0-9]+') installed to /usr/local/go"
fi

# ─── Step 3: Install Chromium (for EvilPuppet) ──────────────────────
step "Installing Chromium for EvilPuppet"
if command -v chromium &>/dev/null || command -v chromium-browser &>/dev/null; then
    CHROME_BIN=$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null)
    info "Chromium already installed at $CHROME_BIN — skipping"
else
    apt-get install -y -qq chromium > /dev/null 2>&1 || \
    apt-get install -y -qq chromium-browser > /dev/null 2>&1 || {
        warn "Could not install via apt, trying snap..."
        snap install chromium 2>/dev/null || {
            error "Failed to install Chromium. Install manually:"
            error "  apt install chromium   OR   snap install chromium"
            error "Then set the path:  puppet chrome /path/to/chromium"
        }
    }

    CHROME_BIN=$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || echo "")
    if [ -n "$CHROME_BIN" ]; then
        info "Chromium installed at $CHROME_BIN"
    fi
fi

# ─── Step 4: Build EvilGinx ─────────────────────────────────────────
step "Building EvilGinx2"
cd "$SCRIPT_DIR"
export PATH=$PATH:/usr/local/go/bin

info "Running go mod vendor..."
go mod vendor 2>/dev/null || go mod tidy && go mod vendor

info "Compiling..."
mkdir -p ./build
go build -o ./build/evilginx -mod=vendor main.go
info "Binary built: $(ls -lh ./build/evilginx | awk '{print $5}') → ./build/evilginx"

# ─── Step 5: Install to /opt/evilginx ───────────────────────────────
step "Installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -f ./build/evilginx "$INSTALL_DIR/evilginx"
chmod +x "$INSTALL_DIR/evilginx"

# Copy phishlets and redirectors
mkdir -p "$INSTALL_DIR/phishlets"
mkdir -p "$INSTALL_DIR/redirectors"
if [ -d "$SCRIPT_DIR/phishlets" ]; then
    cp -r "$SCRIPT_DIR/phishlets/"* "$INSTALL_DIR/phishlets/" 2>/dev/null || true
fi
if [ -d "$SCRIPT_DIR/redirectors" ]; then
    cp -r "$SCRIPT_DIR/redirectors/"* "$INSTALL_DIR/redirectors/" 2>/dev/null || true
fi

# Symlink to PATH
ln -sf "$INSTALL_DIR/evilginx" /usr/local/bin/evilginx
info "Installed to $INSTALL_DIR and linked to /usr/local/bin/evilginx"

# ─── Step 6: Create systemd service ─────────────────────────────────
step "Creating systemd service"
cat > /etc/systemd/system/evilginx.service << 'UNIT'
[Unit]
Description=EvilGinx2 Phishing Framework with EvilPuppet
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/evilginx/evilginx -p /opt/evilginx/phishlets -t /opt/evilginx/redirectors
WorkingDirectory=/opt/evilginx
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Hardening
NoNewPrivileges=false
ProtectSystem=false

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
info "Systemd service created: evilginx.service"

# ─── Step 7: Firewall hints ─────────────────────────────────────────
step "Firewall configuration"
if command -v ufw &>/dev/null; then
    warn "UFW detected. You may need to open these ports:"
    echo -e "    ${CYAN}sudo ufw allow 443/tcp${NC}    # HTTPS proxy"
    echo -e "    ${CYAN}sudo ufw allow 80/tcp${NC}     # HTTP redirect"
    echo -e "    ${CYAN}sudo ufw allow 53/udp${NC}     # DNS"
    echo -e "    ${CYAN}sudo ufw allow 7777/tcp${NC}   # EvilPuppet web UI"
elif command -v iptables &>/dev/null; then
    warn "Make sure these ports are open in iptables:"
    echo -e "    443/tcp (HTTPS), 80/tcp (HTTP), 53/udp (DNS), 7777/tcp (EvilPuppet)"
fi

# ─── Step 8: Stop conflicting services ──────────────────────────────
step "Checking for port conflicts"
for svc in apache2 nginx systemd-resolved; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        warn "$svc is running and may conflict. To stop it:"
        echo -e "    ${CYAN}sudo systemctl stop $svc && sudo systemctl disable $svc${NC}"
    fi
done

# ─── Done ────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ✓ Setup complete!${NC}"
echo ""
echo -e "  ${BOLD}Quick start:${NC}"
echo -e "    ${CYAN}sudo evilginx${NC}                              # run interactively"
echo -e "    ${CYAN}sudo systemctl start evilginx${NC}              # run as service"
echo -e "    ${CYAN}sudo systemctl enable evilginx${NC}             # auto-start on boot"
echo ""
echo -e "  ${BOLD}EvilPuppet (inside evilginx):${NC}"
echo -e "    ${CYAN}: puppet launch <session_id> <target_url>${NC}  # launch puppet browser"
echo -e "    ${CYAN}: puppet url <puppet_id>${NC}                   # get remote control URL"
echo -e "    ${CYAN}: puppet list${NC}                              # see active puppets"
echo ""
echo -e "  ${BOLD}Important:${NC}"
echo -e "    • Puppet web UI listens on port ${YELLOW}7777${NC} (auto-generated password shown at startup)"
echo -e "    • EvilPuppet uses Chromium at: ${YELLOW}$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || echo '/usr/bin/chromium')${NC}"
echo -e "    • Config stored in ${YELLOW}~/.evilginx/${NC}"
echo ""
