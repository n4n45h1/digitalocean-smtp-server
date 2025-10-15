#!/bin/bash
# Quick setup script for Stoat Mail Server from GitHub
# Repository: github.com/n4n45h1/digitalocean-smtp-server

set -e

echo "============================================"
echo "Stoat Mail Server - Quick Setup from GitHub"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Please run as root (use sudo)"
    exit 1
fi

# Install dependencies
echo "[1/5] Installing dependencies..."
apt-get update -qq
apt-get install -y git python3 python3-pip

# Clone repository
echo "[2/5] Cloning repository from GitHub..."
cd /tmp
rm -rf digitalocean-smtp-server
git clone https://github.com/n4n45h1/digitalocean-smtp-server.git
cd digitalocean-smtp-server

# Create installation directory
echo "[3/5] Creating installation directory..."
mkdir -p /opt/stoat-mail-server
cp simple_smtp_server.py /opt/stoat-mail-server/
chmod +x /opt/stoat-mail-server/simple_smtp_server.py

# Create systemd service
echo "[4/5] Creating systemd service..."
cat > /etc/systemd/system/stoat-mail.service << 'EOF'
[Unit]
Description=Stoat Mail Server (SMTP + HTTP API)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/stoat-mail-server
ExecStart=/usr/bin/python3 /opt/stoat-mail-server/simple_smtp_server.py
Restart=always
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=stoat-mail

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Configure firewall
echo "[5/5] Configuring firewall..."
if command -v ufw &> /dev/null; then
    echo "Opening ports 25 (SMTP) and 8080 (HTTP)..."
    ufw allow 25/tcp comment 'Stoat Mail SMTP' 2>/dev/null || true
    ufw allow 8080/tcp comment 'Stoat Mail HTTP' 2>/dev/null || true
fi

# Start service
echo ""
echo "Starting Stoat Mail Server..."
systemctl enable stoat-mail.service
systemctl start stoat-mail.service

# Wait a moment for service to start
sleep 2

echo ""
echo "============================================"
echo "✅ Installation Complete!"
echo "============================================"
echo ""

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

echo "📊 Service Status:"
systemctl status stoat-mail.service --no-pager -l | head -15
echo ""

echo "🌐 Server Info:"
echo "  SMTP Server: ${SERVER_IP}:25"
echo "  HTTP API:    http://${SERVER_IP}:8080"
echo "  Web UI:      http://${SERVER_IP}:8080"
echo ""

echo "🔧 Useful Commands:"
echo "  Status:  systemctl status stoat-mail"
echo "  Restart: systemctl restart stoat-mail"
echo "  Logs:    journalctl -u stoat-mail -f"
echo ""

echo "✅ Test the server:"
echo "  curl http://${SERVER_IP}:8080/api/emails"
echo "  curl http://localhost:8080/api/emails"
echo ""

# Test local connection
echo "🧪 Testing local connection..."
if curl -s http://localhost:8080/api/emails > /dev/null 2>&1; then
    echo "✅ Local HTTP API is working!"
else
    echo "⚠️  HTTP API not responding yet (may need a few seconds to start)"
fi

echo ""
echo "============================================"
