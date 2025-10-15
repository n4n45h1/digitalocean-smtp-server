#!/bin/bash
# Setup script for Stoat Mail Server on Ubuntu

set -e

echo "============================================"
echo "Stoat Mail Server Setup"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Update system
echo "[1/6] Updating system packages..."
apt-get update -qq

# Install Python if not present
echo "[2/6] Installing Python3..."
apt-get install -y python3 python3-pip

# Create directory
echo "[3/6] Creating mail server directory..."
mkdir -p /opt/stoat-mail-server
cp simple_smtp_server.py /opt/stoat-mail-server/
chmod +x /opt/stoat-mail-server/simple_smtp_server.py

# Create systemd service
echo "[4/6] Creating systemd service..."
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

# Configure firewall (if ufw is installed)
echo "[5/6] Configuring firewall..."
if command -v ufw &> /dev/null; then
    echo "Opening ports 25 (SMTP) and 8080 (HTTP)..."
    ufw allow 25/tcp comment 'Stoat Mail SMTP'
    ufw allow 8080/tcp comment 'Stoat Mail HTTP'
else
    echo "ufw not installed, skipping firewall configuration"
fi

# Start and enable service
echo "[6/6] Starting Stoat Mail Server..."
systemctl enable stoat-mail.service
systemctl start stoat-mail.service

echo ""
echo "============================================"
echo "✓ Setup Complete!"
echo "============================================"
echo ""
echo "Service Status:"
systemctl status stoat-mail.service --no-pager || true
echo ""
echo "Useful Commands:"
echo "  Status:  systemctl status stoat-mail"
echo "  Start:   systemctl start stoat-mail"
echo "  Stop:    systemctl stop stoat-mail"
echo "  Restart: systemctl restart stoat-mail"
echo "  Logs:    journalctl -u stoat-mail -f"
echo ""
echo "Server Info:"
echo "  SMTP Server: $(hostname -I | awk '{print $1}'):25"
echo "  HTTP API:    http://$(hostname -I | awk '{print $1}'):8080"
echo "  Web UI:      http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "Test with:"
echo "  curl http://$(hostname -I | awk '{print $1}'):8080/api/emails"
echo ""
