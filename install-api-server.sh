#!/bin/bash

# API Server Installation Script

set -e

# Check if config file exists
if [ ! -f /root/mail-server-config.txt ]; then
    echo "Error: Mail server configuration not found. Run setup-smtp-server.sh first."
    exit 1
fi

# Extract configuration
MAIL_DB_PASSWORD=$(grep "Mail Database Password:" /root/mail-server-config.txt | cut -d' ' -f4)
API_TOKEN=$(grep "API Token:" /root/mail-server-config.txt | cut -d' ' -f3)
DOMAIN=$(grep "Domain:" /root/mail-server-config.txt | head -1 | cut -d' ' -f2)
API_PORT=$(grep "API Port:" /root/mail-server-config.txt | cut -d' ' -f3)

# Create API configuration
cat > /etc/mail-api-config.json <<EOF
{
    "db_password": "${MAIL_DB_PASSWORD}",
    "api_token": "${API_TOKEN}",
    "domain": "${DOMAIN}"
}
EOF

chmod 600 /etc/mail-api-config.json

# Copy API server script
cp mail-api-server.py /usr/local/bin/mail-api-server.py
chmod +x /usr/local/bin/mail-api-server.py

# Create systemd service
cat > /etc/systemd/system/mail-api.service <<EOF
[Unit]
Description=Mail Server REST API
After=network.target mysql.service

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bin
Environment="API_PORT=${API_PORT}"
ExecStart=/usr/bin/python3 /usr/local/bin/mail-api-server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable mail-api.service
systemctl start mail-api.service

echo "Mail API server installed and started successfully!"
echo "API is running on port ${API_PORT}"
echo ""
echo "Test the API:"
echo "curl -H 'Authorization: Bearer ${API_TOKEN}' http://localhost:${API_PORT}/health"
