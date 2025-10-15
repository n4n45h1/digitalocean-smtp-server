#!/bin/bash
# Deploy Stoat Mail Server to remote Ubuntu server

SERVER="157.245.52.81"
USER="root"
PASSWORD="atht@1Rtmt"
REMOTE_DIR="/opt/stoat-mail-server"

echo "============================================"
echo "Deploying Stoat Mail Server"
echo "Server: $SERVER"
echo "============================================"
echo ""

# Create temporary deployment package
echo "[1/4] Creating deployment package..."
mkdir -p /tmp/stoat-mail-deploy
cp simple_smtp_server.py /tmp/stoat-mail-deploy/
cp setup.sh /tmp/stoat-mail-deploy/
cd /tmp/stoat-mail-deploy

# Upload files using scp
echo "[2/4] Uploading files to server..."
echo "Password: $PASSWORD"

sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $USER@$SERVER "mkdir -p $REMOTE_DIR"

sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no \
    simple_smtp_server.py setup.sh \
    $USER@$SERVER:$REMOTE_DIR/

# Run setup script on remote server
echo "[3/4] Running setup on remote server..."
sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $USER@$SERVER << 'ENDSSH'
cd /opt/stoat-mail-server
chmod +x setup.sh
./setup.sh
ENDSSH

# Test connection
echo "[4/4] Testing connection..."
sleep 5
curl -s http://$SERVER:8080/api/emails > /dev/null && echo "✓ HTTP API is responding" || echo "✗ HTTP API not responding"

echo ""
echo "============================================"
echo "✓ Deployment Complete!"
echo "============================================"
echo ""
echo "Server Info:"
echo "  SMTP:    $SERVER:25"
echo "  HTTP:    http://$SERVER:8080"
echo "  Web UI:  http://$SERVER:8080"
echo ""
echo "Connect via SSH:"
echo "  ssh $USER@$SERVER"
echo ""
echo "Check logs:"
echo "  ssh $USER@$SERVER 'journalctl -u stoat-mail -f'"
echo ""

# Cleanup
rm -rf /tmp/stoat-mail-deploy
