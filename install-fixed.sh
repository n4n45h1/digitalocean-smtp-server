#!/bin/bash
# Fixed Quick setup script for Stoat Mail Server

set -e

echo "============================================"
echo "Stoat Mail Server - Quick Setup"
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
apt-get install -y git python3 python3-pip curl wget

# Create temp directory
echo "[2/5] Downloading server script..."
cd /tmp
rm -rf smtp-setup
mkdir -p smtp-setup
cd smtp-setup

# Download the Python script directly
cat > simple_smtp_server.py << 'ENDOFPYTHON'
#!/usr/bin/env python3
"""
Simple SMTP Server for receiving verification emails
Stores emails in memory and provides HTTP API to retrieve them
"""
import asyncore
import smtpd
import json
import time
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from email.parser import Parser
from io import StringIO
from datetime import datetime
import sys

# Store received emails in memory
emails = []
MAX_EMAILS = 1000  # Keep last 1000 emails


class CustomSMTPServer(smtpd.SMTPServer):
    """Custom SMTP server that stores emails"""
    
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        """Process incoming email"""
        try:
            print(f"\n{'='*60}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] New email received")
            print(f"From: {mailfrom}")
            print(f"To: {rcpttos}")
            print(f"Peer: {peer}")
            
            # Parse email
            msg = Parser().parsestr(data.decode('utf-8', errors='ignore'))
            
            subject = msg.get('Subject', 'No Subject')
            body = ""
            
            # Extract body
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
                    elif part.get_content_type() == "text/html":
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            print(f"Subject: {subject}")
            print(f"Body length: {len(body)} chars")
            
            # Extract verification token/link
            token = None
            link_patterns = [
                r'https?://(?:api\.)?stoat\.chat[^\s<>"]*?/auth/account/verify/([a-zA-Z0-9\-_]+)',
                r'https?://[^\s<>"]+?/verify[/\?]([a-zA-Z0-9\-_]{20,})',
                r'/auth/account/verify/([a-zA-Z0-9\-_]{20,})',
                r'verify/([a-zA-Z0-9\-_]{20,})'
            ]
            
            for pattern in link_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    token = match.group(1)
                    print(f"✓ Found verification token: {token[:20]}...")
                    break
            
            # Store email
            email_data = {
                "id": len(emails) + 1,
                "timestamp": datetime.now().isoformat(),
                "from": mailfrom,
                "to": rcpttos,
                "subject": subject,
                "body": body,
                "token": token,
                "peer": str(peer),
                "raw": data.decode('utf-8', errors='ignore')
            }
            
            emails.append(email_data)
            
            # Keep only last MAX_EMAILS
            if len(emails) > MAX_EMAILS:
                emails.pop(0)
            
            print(f"✓ Email stored (ID: {email_data['id']}, Total: {len(emails)})")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"Error processing email: {e}")
            import traceback
            traceback.print_exc()
        
        return


class APIHandler(BaseHTTPRequestHandler):
    """HTTP API to retrieve emails"""
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            if self.path == '/':
                # Main page - show statistics
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Stoat Mail Server</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f0f0f0; }}
                        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
                        h1 {{ color: #333; }}
                        .stats {{ background: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                        .email {{ background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #4CAF50; }}
                        .token {{ background: #ffffcc; padding: 10px; margin: 10px 0; font-family: monospace; }}
                        .endpoint {{ background: #e1f5e1; padding: 10px; margin: 10px 0; font-family: monospace; }}
                        pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; }}
                    </style>
                    <script>
                        function autoRefresh() {{
                            setTimeout(function(){{ location.reload(); }}, 5000);
                        }}
                    </script>
                </head>
                <body onload="autoRefresh()">
                    <div class="container">
                        <h1>🔥 Stoat Mail Server</h1>
                        <div class="stats">
                            <h2>📊 Statistics</h2>
                            <p><strong>Total Emails:</strong> {len(emails)}</p>
                            <p><strong>Server Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                            <p><em>Auto-refreshing every 5 seconds...</em></p>
                        </div>
                        
                        <h2>🔌 API Endpoints</h2>
                        <div class="endpoint">GET /api/emails - Get all emails (JSON)</div>
                        <div class="endpoint">GET /api/emails/&lt;email&gt; - Get emails for specific address</div>
                        <div class="endpoint">GET /api/latest - Get latest email</div>
                        <div class="endpoint">GET /api/token/&lt;email&gt; - Get verification token for email</div>
                        
                        <h2>📧 Recent Emails ({min(10, len(emails))} of {len(emails)})</h2>
"""
                
                # Show last 10 emails
                for email in reversed(emails[-10:]):
                    html += f"""
                        <div class="email">
                            <p><strong>ID:</strong> {email['id']} | <strong>Time:</strong> {email['timestamp']}</p>
                            <p><strong>From:</strong> {email['from']}</p>
                            <p><strong>To:</strong> {', '.join(email['to'])}</p>
                            <p><strong>Subject:</strong> {email['subject']}</p>
"""
                    if email['token']:
                        html += f"""
                            <div class="token">
                                <strong>🔑 Verification Token:</strong> {email['token']}<br>
                                <strong>Link:</strong> https://stoat.chat/auth/account/verify/{email['token']}
                            </div>
"""
                    html += """
                        </div>
"""
                
                html += """
                    </div>
                </body>
                </html>
"""
                self.wfile.write(html.encode())
                
            elif self.path == '/api/emails':
                # Return all emails as JSON
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(emails, indent=2).encode())
                
            elif self.path == '/api/latest':
                # Return latest email
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                if emails:
                    self.wfile.write(json.dumps(emails[-1], indent=2).encode())
                else:
                    self.wfile.write(json.dumps({"error": "No emails yet"}).encode())
                    
            elif self.path.startswith('/api/emails/'):
                # Get emails for specific address
                email_address = self.path.split('/')[-1].lower()
                matching = [e for e in emails if any(email_address in to.lower() for to in e['to'])]
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(matching, indent=2).encode())
                
            elif self.path.startswith('/api/token/'):
                # Get verification token for specific email
                email_address = self.path.split('/')[-1].lower()
                matching = [e for e in emails if any(email_address in to.lower() for to in e['to']) and e['token']]
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                if matching:
                    latest = matching[-1]
                    self.wfile.write(json.dumps({
                        "email": email_address,
                        "token": latest['token'],
                        "link": f"https://stoat.chat/auth/account/verify/{latest['token']}",
                        "timestamp": latest['timestamp']
                    }, indent=2).encode())
                else:
                    self.wfile.write(json.dumps({"error": "No token found for this email"}).encode())
                    
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"404 Not Found")
                
        except Exception as e:
            print(f"API Error: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error: {str(e)}".encode())


def run_smtp_server(host='0.0.0.0', port=25):
    """Run SMTP server"""
    print(f"Starting SMTP server on {host}:{port}")
    server = CustomSMTPServer((host, port), None)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        print("\nSMTP server stopped")


def run_http_server(host='0.0.0.0', port=8080):
    """Run HTTP API server"""
    print(f"Starting HTTP API server on {host}:{port}")
    server = HTTPServer((host, port), APIHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nHTTP server stopped")


if __name__ == "__main__":
    print("="*60)
    print("🔥 Stoat Mail Server Starting...")
    print("="*60)
    print(f"SMTP Server: 0.0.0.0:25 (port 25)")
    print(f"HTTP API: 0.0.0.0:8080")
    print(f"Web Interface: http://localhost:8080")
    print("="*60)
    print()
    
    # Start SMTP server in background thread
    smtp_thread = Thread(target=run_smtp_server, daemon=True)
    smtp_thread.start()
    
    # Give SMTP server time to start
    time.sleep(1)
    
    # Run HTTP server in main thread
    try:
        run_http_server()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        sys.exit(0)
ENDOFPYTHON

chmod +x simple_smtp_server.py

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

# Stop any existing service
systemctl stop stoat-mail 2>/dev/null || true

# Configure firewall
echo "[5/5] Configuring firewall..."
if command -v ufw &> /dev/null; then
    echo "Opening ports 25 (SMTP) and 8080 (HTTP)..."
    ufw allow 25/tcp comment 'Stoat Mail SMTP' 2>/dev/null || true
    ufw allow 8080/tcp comment 'Stoat Mail HTTP' 2>/dev/null || true
fi

# Check if port 25 is available
if netstat -tuln | grep -q ":25 "; then
    echo "⚠️  WARNING: Port 25 is already in use!"
    echo "   Checking what's using it..."
    lsof -i :25 || netstat -tulpn | grep :25
    echo ""
    echo "   You may need to stop the existing service:"
    echo "   systemctl stop postfix"
    echo ""
fi

# Start service
echo ""
echo "Starting Stoat Mail Server..."
systemctl enable stoat-mail.service
systemctl start stoat-mail.service

# Wait a moment for service to start
sleep 3

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
echo "  Stop:    systemctl stop stoat-mail"
echo ""

echo "✅ Test the server:"
echo "  curl http://localhost:8080/api/emails"
echo "  curl http://${SERVER_IP}:8080/api/emails"
echo ""

# Test local connection
echo "🧪 Testing local connection..."
if curl -s http://localhost:8080/api/emails > /dev/null 2>&1; then
    echo "✅ Local HTTP API is working!"
else
    echo "⚠️  HTTP API not responding yet"
    echo "   Check logs: journalctl -u stoat-mail -n 20"
fi

echo ""
echo "============================================"
echo "Setup complete! Server is ready to use."
echo "============================================"
