#!/bin/bash
# Super simple installation script for Stoat Mail Server
# No MySQL, no git, just pure Python SMTP server

echo "=========================================="
echo "Stoat Mail Server - Simple Install"
echo "=========================================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Install only Python3
echo "[1/3] Installing Python3..."
apt-get update -qq
apt-get install -y python3

# Create directory and script
echo "[2/3] Creating SMTP server..."
mkdir -p /opt/stoat-mail-server
cd /opt/stoat-mail-server

# Create the Python server script inline
cat > simple_smtp_server.py << 'ENDPYTHON'
#!/usr/bin/env python3
import asyncore, smtpd, json, time, re
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from email.parser import Parser
from datetime import datetime
import sys

emails = []
MAX_EMAILS = 1000

class CustomSMTPServer(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        try:
            print(f"\n{'='*60}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] New email")
            print(f"From: {mailfrom}")
            print(f"To: {rcpttos}")
            
            msg = Parser().parsestr(data.decode('utf-8', errors='ignore'))
            subject = msg.get('Subject', 'No Subject')
            body = ""
            
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
                    elif part.get_content_type() == "text/html":
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            token = None
            patterns = [
                r'https?://(?:api\.)?stoat\.chat[^\s<>"]*?/auth/account/verify/([a-zA-Z0-9\-_]+)',
                r'/auth/account/verify/([a-zA-Z0-9\-_]{20,})'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    token = match.group(1)
                    print(f"✓ Token: {token[:20]}...")
                    break
            
            email_data = {
                "id": len(emails) + 1,
                "timestamp": datetime.now().isoformat(),
                "from": mailfrom,
                "to": rcpttos,
                "subject": subject,
                "body": body,
                "token": token
            }
            
            emails.append(email_data)
            if len(emails) > MAX_EMAILS:
                emails.pop(0)
            
            print(f"✓ Stored (ID: {email_data['id']})")
            print(f"{'='*60}\n")
        except Exception as e:
            print(f"Error: {e}")
        return

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        try:
            if self.path == '/':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                html = f"""<!DOCTYPE html>
<html><head><title>Stoat Mail</title>
<style>body{{font-family:Arial;margin:20px;background:#f0f0f0}}
.container{{max-width:1200px;margin:0 auto;background:white;padding:20px;border-radius:8px}}
.email{{background:#f9f9f9;padding:15px;margin:10px 0;border-left:4px solid #4CAF50}}
.token{{background:#ffffcc;padding:10px;margin:10px 0;font-family:monospace}}</style>
<script>setTimeout(function(){{location.reload()}},5000)</script>
</head><body><div class="container">
<h1>🔥 Stoat Mail Server</h1>
<p><strong>Total Emails:</strong> {len(emails)}</p>
<p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><em>Auto-refresh every 5s</em></p>
<h2>Recent Emails ({min(10, len(emails))} of {len(emails)})</h2>"""
                
                for email in reversed(emails[-10:]):
                    html += f"""<div class="email">
<p><strong>ID:</strong> {email['id']} | <strong>Time:</strong> {email['timestamp']}</p>
<p><strong>From:</strong> {email['from']}</p>
<p><strong>To:</strong> {', '.join(email['to'])}</p>
<p><strong>Subject:</strong> {email['subject']}</p>"""
                    if email['token']:
                        html += f"""<div class="token"><strong>🔑 Token:</strong> {email['token']}<br>
<strong>Link:</strong> https://stoat.chat/auth/account/verify/{email['token']}</div>"""
                    html += "</div>"
                
                html += "</div></body></html>"
                self.wfile.write(html.encode())
                
            elif self.path == '/api/emails':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(emails, indent=2).encode())
                
            elif self.path == '/api/latest':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                if emails:
                    self.wfile.write(json.dumps(emails[-1], indent=2).encode())
                else:
                    self.wfile.write(json.dumps({"error": "No emails"}).encode())
                    
            elif self.path.startswith('/api/emails/'):
                email_address = self.path.split('/')[-1].lower()
                matching = [e for e in emails if any(email_address in to.lower() for to in e['to'])]
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(matching, indent=2).encode())
                
            elif self.path.startswith('/api/token/'):
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
                    self.wfile.write(json.dumps({"error": "No token found"}).encode())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"404")
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error: {str(e)}".encode())

def run_smtp_server(host='0.0.0.0', port=25):
    print(f"Starting SMTP on {host}:{port}")
    server = CustomSMTPServer((host, port), None)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        print("\nSMTP stopped")

def run_http_server(host='0.0.0.0', port=8080):
    print(f"Starting HTTP on {host}:{port}")
    server = HTTPServer((host, port), APIHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nHTTP stopped")

if __name__ == "__main__":
    print("="*60)
    print("🔥 Stoat Mail Server")
    print("="*60)
    print(f"SMTP: 0.0.0.0:25")
    print(f"HTTP: 0.0.0.0:8080")
    print("="*60)
    
    smtp_thread = Thread(target=run_smtp_server, daemon=True)
    smtp_thread.start()
    time.sleep(1)
    
    try:
        run_http_server()
    except KeyboardInterrupt:
        print("\nShutdown")
        sys.exit(0)
ENDPYTHON

chmod +x simple_smtp_server.py

# Create systemd service
echo "[3/3] Setting up service..."
cat > /etc/systemd/system/stoat-mail.service << 'ENDSVC'
[Unit]
Description=Stoat Mail Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/stoat-mail-server
ExecStart=/usr/bin/python3 /opt/stoat-mail-server/simple_smtp_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
ENDSVC

systemctl daemon-reload
systemctl enable stoat-mail.service
systemctl start stoat-mail.service

sleep 2

echo ""
echo "=========================================="
echo "✅ Installation Complete!"
echo "=========================================="
echo ""

SERVER_IP=$(hostname -I | awk '{print $1}')

echo "📊 Status:"
systemctl status stoat-mail.service --no-pager | head -10

echo ""
echo "🌐 Access:"
echo "  SMTP: ${SERVER_IP}:25"
echo "  Web:  http://${SERVER_IP}:8080"
echo ""
echo "🔧 Commands:"
echo "  systemctl status stoat-mail"
echo "  systemctl restart stoat-mail"
echo "  journalctl -u stoat-mail -f"
echo ""
