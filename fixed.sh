#!/bin/bash
# Fixed SMTP server that accepts all relay

echo "Installing fixed SMTP server..."

# Stop existing service
systemctl stop stoat-mail 2>/dev/null || true

# Create fixed version
cat > /opt/stoat-mail-server/simple_smtp_server.py << 'ENDPYTHON'
#!/usr/bin/env python3
"""
Fixed SMTP Server - Accepts all relay for apps.tokyo
"""
import asyncore
from smtpd import SMTPServer
import json
import time
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from email.parser import Parser
from datetime import datetime
import sys

emails = []
MAX_EMAILS = 1000

class FixedSMTPServer(SMTPServer):
    """SMTP Server that accepts all relay"""
    
    # Override to accept all relay
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        """Process and store incoming email"""
        try:
            print(f"\n{'='*60}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Email received")
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
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        try:
                            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            break
                        except:
                            pass
                    elif content_type == "text/html":
                        try:
                            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except:
                            pass
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='ignore')
                except:
                    body = str(msg.get_payload())
            
            print(f"Subject: {subject}")
            print(f"Body length: {len(body)} chars")
            
            # Extract verification token
            token = None
            patterns = [
                r'https?://(?:api\.)?stoat\.chat[^\s<>"]*?/auth/account/verify/([a-zA-Z0-9\-_]+)',
                r'https?://[^\s<>"]+?/verify[/\?]([a-zA-Z0-9\-_]{20,})',
                r'/auth/account/verify/([a-zA-Z0-9\-_]{20,})',
                r'verify/([a-zA-Z0-9\-_]{20,})'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    token = match.group(1)
                    print(f"✓ Found token: {token[:20]}...")
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
            if len(emails) > MAX_EMAILS:
                emails.pop(0)
            
            print(f"✓ Stored email ID: {email_data['id']}, Total: {len(emails)}")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"Error processing: {e}")
            import traceback
            traceback.print_exc()
        
        # IMPORTANT: Return None to accept the message
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
<html><head><title>Stoat Mail Server</title>
<style>
body{{font-family:Arial,sans-serif;margin:20px;background:#f0f0f0}}
.container{{max-width:1200px;margin:0 auto;background:white;padding:20px;border-radius:8px}}
h1{{color:#333}}
.stats{{background:#e8f4f8;padding:15px;border-radius:5px;margin:20px 0}}
.email{{background:#f9f9f9;padding:15px;margin:10px 0;border-left:4px solid #4CAF50}}
.token{{background:#ffffcc;padding:10px;margin:10px 0;font-family:monospace}}
pre{{background:#f5f5f5;padding:10px;overflow-x:auto;max-height:200px}}
</style>
<script>setTimeout(function(){{location.reload()}},5000)</script>
</head><body>
<div class="container">
<h1>🔥 Stoat Mail Server</h1>
<div class="stats">
<h2>📊 Stats</h2>
<p><strong>Total Emails:</strong> {len(emails)}</p>
<p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><em>Auto-refresh every 5s</em></p>
</div>
<h2>📧 Recent Emails ({min(10, len(emails))} of {len(emails)})</h2>
"""
                
                for email in reversed(emails[-10:]):
                    html += f"""<div class="email">
<p><strong>ID:</strong> {email['id']} | <strong>Time:</strong> {email['timestamp']}</p>
<p><strong>From:</strong> {email['from']}</p>
<p><strong>To:</strong> {', '.join(email['to'])}</p>
<p><strong>Subject:</strong> {email['subject']}</p>"""
                    if email['token']:
                        html += f"""<div class="token">
<strong>🔑 Token:</strong> {email['token']}<br>
<strong>Link:</strong> https://stoat.chat/auth/account/verify/{email['token']}
</div>"""
                    if email['body']:
                        preview = email['body'][:300]
                        html += f"<details><summary>Body preview</summary><pre>{preview}...</pre></details>"
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
                    self.wfile.write(json.dumps({"error": "No emails yet"}).encode())
                    
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
                self.wfile.write(b"404 Not Found")
                
        except Exception as e:
            print(f"API Error: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error: {str(e)}".encode())

def run_smtp_server(host='0.0.0.0', port=25):
    print(f"Starting SMTP on {host}:{port}")
    # Use our fixed server
    server = FixedSMTPServer((host, port), None)
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
    print("🔥 Stoat Mail Server (Fixed - No Relay Restrictions)")
    print("="*60)
    print(f"SMTP: 0.0.0.0:25 (accepts ALL relay)")
    print(f"HTTP: 0.0.0.0:8080")
    print(f"Web:  http://localhost:8080")
    print("="*60)
    print()
    
    smtp_thread = Thread(target=run_smtp_server, daemon=True)
    smtp_thread.start()
    time.sleep(1)
    
    try:
        run_http_server()
    except KeyboardInterrupt:
        print("\n\nShutdown...")
        sys.exit(0)
ENDPYTHON

chmod +x /opt/stoat-mail-server/simple_smtp_server.py

# Restart service
systemctl restart stoat-mail

sleep 2

echo ""
echo "✅ Fixed SMTP server installed!"
echo ""
echo "Testing..."
systemctl status stoat-mail --no-pager | head -10

echo ""
echo "Server is now accepting all relay"
echo "Test: curl http://$(hostname -I | awk '{print $1}'):8080/api/emails"
