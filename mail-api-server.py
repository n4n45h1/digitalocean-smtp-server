#!/usr/bin/env python3
"""
Mail Server REST API
Provides endpoints for managing email accounts and retrieving mail
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import bcrypt
import os
import sys
import imaplib
import email
from email.header import decode_header
import json
from datetime import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)

# Configuration
DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'mailuser',
    'database': 'mailserver'
}

# Load from environment or config file
CONFIG_FILE = '/etc/mail-api-config.json'
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        DB_CONFIG['password'] = config.get('db_password')
        API_TOKEN = config.get('api_token')
        DOMAIN = config.get('domain')
else:
    print(f"Error: Configuration file {CONFIG_FILE} not found")
    sys.exit(1)

# Database connection helper
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or token != f"Bearer {API_TOKEN}":
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'message': 'Mail API server is running'})

# Create email account
@app.route('/api/accounts', methods=['POST'])
@require_auth
def create_account():
    """
    Create a new email account
    Request body: {"email": "user@domain.com", "password": "password123"}
    """
    data = request.get_json()
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password are required'}), 400
    
    email_address = data['email'].lower()
    password = data['password']
    
    # Validate email format
    if '@' not in email_address:
        return jsonify({'error': 'Invalid email format'}), 400
    
    domain = email_address.split('@')[1]
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if domain exists
        cursor.execute("SELECT id FROM virtual_domains WHERE name = %s", (domain,))
        domain_result = cursor.fetchone()
        
        if not domain_result:
            return jsonify({'error': 'Domain not found'}), 404
        
        domain_id = domain_result['id']
        
        # Check if email already exists
        cursor.execute("SELECT id FROM virtual_users WHERE email = %s", (email_address,))
        if cursor.fetchone():
            return jsonify({'error': 'Email already exists'}), 409
        
        # Hash password using bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Insert new user
        cursor.execute(
            "INSERT INTO virtual_users (domain_id, email, password) VALUES (%s, %s, %s)",
            (domain_id, email_address, password_hash)
        )
        conn.commit()
        
        user_id = cursor.lastrowid
        
        # Create mailbox directory
        mailbox_path = f"/var/mail/vhosts/{domain}/{email_address.split('@')[0]}"
        os.makedirs(mailbox_path, exist_ok=True)
        os.system(f"chown -R vmail:vmail {mailbox_path}")
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Email account created successfully',
            'account': {
                'id': user_id,
                'email': email_address,
                'domain': domain
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# List email accounts
@app.route('/api/accounts', methods=['GET'])
@require_auth
def list_accounts():
    """
    List all email accounts
    Query params: domain (optional)
    """
    domain_filter = request.args.get('domain')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        if domain_filter:
            cursor.execute("""
                SELECT u.id, u.email, d.name as domain
                FROM virtual_users u
                JOIN virtual_domains d ON u.domain_id = d.id
                WHERE d.name = %s
                ORDER BY u.email
            """, (domain_filter,))
        else:
            cursor.execute("""
                SELECT u.id, u.email, d.name as domain
                FROM virtual_users u
                JOIN virtual_domains d ON u.domain_id = d.id
                ORDER BY u.email
            """)
        
        accounts = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'count': len(accounts),
            'accounts': accounts
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get account details
@app.route('/api/accounts/<email>', methods=['GET'])
@require_auth
def get_account(email):
    """
    Get details for a specific email account
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT u.id, u.email, d.name as domain
            FROM virtual_users u
            JOIN virtual_domains d ON u.domain_id = d.id
            WHERE u.email = %s
        """, (email.lower(),))
        
        account = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if not account:
            return jsonify({'error': 'Account not found'}), 404
        
        return jsonify({
            'success': True,
            'account': account
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Update account password
@app.route('/api/accounts/<email>/password', methods=['PUT'])
@require_auth
def update_password(email):
    """
    Update password for an email account
    Request body: {"password": "newpassword123"}
    """
    data = request.get_json()
    
    if not data or 'password' not in data:
        return jsonify({'error': 'Password is required'}), 400
    
    password = data['password']
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password
        cursor.execute(
            "UPDATE virtual_users SET password = %s WHERE email = %s",
            (password_hash, email.lower())
        )
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({'error': 'Account not found'}), 404
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Password updated successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Delete email account
@app.route('/api/accounts/<email>', methods=['DELETE'])
@require_auth
def delete_account(email):
    """
    Delete an email account
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get domain info before deletion
        cursor.execute("""
            SELECT d.name as domain
            FROM virtual_users u
            JOIN virtual_domains d ON u.domain_id = d.id
            WHERE u.email = %s
        """, (email.lower(),))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'error': 'Account not found'}), 404
        
        domain = result['domain']
        
        # Delete user
        cursor.execute("DELETE FROM virtual_users WHERE email = %s", (email.lower(),))
        conn.commit()
        
        # Delete mailbox directory
        mailbox_path = f"/var/mail/vhosts/{domain}/{email.split('@')[0]}"
        os.system(f"rm -rf {mailbox_path}")
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Account deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Create email alias
@app.route('/api/aliases', methods=['POST'])
@require_auth
def create_alias():
    """
    Create an email alias
    Request body: {"source": "alias@domain.com", "destination": "real@domain.com"}
    """
    data = request.get_json()
    
    if not data or 'source' not in data or 'destination' not in data:
        return jsonify({'error': 'Source and destination are required'}), 400
    
    source = data['source'].lower()
    destination = data['destination'].lower()
    domain = source.split('@')[1]
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get domain ID
        cursor.execute("SELECT id FROM virtual_domains WHERE name = %s", (domain,))
        domain_result = cursor.fetchone()
        
        if not domain_result:
            return jsonify({'error': 'Domain not found'}), 404
        
        domain_id = domain_result['id']
        
        # Create alias
        cursor.execute(
            "INSERT INTO virtual_aliases (domain_id, source, destination) VALUES (%s, %s, %s)",
            (domain_id, source, destination)
        )
        conn.commit()
        
        alias_id = cursor.lastrowid
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Alias created successfully',
            'alias': {
                'id': alias_id,
                'source': source,
                'destination': destination
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# List aliases
@app.route('/api/aliases', methods=['GET'])
@require_auth
def list_aliases():
    """
    List all email aliases
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT a.id, a.source, a.destination, d.name as domain
            FROM virtual_aliases a
            JOIN virtual_domains d ON a.domain_id = d.id
            ORDER BY a.source
        """)
        
        aliases = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'count': len(aliases),
            'aliases': aliases
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Delete alias
@app.route('/api/aliases/<int:alias_id>', methods=['DELETE'])
@require_auth
def delete_alias(alias_id):
    """
    Delete an email alias
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM virtual_aliases WHERE id = %s", (alias_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({'error': 'Alias not found'}), 404
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Alias deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get emails for an account
@app.route('/api/accounts/<email>/messages', methods=['GET'])
@require_auth
def get_messages(email):
    """
    Get messages for an email account via IMAP
    Query params: mailbox (default: INBOX), limit (default: 50)
    """
    password = request.args.get('password')
    if not password:
        return jsonify({'error': 'Password is required as query parameter'}), 400
    
    mailbox = request.args.get('mailbox', 'INBOX')
    limit = int(request.args.get('limit', 50))
    
    try:
        # Connect to IMAP
        imap = imaplib.IMAP4_SSL('localhost', 993)
        imap.login(email, password)
        imap.select(mailbox)
        
        # Search for all emails
        status, messages = imap.search(None, 'ALL')
        message_ids = messages[0].split()
        
        # Get last N messages
        message_ids = message_ids[-limit:]
        
        emails = []
        for msg_id in reversed(message_ids):
            status, msg_data = imap.fetch(msg_id, '(RFC822)')
            
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    # Decode subject
                    subject = decode_header(msg['Subject'])[0][0]
                    if isinstance(subject, bytes):
                        subject = subject.decode()
                    
                    # Get body
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode()
                                break
                    else:
                        body = msg.get_payload(decode=True).decode()
                    
                    emails.append({
                        'id': msg_id.decode(),
                        'from': msg['From'],
                        'to': msg['To'],
                        'subject': subject,
                        'date': msg['Date'],
                        'body': body[:500]  # First 500 chars
                    })
        
        imap.close()
        imap.logout()
        
        return jsonify({
            'success': True,
            'count': len(emails),
            'messages': emails
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Add domain
@app.route('/api/domains', methods=['POST'])
@require_auth
def add_domain():
    """
    Add a new domain
    Request body: {"domain": "example.com"}
    """
    data = request.get_json()
    
    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain is required'}), 400
    
    domain = data['domain'].lower()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("INSERT INTO virtual_domains (name) VALUES (%s)", (domain,))
        conn.commit()
        
        domain_id = cursor.lastrowid
        
        # Create domain directory
        os.makedirs(f"/var/mail/vhosts/{domain}", exist_ok=True)
        os.system(f"chown -R vmail:vmail /var/mail/vhosts/{domain}")
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Domain added successfully',
            'domain': {
                'id': domain_id,
                'name': domain
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# List domains
@app.route('/api/domains', methods=['GET'])
@require_auth
def list_domains():
    """
    List all domains
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT id, name FROM virtual_domains ORDER BY name")
        domains = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'count': len(domains),
            'domains': domains
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('API_PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
