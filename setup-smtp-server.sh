#!/bin/bash

# DigitalOcean SMTP Server Setup Script by copilot
# Postfix + Dovecot + REST API

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo_error "This script must be run as root"
   exit 1
fi

# Configuration
read -p "Enter your domain name (e.g., mail.example.com): " DOMAIN
read -p "Enter admin email address: " ADMIN_EMAIL
read -p "Enter API port (default: 8080): " API_PORT
API_PORT=${API_PORT:-8080}
read -sp "Enter API authentication token: " API_TOKEN
echo

if [ -z "$DOMAIN" ] || [ -z "$ADMIN_EMAIL" ] || [ -z "$API_TOKEN" ]; then
    echo_error "All fields are required"
    exit 1
fi

# Update system
echo_info "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install required packages
echo_info "Installing required packages..."
apt-get install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-pop3d \
    dovecot-lmtpd dovecot-mysql mysql-server python3 python3-pip nginx certbot \
    python3-certbot-nginx opendkim opendkim-tools

# Install Python packages
echo_info "Installing Python packages..."
pip3 install flask flask-cors mysql-connector-python bcrypt

# Configure MySQL
echo_info "Configuring MySQL database..."
MYSQL_ROOT_PASSWORD=$(openssl rand -base64 32)
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD}';"

# Create mail database
MAIL_DB_PASSWORD=$(openssl rand -base64 32)
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" <<EOF
CREATE DATABASE IF NOT EXISTS mailserver;
CREATE USER IF NOT EXISTS 'mailuser'@'localhost' IDENTIFIED BY '${MAIL_DB_PASSWORD}';
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'localhost';
FLUSH PRIVILEGES;

USE mailserver;

CREATE TABLE IF NOT EXISTS virtual_domains (
    id INT NOT NULL AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS virtual_users (
    id INT NOT NULL AUTO_INCREMENT,
    domain_id INT NOT NULL,
    email VARCHAR(120) NOT NULL,
    password VARCHAR(255) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY (email),
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS virtual_aliases (
    id INT NOT NULL AUTO_INCREMENT,
    domain_id INT NOT NULL,
    source VARCHAR(120) NOT NULL,
    destination VARCHAR(120) NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO virtual_domains (name) VALUES ('${DOMAIN}');
EOF

echo_info "Database configured successfully"

# Configure Postfix
echo_info "Configuring Postfix..."
cat > /etc/postfix/main.cf <<EOF
# Basic settings
smtpd_banner = \$myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2

# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/${DOMAIN}/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/${DOMAIN}/privkey.pem
smtpd_tls_security_level=may
smtp_tls_security_level = may
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# Network settings
myhostname = ${DOMAIN}
myorigin = ${DOMAIN}
mydestination = localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

# Virtual domain settings
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf
virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf

# SMTP restrictions
smtpd_helo_required = yes
smtpd_recipient_restrictions =
    permit_sasl_authenticated,
    permit_mynetworks,
    reject_unauth_destination,
    reject_invalid_hostname,
    reject_non_fqdn_hostname,
    reject_non_fqdn_sender,
    reject_non_fqdn_recipient,
    reject_unknown_sender_domain,
    reject_unknown_recipient_domain,
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net,
    permit

# SASL settings
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$myhostname
broken_sasl_auth_clients = yes

# OpenDKIM
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = \$smtpd_milters
EOF

# MySQL configuration files for Postfix
cat > /etc/postfix/mysql-virtual-mailbox-domains.cf <<EOF
user = mailuser
password = ${MAIL_DB_PASSWORD}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s'
EOF

cat > /etc/postfix/mysql-virtual-mailbox-maps.cf <<EOF
user = mailuser
password = ${MAIL_DB_PASSWORD}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_users WHERE email='%s'
EOF

cat > /etc/postfix/mysql-virtual-alias-maps.cf <<EOF
user = mailuser
password = ${MAIL_DB_PASSWORD}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s'
EOF

chmod 640 /etc/postfix/mysql-*.cf
chown root:postfix /etc/postfix/mysql-*.cf

# Configure Postfix master.cf
cat >> /etc/postfix/master.cf <<EOF

submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
EOF

# Configure Dovecot
echo_info "Configuring Dovecot..."
cat > /etc/dovecot/dovecot.conf <<EOF
protocols = imap pop3 lmtp
listen = *, ::
dict {
}
!include conf.d/*.conf
!include_try local.conf
EOF

cat > /etc/dovecot/conf.d/10-auth.conf <<EOF
disable_plaintext_auth = yes
auth_mechanisms = plain login
!include auth-sql.conf.ext
EOF

cat > /etc/dovecot/conf.d/auth-sql.conf.ext <<EOF
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}
EOF

cat > /etc/dovecot/dovecot-sql.conf.ext <<EOF
driver = mysql
connect = host=127.0.0.1 dbname=mailserver user=mailuser password=${MAIL_DB_PASSWORD}
default_pass_scheme = BLF-CRYPT
password_query = SELECT email as user, password FROM virtual_users WHERE email='%u';
EOF

chmod 640 /etc/dovecot/dovecot-sql.conf.ext
chown root:dovecot /etc/dovecot/dovecot-sql.conf.ext

cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
mail_location = maildir:/var/mail/vhosts/%d/%n
mail_privileged_group = mail
namespace inbox {
  inbox = yes
}
first_valid_uid = 1000
mbox_write_locks = fcntl
EOF

cat > /etc/dovecot/conf.d/10-master.conf <<EOF
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
  }
  user = dovecot
}

service auth-worker {
  user = vmail
}
EOF

cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = required
ssl_cert = </etc/letsencrypt/live/${DOMAIN}/fullchain.pem
ssl_key = </etc/letsencrypt/live/${DOMAIN}/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_prefer_server_ciphers = yes
ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
EOF

# Create vmail user
echo_info "Creating vmail user..."
groupadd -g 5000 vmail || true
useradd -g vmail -u 5000 vmail -d /var/mail -s /usr/sbin/nologin || true
mkdir -p /var/mail/vhosts/${DOMAIN}
chown -R vmail:vmail /var/mail

# Get SSL certificate
echo_info "Obtaining SSL certificate..."
systemctl stop nginx || true
certbot certonly --standalone -d ${DOMAIN} --non-interactive --agree-tos -m ${ADMIN_EMAIL} || echo_warning "SSL certificate setup failed. Please configure manually."
systemctl start nginx || true

# Configure OpenDKIM
echo_info "Configuring OpenDKIM..."
mkdir -p /etc/opendkim/keys/${DOMAIN}
cat > /etc/opendkim.conf <<EOF
Syslog yes
SyslogSuccess yes
LogWhy yes
UMask 002
OversignHeaders From
Canonicalization relaxed/simple
Mode sv
SubDomains no
AutoRestart yes
AutoRestartRate 10/1M
Background yes
DNSTimeout 5
SignatureAlgorithm rsa-sha256
Socket inet:8891@127.0.0.1
PidFile /run/opendkim/opendkim.pid
TrustAnchorFile /usr/share/dns/root.key
UserID opendkim
KeyTable /etc/opendkim/key.table
SigningTable refile:/etc/opendkim/signing.table
ExternalIgnoreList /etc/opendkim/trusted.hosts
InternalHosts /etc/opendkim/trusted.hosts
EOF

cat > /etc/opendkim/key.table <<EOF
mail._domainkey.${DOMAIN} ${DOMAIN}:mail:/etc/opendkim/keys/${DOMAIN}/mail.private
EOF

cat > /etc/opendkim/signing.table <<EOF
*@${DOMAIN} mail._domainkey.${DOMAIN}
EOF

cat > /etc/opendkim/trusted.hosts <<EOF
127.0.0.1
localhost
${DOMAIN}
EOF

cd /etc/opendkim/keys/${DOMAIN}
opendkim-genkey -b 2048 -d ${DOMAIN} -D /etc/opendkim/keys/${DOMAIN} -s mail -v
chown -R opendkim:opendkim /etc/opendkim
chmod 600 /etc/opendkim/keys/${DOMAIN}/mail.private

echo_info "DKIM public key (add this as TXT record 'mail._domainkey.${DOMAIN}'):"
cat /etc/opendkim/keys/${DOMAIN}/mail.txt

# Save configuration
cat > /root/mail-server-config.txt <<EOF
=================================
Mail Server Configuration
=================================
Domain: ${DOMAIN}
Admin Email: ${ADMIN_EMAIL}

MySQL Root Password: ${MYSQL_ROOT_PASSWORD}
Mail Database Password: ${MAIL_DB_PASSWORD}

API Port: ${API_PORT}
API Token: ${API_TOKEN}

SMTP Ports:
- 25 (SMTP)
- 587 (Submission)
- 465 (SMTPS)

IMAP Ports:
- 143 (IMAP)
- 993 (IMAPS)

POP3 Ports:
- 110 (POP3)
- 995 (POP3S)

API Endpoint: http://${DOMAIN}:${API_PORT}

DKIM Record:
$(cat /etc/opendkim/keys/${DOMAIN}/mail.txt)

=================================
EOF

chmod 600 /root/mail-server-config.txt

echo_info "Configuration saved to /root/mail-server-config.txt"

# Restart services
echo_info "Restarting services..."
systemctl enable postfix dovecot opendkim
systemctl restart postfix dovecot opendkim

echo_info "SMTP server setup completed!"
echo_info "Starting API server setup..."

# Create API server script (will be created in next file)
