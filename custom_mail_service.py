#!/usr/bin/env python3
"""
Custom Mail Service for Stoat Account Generator
Uses custom SMTP server API
"""
import requests
import time
import random
import string
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class CustomMailService:
    """Handle temporary email operations using custom SMTP server"""
    
    def __init__(self, api_url: str = "http://157.245.52.81:8080", domain: str = "apps.tokyo"):
        self.api_url = api_url.rstrip('/')
        self.domain = domain
        self.email = None
        self.session = requests.Session()
        logger.info(f"Initialized CustomMailService with API: {api_url}, domain: {domain}")
        
    def generate_random_alias(self, length: int = 10) -> str:
        """Generate a random email alias"""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choices(chars, k=length))
        
    def generate_email(self) -> str:
        """Generate a temporary email address"""
        alias = self.generate_random_alias()
        self.email = f"{alias}@{self.domain}"
        logger.info(f"✓ Generated email: {self.email}")
        return self.email
    
    def get_messages(self, email_address: Optional[str] = None) -> list:
        """Get all messages for the specified email"""
        if not email_address:
            email_address = self.email
            
        if not email_address:
            return []
        
        try:
            # Query custom SMTP server API
            response = self.session.get(
                f"{self.api_url}/api/emails/{email_address}",
                timeout=10
            )
            
            if response.status_code == 200:
                messages = response.json()
                logger.debug(f"Found {len(messages)} messages for {email_address}")
                return messages
            else:
                logger.debug(f"API returned status {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Failed to get messages: {e}")
            return []
    
    def get_verification_token(self, email_address: Optional[str] = None) -> Optional[str]:
        """Get verification token for the specified email"""
        if not email_address:
            email_address = self.email
            
        if not email_address:
            return None
        
        try:
            # Query token endpoint
            response = self.session.get(
                f"{self.api_url}/api/token/{email_address}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'token' in data:
                    token = data['token']
                    logger.info(f"✓ Found verification token: {token[:20]}...")
                    return token
            
            return None
        except Exception as e:
            logger.error(f"Failed to get token: {e}")
            return None
    
    def wait_for_verification_email(self, timeout: int = 120, check_interval: int = 5) -> Optional[Dict[str, str]]:
        """Wait for verification email and extract the token"""
        logger.info(f"Waiting for verification email to {self.email}...")
        logger.info(f"Check status at: {self.api_url}")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # Try to get token directly
                token = self.get_verification_token(self.email)
                
                if token:
                    logger.info(f"✓ Verification token found!")
                    return {
                        "type": "token",
                        "value": token,
                        "full_link": f"https://stoat.chat/auth/account/verify/{token}"
                    }
                
                # Check messages
                messages = self.get_messages(self.email)
                
                if messages:
                    logger.debug(f"Found {len(messages)} message(s), checking for verification...")
                    
                    for message in messages:
                        sender = str(message.get('from', '')).lower()
                        
                        # Look for stoat.chat email
                        if 'stoat' in sender or 'revolt' in sender or 'noreply' in sender:
                            logger.info(f"✓ Verification email found from {sender}")
                            
                            token = message.get('token')
                            if token:
                                return {
                                    "type": "token",
                                    "value": token,
                                    "full_link": f"https://stoat.chat/auth/account/verify/{token}"
                                }
                
                logger.debug(f"No verification email yet, waiting {check_interval}s...")
                
            except Exception as e:
                logger.debug(f"Error checking messages: {e}")
            
            time.sleep(check_interval)
        
        logger.error("Timeout waiting for verification email")
        return None


if __name__ == "__main__":
    # Test the mail service
    logging.basicConfig(level=logging.DEBUG)
    
    service = CustomMailService()
    email = service.generate_email()
    
    print(f"\nGenerated email: {email}")
    print(f"Waiting for messages...")
    print(f"Send test email to: {email}")
    print(f"Check web interface: {service.api_url}")
    
    # Wait for test email
    result = service.wait_for_verification_email(timeout=300)
    
    if result:
        print(f"\n✓ Received: {result}")
    else:
        print(f"\n✗ No email received")
