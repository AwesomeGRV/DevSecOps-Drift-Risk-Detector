"""
Enhanced security module with latest best practices and modern security features
"""

import secrets
import hashlib
import hmac
import time
import ipaddress
import re
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import logging
from fastapi import HTTPException, status, Request
from slowapi.util import get_remote_address
import redis
import asyncio

class SecurityLevel(Enum):
    """Security levels for different operations"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_type: str
    severity: SecurityLevel
    user_id: Optional[str]
    ip_address: str
    timestamp: datetime
    details: Dict[str, Any]
    blocked: bool = False

class EnhancedSecurityValidator:
    """Enhanced security validator with modern security practices"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
        self.pwd_context = CryptContext(
            schemes=["bcrypt"], 
            deprecated="auto",
            bcrypt__rounds=12
        )
        self.logger = logging.getLogger(__name__)
        
        # Security patterns
        self.dangerous_patterns = [
            r'<script[^>]*>.*?</script>',  # XSS
            r'javascript:',                # JavaScript URLs
            r'on\w+\s*=',                 # Event handlers
            r'expression\s*\(',           # CSS expressions
            r'@import',                   # CSS imports
        ]
        
        # SQL injection patterns
        self.sql_injection_patterns = [
            r'(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)',
            r'(--|\#|\/\*|\*\/)',         # SQL comments
            r'(\|\|)',                    # SQL concatenation
            r'(\'\s*;)',                  # String termination
        ]
        
        # Rate limiting configurations
        self.rate_limits = {
            'auth': {'requests': 5, 'window': 300},      # 5 requests per 5 minutes
            'upload': {'requests': 10, 'window': 60},    # 10 uploads per minute
            'analysis': {'requests': 3, 'window': 300},  # 3 analyses per 5 minutes
            'api': {'requests': 100, 'window': 60},     # 100 API calls per minute
        }
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    def hash_password(self, password: str) -> str:
        """Hash password with bcrypt"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return self.pwd_context.verify(password, hashed)
    
    def create_jwt_token(self, payload: Dict[str, Any], expires_in: int = 1800) -> str:
        """Create JWT token with enhanced security"""
        now = datetime.utcnow()
        payload.update({
            'iat': now,
            'exp': now + timedelta(seconds=expires_in),
            'jti': self.generate_secure_token(16),  # Unique token ID
            'iss': 'drift-detector',
            'aud': 'drift-detector-users'
        })
        
        # Use stronger secret key
        secret_key = secrets.token_bytes(64)
        token = jwt.encode(payload, secret_key, algorithm='HS256')
        
        # Store token in Redis for revocation support
        if self.redis_client:
            self.redis_client.setex(
                f"token:{payload['jti']}", 
                expires_in, 
                json.dumps({'user_id': payload.get('sub'), 'created': now.isoformat()})
            )
        
        return token
    
    def verify_jwt_token(self, token: str, secret_key: str) -> Dict[str, Any]:
        """Verify JWT token with enhanced security checks"""
        try:
            payload = jwt.decode(
                token, 
                secret_key, 
                algorithms=['HS256'],
                options={
                    'require': ['exp', 'iat', 'jti', 'iss', 'aud'],
                    'verify_iat': True,
                    'verify_exp': True,
                    'verify_iss': True,
                    'verify_aud': True
                }
            )
            
            # Check if token is revoked
            if self.redis_client:
                token_data = self.redis_client.get(f"token:{payload['jti']}")
                if not token_data:
                    raise jwt.InvalidTokenError("Token revoked")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )
    
    def validate_file_content(self, content: bytes, filename: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Enhanced file content validation"""
        metadata = {
            'filename': filename,
            'size': len(content),
            'content_type': self._detect_content_type(content),
            'hash': self._calculate_file_hash(content),
            'validation_timestamp': datetime.utcnow().isoformat()
        }
        
        # Size validation (max 100MB)
        if len(content) > 100 * 1024 * 1024:
            return False, "File size exceeds 100MB limit", metadata
        
        # File type validation
        allowed_extensions = {'.json', '.hcl', '.tf', '.tfstate', '.yml', '.yaml', '.log'}
        file_ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
        
        if file_ext not in allowed_extensions:
            return False, f"File type {file_ext} not allowed", metadata
        
        # Content validation
        try:
            content_str = content.decode('utf-8')
            
            # Check for malicious patterns
            for pattern in self.dangerous_patterns:
                if re.search(pattern, content_str, re.IGNORECASE):
                    return False, f"Potentially dangerous content detected: {pattern}", metadata
            
            # SQL injection check
            for pattern in self.sql_injection_patterns:
                if re.search(pattern, content_str, re.IGNORECASE):
                    return False, f"SQL injection pattern detected: {pattern}", metadata
            
            # JSON structure validation for JSON files
            if file_ext in ['.json', '.tfstate']:
                try:
                    json.loads(content_str)
                except json.JSONDecodeError as e:
                    return False, f"Invalid JSON format: {str(e)}", metadata
            
        except UnicodeDecodeError:
            return False, "File contains invalid character encoding", metadata
        
        return True, "File validation passed", metadata
    
    def _detect_content_type(self, content: bytes) -> str:
        """Detect content type from file bytes"""
        try:
            import magic
            return magic.from_buffer(content, mime=True)
        except ImportError:
            # Fallback to basic detection
            if content.startswith(b'{'):
                return 'application/json'
            elif content.startswith(b'provider'):
                return 'text/hcl'
            else:
                return 'text/plain'
    
    def _calculate_file_hash(self, content: bytes) -> str:
        """Calculate SHA-256 hash of file content"""
        return hashlib.sha256(content).hexdigest()
    
    def sanitize_input(self, input_data: Any, max_length: int = 10000) -> Tuple[bool, Any, str]:
        """Sanitize and validate input data"""
        try:
            if isinstance(input_data, str):
                # Length validation
                if len(input_data) > max_length:
                    return False, None, f"Input exceeds maximum length of {max_length} characters"
                
                # Remove potentially dangerous characters
                sanitized = re.sub(r'[<>"\'&]', '', input_data)
                
                # Check for remaining dangerous patterns
                for pattern in self.dangerous_patterns:
                    if re.search(pattern, sanitized, re.IGNORECASE):
                        return False, None, f"Potentially dangerous content detected: {pattern}"
                
                return True, sanitized, "Input sanitized successfully"
            
            elif isinstance(input_data, dict):
                # Recursively sanitize dictionary values
                sanitized_dict = {}
                for key, value in input_data.items():
                    is_valid, sanitized_value, error = self.sanitize_input(value, max_length)
                    if not is_valid:
                        return False, None, f"Error in field '{key}': {error}"
                    sanitized_dict[key] = sanitized_value
                
                return True, sanitized_dict, "Dictionary sanitized successfully"
            
            elif isinstance(input_data, list):
                # Recursively sanitize list items
                sanitized_list = []
                for i, item in enumerate(input_data):
                    is_valid, sanitized_item, error = self.sanitize_input(item, max_length)
                    if not is_valid:
                        return False, None, f"Error in item {i}: {error}"
                    sanitized_list.append(sanitized_item)
                
                return True, sanitized_list, "List sanitized successfully"
            
            else:
                # For other types, just ensure it's not dangerous
                return True, input_data, "Input validated successfully"
                
        except Exception as e:
            return False, None, f"Input sanitization error: {str(e)}"
    
    async def check_rate_limit(self, request: Request, operation: str) -> Tuple[bool, Dict[str, Any]]:
        """Enhanced rate limiting with Redis backend"""
        if not self.redis_client:
            return True, {"message": "Rate limiting not available"}
        
        client_ip = get_remote_address(request)
        rate_config = self.rate_limits.get(operation, self.rate_limits['api'])
        
        key = f"rate_limit:{operation}:{client_ip}"
        
        try:
            # Get current count
            current_count = self.redis_client.get(key)
            current_count = int(current_count) if current_count else 0
            
            if current_count >= rate_config['requests']:
                # Check if window has expired
                ttl = self.redis_client.ttl(key)
                if ttl <= 0:
                    # Reset counter
                    self.redis_client.setex(key, rate_config['window'], 1)
                    return True, {"remaining": rate_config['requests'] - 1}
                else:
                    return False, {
                        "error": "Rate limit exceeded",
                        "retry_after": ttl,
                        "limit": rate_config['requests'],
                        "window": rate_config['window']
                    }
            
            # Increment counter
            new_count = self.redis_client.incr(key)
            if new_count == 1:
                self.redis_client.expire(key, rate_config['window'])
            
            return True, {
                "remaining": rate_config['requests'] - new_count,
                "limit": rate_config['requests'],
                "window": rate_config['window']
            }
            
        except Exception as e:
            self.logger.error(f"Rate limiting error: {e}")
            return True, {"message": "Rate limiting error, allowing request"}
    
    def detect_anomalies(self, request: Request, user_id: Optional[str] = None) -> List[SecurityEvent]:
        """Detect security anomalies in requests"""
        events = []
        client_ip = get_remote_address(request)
        
        # Check for suspicious user agents
        user_agent = request.headers.get('user-agent', '')
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan']
        for agent in suspicious_agents:
            if agent.lower() in user_agent.lower():
                events.append(SecurityEvent(
                    event_type="suspicious_user_agent",
                    severity=SecurityLevel.HIGH,
                    user_id=user_id,
                    ip_address=client_ip,
                    timestamp=datetime.utcnow(),
                    details={"user_agent": user_agent, "pattern": agent},
                    blocked=True
                ))
        
        # Check for missing required headers
        required_headers = ['host', 'user-agent']
        for header in required_headers:
            if header not in request.headers:
                events.append(SecurityEvent(
                    event_type="missing_header",
                    severity=SecurityLevel.MEDIUM,
                    user_id=user_id,
                    ip_address=client_ip,
                    timestamp=datetime.utcnow(),
                    details={"missing_header": header}
                ))
        
        # Check for IP reputation (placeholder for actual IP reputation service)
        if self._is_suspicious_ip(client_ip):
            events.append(SecurityEvent(
                event_type="suspicious_ip",
                severity=SecurityLevel.HIGH,
                user_id=user_id,
                ip_address=client_ip,
                timestamp=datetime.utcnow(),
                details={"ip": client_ip},
                blocked=True
            ))
        
        return events
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious (placeholder for IP reputation service)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private ranges (should not be accessible from internet in production)
            if ip_obj.is_private:
                return False
            
            # Check for known malicious ranges (placeholder)
            malicious_ranges = [
                '192.0.2.0/24',  # TEST-NET-1
                '198.51.100.0/24',  # TEST-NET-2
                '203.0.113.0/24',   # TEST-NET-3
            ]
            
            for range_str in malicious_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return True
            
            return False
            
        except ValueError:
            return True  # Invalid IP is suspicious
    
    def encrypt_sensitive_data(self, data: str, password: str) -> str:
        """Encrypt sensitive data using Fernet"""
        try:
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'drift_detector_salt',  # In production, use random salt
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            f = Fernet(key)
            encrypted_data = f.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
            
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            raise ValueError("Failed to encrypt data")
    
    def decrypt_sensitive_data(self, encrypted_data: str, password: str) -> str:
        """Decrypt sensitive data using Fernet"""
        try:
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'drift_detector_salt',  # In production, use random salt
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            f = Fernet(key)
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = f.decrypt(decoded_data)
            return decrypted_data.decode()
            
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            raise ValueError("Failed to decrypt data")
    
    def log_security_event(self, event: SecurityEvent):
        """Log security event with structured logging"""
        event_data = {
            "event_type": event.event_type,
            "severity": event.severity.value,
            "user_id": event.user_id,
            "ip_address": event.ip_address,
            "timestamp": event.timestamp.isoformat(),
            "details": event.details,
            "blocked": event.blocked
        }
        
        if event.severity in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
            self.logger.error(f"Security Event: {json.dumps(event_data)}")
        else:
            self.logger.warning(f"Security Event: {json.dumps(event_data)}")
        
        # Store in Redis for analysis
        if self.redis_client:
            self.redis_client.lpush(
                "security_events",
                json.dumps(event_data)
            )
            # Keep only last 1000 events
            self.redis_client.ltrim("security_events", 0, 999)

# Global enhanced security instance
enhanced_security = EnhancedSecurityValidator()
