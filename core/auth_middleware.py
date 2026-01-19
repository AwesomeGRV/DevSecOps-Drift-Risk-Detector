import os
import jwt
import redis
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import JWTError, jwt
import logging
import hashlib
import secrets

logger = logging.getLogger(__name__)

class AuthManager:
    """Comprehensive authentication and authorization management"""
    
    def __init__(self):
        self.secret_key = os.getenv('JWT_SECRET_KEY', self._generate_secret_key())
        self.algorithm = "HS256"
        self.access_token_expire_minutes = int(os.getenv('TOKEN_EXPIRE_MINUTES', '30'))
        self.redis_client = self._init_redis()
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.security = HTTPBearer()
        
        # Rate limiting
        self.max_requests_per_minute = int(os.getenv('MAX_REQUESTS_PER_MINUTE', '60'))
        self.max_login_attempts = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
        self.lockout_duration_minutes = int(os.getenv('LOCKOUT_DURATION_MINUTES', '15'))
    
    def _generate_secret_key(self) -> str:
        """Generate a secure secret key if not provided"""
        return secrets.token_urlsafe(32)
    
    def _init_redis(self):
        """Initialize Redis for session management and rate limiting"""
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
            return redis.from_url(redis_url, decode_responses=True)
        except Exception as e:
            logger.warning(f"Redis not available, using in-memory storage: {e}")
            return None
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Generate password hash"""
        return self.pwd_context.hash(password)
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        
        # Store token in Redis for revocation support
        if self.redis_client:
            token_key = f"token:{hashlib.sha256(encoded_jwt.encode()).hexdigest()}"
            self.redis_client.setex(token_key, self.access_token_expire_minutes * 60, "active")
        
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            # Check if token is revoked in Redis
            if self.redis_client:
                token_key = f"token:{hashlib.sha256(token.encode()).hexdigest()}"
                if not self.redis_client.exists(token_key):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token has been revoked",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError:
            return None
    
    def is_rate_limited(self, identifier: str, window_seconds: int = 60) -> bool:
        """Check if identifier is rate limited"""
        if not self.redis_client:
            return False
        
        key = f"rate_limit:{identifier}"
        current_requests = self.redis_client.get(key)
        
        if current_requests is None:
            # First request in window
            self.redis_client.setex(key, window_seconds, 1)
            return False
        elif int(current_requests) >= self.max_requests_per_minute:
            return True
        else:
            self.redis_client.incr(key)
            return False
    
    def is_account_locked(self, identifier: str) -> bool:
        """Check if account is locked due to failed login attempts"""
        if not self.redis_client:
            return False
        
        lock_key = f"account_lock:{identifier}"
        return self.redis_client.exists(lock_key)
    
    def record_failed_login(self, identifier: str):
        """Record failed login attempt"""
        if not self.redis_client:
            return
        
        attempts_key = f"login_attempts:{identifier}"
        attempts = self.redis_client.incr(attempts_key)
        
        if attempts >= self.max_login_attempts:
            # Lock the account
            lock_key = f"account_lock:{identifier}"
            self.redis_client.setex(lock_key, self.lockout_duration_minutes * 60, "locked")
            self.redis_client.delete(attempts_key)
        else:
            # Set expiry for attempts counter
            self.redis_client.expire(attempts_key, self.lockout_duration_minutes * 60)
    
    def clear_login_attempts(self, identifier: str):
        """Clear failed login attempts on successful login"""
        if not self.redis_client:
            return
        
        attempts_key = f"login_attempts:{identifier}"
        self.redis_client.delete(attempts_key)
    
    def revoke_token(self, token: str):
        """Revoke a JWT token"""
        if self.redis_client:
            token_key = f"token:{hashlib.sha256(token.encode()).hexdigest()}"
            self.redis_client.delete(token_key)
    
    def get_user_permissions(self, user_id: str) -> list:
        """Get user permissions from storage"""
        if not self.redis_client:
            return ["read", "analyze"]  # Default permissions
        
        permissions_key = f"user_permissions:{user_id}"
        permissions = self.redis_client.smembers(permissions_key)
        return list(permissions) if permissions else ["read", "analyze"]
    
    def has_permission(self, user_id: str, required_permission: str) -> bool:
        """Check if user has required permission"""
        user_permissions = self.get_user_permissions(user_id)
        return required_permission in user_permissions

class SecurityMiddleware:
    """Security middleware for FastAPI application"""
    
    def __init__(self, auth_manager: AuthManager):
        self.auth_manager = auth_manager
    
    async def authenticate_request(self, request: Request, credentials: HTTPAuthorizationCredentials) -> Dict[str, Any]:
        """Authenticate incoming request"""
        token = credentials.credentials
        payload = self.auth_manager.verify_token(token)
        
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check rate limiting
        client_ip = self._get_client_ip(request)
        user_id = payload.get("sub")
        
        if self.auth_manager.is_rate_limited(f"{client_ip}:{user_id}"):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        
        return payload
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"

def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract auth_manager and user_info from kwargs
            auth_manager = kwargs.get('auth_manager')
            user_info = kwargs.get('user_info')
            
            if not auth_manager or not user_info:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            user_id = user_info.get("sub")
            if not auth_manager.has_permission(user_id, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{permission}' required"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

# Security headers configuration
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
}

def add_security_headers(response):
    """Add security headers to response"""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response
