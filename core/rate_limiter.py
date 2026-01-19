import time
import redis
import asyncio
from typing import Dict, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading
import logging
from fastapi import HTTPException, status
import os
import hashlib

logger = logging.getLogger(__name__)

class RateLimiter:
    """Advanced rate limiting with multiple strategies"""
    
    def __init__(self):
        self.redis_client = self._init_redis()
        self.use_redis = self.redis_client is not None
        
        # In-memory fallback
        self.memory_store = defaultdict(lambda: deque())
        self.memory_lock = threading.Lock()
        
        # Rate limiting configurations
        self.limits = {
            'default': {'requests': 60, 'window': 60},  # 60 requests per minute
            'upload': {'requests': 10, 'window': 60},   # 10 uploads per minute
            'analysis': {'requests': 5, 'window': 300}, # 5 analyses per 5 minutes
            'auth': {'requests': 5, 'window': 300},     # 5 auth attempts per 5 minutes
            'api': {'requests': 100, 'window': 60},     # 100 API calls per minute
        }
        
        # DDoS protection thresholds
        self.ddos_thresholds = {
            'burst_requests': 50,      # 50 requests in 10 seconds
            'burst_window': 10,
            'sustained_requests': 200, # 200 requests in 1 minute
            'sustained_window': 60,
            'blacklist_duration': 3600  # 1 hour blacklist
        }
    
    def _init_redis(self):
        """Initialize Redis client"""
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
            client = redis.from_url(redis_url, decode_responses=True)
            client.ping()  # Test connection
            return client
        except Exception as e:
            logger.warning(f"Redis not available, using in-memory rate limiting: {e}")
            return None
    
    def is_allowed(self, key: str, limit_type: str = 'default') -> Tuple[bool, Dict]:
        """
        Check if request is allowed based on rate limits
        
        Returns:
            Tuple[is_allowed, rate_limit_info]
        """
        limit_config = self.limits.get(limit_type, self.limits['default'])
        
        if self.use_redis:
            return self._redis_rate_limit(key, limit_config)
        else:
            return self._memory_rate_limit(key, limit_config)
    
    def _redis_rate_limit(self, key: str, limit_config: Dict) -> Tuple[bool, Dict]:
        """Redis-based rate limiting with sliding window"""
        try:
            now = int(time.time())
            window = limit_config['window']
            max_requests = limit_config['requests']
            
            # Use Redis sorted set for sliding window
            redis_key = f"rate_limit:{hashlib.md5(key.encode()).hexdigest()}"
            
            # Remove old entries
            self.redis_client.zremrangebyscore(redis_key, 0, now - window)
            
            # Count current requests
            current_requests = self.redis_client.zcard(redis_key)
            
            if current_requests >= max_requests:
                # Get TTL for the oldest request
                oldest_request = self.redis_client.zrange(redis_key, 0, 0, withscores=True)
                ttl = int(oldest_request[0][1]) + window - now if oldest_request else window
                
                return False, {
                    'allowed': False,
                    'limit': max_requests,
                    'remaining': 0,
                    'reset_time': now + ttl,
                    'retry_after': ttl
                }
            
            # Add current request
            self.redis_client.zadd(redis_key, {str(now): now})
            self.redis_client.expire(redis_key, window)
            
            return True, {
                'allowed': True,
                'limit': max_requests,
                'remaining': max_requests - current_requests - 1,
                'reset_time': now + window,
                'retry_after': 0
            }
            
        except Exception as e:
            logger.error(f"Redis rate limiting error: {e}")
            # Fallback to memory-based limiting
            return self._memory_rate_limit(key, limit_config)
    
    def _memory_rate_limit(self, key: str, limit_config: Dict) -> Tuple[bool, Dict]:
        """In-memory rate limiting (fallback)"""
        now = time.time()
        window = limit_config['window']
        max_requests = limit_config['requests']
        
        with self.memory_lock:
            requests = self.memory_store[key]
            
            # Remove old requests
            while requests and requests[0] <= now - window:
                requests.popleft()
            
            current_requests = len(requests)
            
            if current_requests >= max_requests:
                # Calculate retry after
                oldest_request = requests[0] if requests else now
                retry_after = int(oldest_request + window - now)
                
                return False, {
                    'allowed': False,
                    'limit': max_requests,
                    'remaining': 0,
                    'reset_time': now + retry_after,
                    'retry_after': retry_after
                }
            
            # Add current request
            requests.append(now)
            
            return True, {
                'allowed': True,
                'limit': max_requests,
                'remaining': max_requests - current_requests - 1,
                'reset_time': now + window,
                'retry_after': 0
            }
    
    def check_ddos_protection(self, identifier: str) -> Tuple[bool, Optional[str]]:
        """
        Check for DDoS patterns and blacklist if necessary
        
        Returns:
            Tuple[is_allowed, reason_if_blocked]
        """
        if not self.use_redis:
            return True, None
        
        try:
            now = int(time.time())
            
            # Check if already blacklisted
            blacklist_key = f"blacklist:{identifier}"
            if self.redis_client.exists(blacklist_key):
                ttl = self.redis_client.ttl(blacklist_key)
                return False, f"Rate limited. Try again in {ttl} seconds."
            
            # Check burst requests
            burst_key = f"burst:{identifier}"
            self.redis_client.zremrangebyscore(burst_key, 0, now - self.ddos_thresholds['burst_window'])
            burst_count = self.redis_client.zcard(burst_key)
            
            if burst_count >= self.ddos_thresholds['burst_requests']:
                self.redis_client.setex(blacklist_key, self.ddos_thresholds['blacklist_duration'], "ddos")
                logger.warning(f"DDoS protection triggered - burst: {identifier}")
                return False, f"Too many requests. Blocked for {self.ddos_thresholds['blacklist_duration']} seconds."
            
            # Check sustained requests
            sustained_key = f"sustained:{identifier}"
            self.redis_client.zremrangebyscore(sustained_key, 0, now - self.ddos_thresholds['sustained_window'])
            sustained_count = self.redis_client.zcard(sustained_key)
            
            if sustained_count >= self.ddos_thresholds['sustained_requests']:
                self.redis_client.setex(blacklist_key, self.ddos_thresholds['blacklist_duration'], "ddos")
                logger.warning(f"DDoS protection triggered - sustained: {identifier}")
                return False, f"Too many requests. Blocked for {self.ddos_thresholds['blacklist_duration']} seconds."
            
            # Record current request
            self.redis_client.zadd(burst_key, {str(now): now})
            self.redis_client.expire(burst_key, self.ddos_thresholds['burst_window'])
            self.redis_client.zadd(sustained_key, {str(now): now})
            self.redis_client.expire(sustained_key, self.ddos_thresholds['sustained_window'])
            
            return True, None
            
        except Exception as e:
            logger.error(f"DDoS protection error: {e}")
            return True, None
    
    def get_rate_limit_headers(self, rate_info: Dict) -> Dict[str, str]:
        """Generate rate limit headers for HTTP response"""
        headers = {}
        
        if rate_info.get('limit'):
            headers['X-RateLimit-Limit'] = str(rate_info['limit'])
        if rate_info.get('remaining') is not None:
            headers['X-RateLimit-Remaining'] = str(rate_info['remaining'])
        if rate_info.get('reset_time'):
            headers['X-RateLimit-Reset'] = str(rate_info['reset_time'])
        if rate_info.get('retry_after'):
            headers['Retry-After'] = str(rate_info['retry_after'])
        
        return headers
    
    def cleanup_expired_keys(self):
        """Cleanup expired keys (for memory-based storage)"""
        if self.use_redis:
            return  # Redis handles expiration automatically
        
        now = time.time()
        with self.memory_lock:
            for key, requests in list(self.memory_store.items()):
                while requests and requests[0] <= now - 300:  # 5 minutes cleanup window
                    requests.popleft()
                
                if not requests:
                    del self.memory_store[key]

class RateLimitMiddleware:
    """FastAPI middleware for rate limiting"""
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
    
    async def check_rate_limit(self, request, limit_type: str = 'default'):
        """Check rate limit for incoming request"""
        # Get client identifier
        client_ip = self._get_client_ip(request)
        user_id = getattr(request.state, 'user_id', None)
        
        # Create rate limit key
        if user_id:
            key = f"user:{user_id}:{limit_type}"
        else:
            key = f"ip:{client_ip}:{limit_type}"
        
        # Check DDoS protection
        is_allowed, reason = self.rate_limiter.check_ddos_protection(client_ip)
        if not is_allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=reason,
                headers=self.rate_limiter.get_rate_limit_headers({'retry_after': 3600})
            )
        
        # Check rate limits
        allowed, rate_info = self.rate_limiter.is_allowed(key, limit_type)
        
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers=self.rate_limiter.get_rate_limit_headers(rate_info)
            )
        
        return rate_info
    
    def _get_client_ip(self, request):
        """Extract client IP from request"""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"

# Global rate limiter instance
rate_limiter = RateLimiter()

# Background task for cleanup
async def cleanup_task():
    """Background task to cleanup expired rate limit entries"""
    while True:
        await asyncio.sleep(300)  # Run every 5 minutes
        rate_limiter.cleanup_expired_keys()
