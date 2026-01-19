import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from core.security_validator import SecurityValidator
from core.auth_middleware import AuthManager
from core.rate_limiter import RateLimiter
from app.main import app

class TestSecurityValidator:
    """Test security validation functionality"""
    
    def setup_method(self):
        self.validator = SecurityValidator()
    
    def test_valid_json_file(self):
        """Test validation of valid JSON file"""
        valid_json = {"test": "data", "number": 123}
        content = json.dumps(valid_json).encode()
        
        is_valid, error_msg, metadata = self.validator.validate_file_upload(
            content, "test.json"
        )
        
        assert is_valid is True
        assert error_msg is None
        assert metadata is not None
        assert metadata['file_extension'] == '.json'
        assert metadata['file_size'] == len(content)
    
    def test_invalid_file_extension(self):
        """Test rejection of invalid file extension"""
        content = b"test content"
        
        is_valid, error_msg, metadata = self.validator.validate_file_upload(
            content, "test.exe"
        )
        
        assert is_valid is False
        assert "File extension" in error_msg
        assert metadata is None
    
    def test_file_size_limit(self):
        """Test file size limit enforcement"""
        # Create content larger than limit
        large_content = b"x" * (200 * 1024 * 1024)  # 200MB
        
        is_valid, error_msg, metadata = self.validator.validate_file_upload(
            large_content, "large.json"
        )
        
        assert is_valid is False
        assert "File size exceeds" in error_msg
    
    def test_xss_detection(self):
        """Test XSS pattern detection"""
        xss_content = '{"test": "<script>alert(\"xss\")</script>"}'.encode()
        
        is_valid, error_msg, metadata = self.validator.validate_file_upload(
            xss_content, "test.json"
        )
        
        assert is_valid is False
        assert "dangerous content" in error_msg
    
    def test_sensitive_data_masking(self):
        """Test sensitive data detection and masking"""
        content_with_secrets = '''
        {
            "api_key": "AKIAIOSFODNN7EXAMPLE",
            "password": "secret123",
            "normal_data": "safe"
        }
        '''.encode()
        
        is_valid, error_msg, metadata = self.validator.validate_file_upload(
            content_with_secrets, "config.json"
        )
        
        assert is_valid is True
        assert metadata['sensitive_data_detected'] is True
        assert metadata['sensitive_findings_count'] > 0
    
    def test_json_sanitization(self):
        """Test JSON input sanitization"""
        malicious_json = {
            "normal_key": "normal_value",
            "script<xss>": "<script>alert('xss')</script>",
            "null_byte": "test\x00value",
            "nested": {
                "safe": "value",
                "dangerous": "javascript:alert(1)"
            }
        }
        
        is_valid, sanitized, error = self.validator.sanitize_json_input(malicious_json)
        
        assert is_valid is True
        assert error is None
        assert "\x00" not in str(sanitized)
        assert "javascript:" not in str(sanitized)
    
    def test_cloud_config_schema_validation(self):
        """Test cloud configuration schema validation"""
        valid_config = {
            "aws_instance": {
                "web_server": {
                    "instance_type": "t3.micro",
                    "ami": "ami-12345678"
                }
            },
            "aws_s3_bucket": {
                "data_bucket": {
                    "bucket": "my-bucket",
                    "acl": "private"
                }
            }
        }
        
        is_valid, error_msg = self.validator.validate_cloud_config_schema(valid_config)
        
        assert is_valid is True
        assert error_msg is None
    
    def test_invalid_cloud_config_schema(self):
        """Test invalid cloud configuration schema"""
        invalid_config = {
            "invalid_resource": {
                "test": "value"
            }
        }
        
        is_valid, error_msg = self.validator.validate_cloud_config_schema(invalid_config)
        
        assert is_valid is False
        assert "Invalid resource type prefix" in error_msg

class TestAuthManager:
    """Test authentication and authorization"""
    
    def setup_method(self):
        self.auth_manager = AuthManager()
    
    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "test_password_123"
        hashed = self.auth_manager.get_password_hash(password)
        
        assert hashed != password
        assert self.auth_manager.verify_password(password, hashed) is True
        assert self.auth_manager.verify_password("wrong_password", hashed) is False
    
    def test_token_creation_and_verification(self):
        """Test JWT token creation and verification"""
        user_data = {"sub": "testuser", "permissions": ["read", "analyze"]}
        token = self.auth_manager.create_access_token(user_data)
        
        assert token is not None
        assert isinstance(token, str)
        
        payload = self.auth_manager.verify_token(token)
        assert payload is not None
        assert payload["sub"] == "testuser"
        assert "read" in payload["permissions"]
    
    def test_invalid_token_verification(self):
        """Test invalid token verification"""
        invalid_token = "invalid.token.here"
        
        payload = self.auth_manager.verify_token(invalid_token)
        assert payload is None
    
    def test_permission_checking(self):
        """Test permission checking"""
        user_id = "testuser"
        
        # Test default permissions
        assert self.auth_manager.has_permission(user_id, "read") is True
        assert self.auth_manager.has_permission(user_id, "analyze") is True
        assert self.auth_manager.has_permission(user_id, "admin") is False

class TestRateLimiter:
    """Test rate limiting functionality"""
    
    def setup_method(self):
        self.rate_limiter = RateLimiter()
    
    def test_rate_limit_allowance(self):
        """Test rate limiting allows requests within limit"""
        key = "test_key"
        
        # First request should be allowed
        is_allowed, info = self.rate_limiter.is_allowed(key, 'default')
        assert is_allowed is True
        assert info['remaining'] >= 0
    
    def test_rate_limit_exceeded(self):
        """Test rate limiting blocks requests exceeding limit"""
        key = "test_key_exceed"
        
        # Make requests up to the limit
        limit_config = self.rate_limiter.limits['default']
        for _ in range(limit_config['requests']):
            self.rate_limiter.is_allowed(key, 'default')
        
        # Next request should be blocked
        is_allowed, info = self.rate_limiter.is_allowed(key, 'default')
        assert is_allowed is False
        assert info['remaining'] == 0
        assert info['retry_after'] > 0
    
    def test_ddos_protection(self):
        """Test DDoS protection triggers"""
        identifier = "test_ddos"
        
        # Simulate burst requests
        for _ in range(self.rate_limiter.ddos_thresholds['burst_requests']):
            self.rate_limiter.check_ddos_protection(identifier)
        
        # Next request should be blocked
        is_allowed, reason = self.rate_limiter.check_ddos_protection(identifier)
        assert is_allowed is False
        assert "Too many requests" in reason

class TestAPISecurity:
    """Test API security endpoints and middleware"""
    
    def setup_method(self):
        self.client = TestClient(app)
    
    def test_login_endpoint(self):
        """Test login endpoint with valid credentials"""
        with patch.dict(os.environ, {
            'ADMIN_USERNAME': 'testuser',
            'ADMIN_PASSWORD': 'testpass'
        }):
            response = self.client.post("/login", json={
                "username": "testuser",
                "password": "testpass"
            })
            
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
    
    def test_login_invalid_credentials(self):
        """Test login endpoint with invalid credentials"""
        response = self.client.post("/login", json={
            "username": "wronguser",
            "password": "wrongpass"
        })
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    def test_protected_endpoint_without_auth(self):
        """Test accessing protected endpoint without authentication"""
        response = self.client.get("/user/profile")
        
        assert response.status_code == 403
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = self.client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "security" in data
        assert "metrics" in data
    
    def test_security_headers(self):
        """Test security headers are present"""
        response = self.client.get("/health")
        
        assert response.status_code == 200
        headers = response.headers
        assert "X-Content-Type-Options" in headers
        assert "X-Frame-Options" in headers
        assert "X-XSS-Protection" in headers
        assert "Strict-Transport-Security" in headers

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
