import os
import json
import magic
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import re
import logging

logger = logging.getLogger(__name__)

class SecurityValidator:
    """Comprehensive input validation and sanitization for security"""
    
    def __init__(self):
        self.allowed_mime_types = {
            'application/json',
            'text/plain',
            'application/x-hcl',
            'application/tf',
            'application/tfstate'
        }
        
        self.allowed_extensions = {
            '.json', '.hcl', '.tf', '.tfstate', '.yml', '.yaml'
        }
        
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        
        self.dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',  # onclick, onload, etc.
            r'eval\s*\(',
            r'document\.',
            r'window\.',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'Function\s*\(',
            r'RegExp\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'exec\s*\(',
            r'shell_exec\s*\(',
            r'passthru\s*\(',
            r'file_get_contents\s*\(',
            r'fopen\s*\(',
            r'unlink\s*\(',
            r'rmdir\s*\(',
            r'mkdir\s*\(',
            r'chmod\s*\(',
            r'chown\s*\(',
        ]
        
        self.sensitive_data_patterns = [
            r'(?:password|passwd|pwd|secret|token|key|api_key|access_key|secret_key)[\'"\s]*[:=][\'"\s]*([^\s\'"]+)',
            r'(?:AKIA|ASIA)[A-Z0-9]{16}',  # AWS Access Key
            r'[A-Za-z0-9/+=]{40}',  # AWS Secret Key pattern
            r'ghp_[A-Za-z0-9]{36}',  # GitHub Personal Access Token
            r'xoxb-[0-9]{10}-[0-9]{10}-[A-Za-z0-9]{24}',  # Slack Bot Token
            r'sk-[A-Za-z0-9]{48}',  # Stripe Secret Key
        ]
    
    def validate_file_upload(self, file_content: bytes, filename: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Comprehensive file validation for security
        
        Returns:
            Tuple[is_valid, error_message, sanitized_metadata]
        """
        try:
            # Check file size
            if len(file_content) > self.max_file_size:
                return False, f"File size exceeds maximum limit of {self.max_file_size // (1024*1024)}MB", None
            
            # Check file extension
            file_ext = Path(filename).suffix.lower()
            if file_ext not in self.allowed_extensions:
                return False, f"File extension '{file_ext}' not allowed. Allowed: {', '.join(self.allowed_extensions)}", None
            
            # Check MIME type
            mime_type = magic.from_buffer(file_content, mime=True)
            if mime_type not in self.allowed_mime_types:
                # For text files, magic might return text/plain instead of application/json
                if mime_type not in ['text/plain', 'application/octet-stream']:
                    return False, f"File type '{mime_type}' not allowed", None
            
            # Scan for dangerous content patterns
            content_str = file_content.decode('utf-8', errors='ignore')
            
            # Check for XSS/injection patterns
            for pattern in self.dangerous_patterns:
                if re.search(pattern, content_str, re.IGNORECASE | re.DOTALL):
                    logger.warning(f"Dangerous pattern detected in file {filename}: {pattern}")
                    return False, f"File contains potentially dangerous content", None
            
            # Detect and mask sensitive data
            masked_content, sensitive_findings = self._mask_sensitive_data(content_str)
            
            # Validate JSON structure if it's a JSON file
            if file_ext in ['.json', '.tfstate']:
                try:
                    json.loads(masked_content)
                except json.JSONDecodeError as e:
                    return False, f"Invalid JSON format: {str(e)}", None
            
            # Generate file hash for integrity
            file_hash = hashlib.sha256(file_content).hexdigest()
            
            metadata = {
                'original_filename': filename,
                'file_size': len(file_content),
                'mime_type': mime_type,
                'file_extension': file_ext,
                'content_hash': file_hash,
                'sensitive_data_detected': len(sensitive_findings) > 0,
                'sensitive_findings_count': len(sensitive_findings),
                'validation_timestamp': self._get_timestamp()
            }
            
            return True, None, metadata
            
        except Exception as e:
            logger.error(f"File validation error: {str(e)}")
            return False, f"Validation error: {str(e)}", None
    
    def sanitize_json_input(self, json_data: Any) -> Tuple[bool, Any, Optional[str]]:
        """
        Sanitize JSON input data
        
        Returns:
            Tuple[is_valid, sanitized_data, error_message]
        """
        try:
            if isinstance(json_data, dict):
                sanitized = {}
                for key, value in json_data.items():
                    # Sanitize keys
                    safe_key = self._sanitize_string(key)
                    if not safe_key:
                        continue
                    
                    # Recursively sanitize values
                    is_valid, safe_value, error = self.sanitize_json_input(value)
                    if not is_valid:
                        return False, None, error
                    
                    sanitized[safe_key] = safe_value
                
                return True, sanitized, None
            
            elif isinstance(json_data, list):
                sanitized = []
                for item in json_data:
                    is_valid, safe_item, error = self.sanitize_json_input(item)
                    if not is_valid:
                        return False, None, error
                    sanitized.append(safe_item)
                
                return True, sanitized, None
            
            elif isinstance(json_data, str):
                return True, self._sanitize_string(json_data), None
            
            else:
                # Numbers, booleans, null are safe as-is
                return True, json_data, None
                
        except Exception as e:
            return False, None, f"JSON sanitization error: {str(e)}"
    
    def _sanitize_string(self, input_str: str) -> str:
        """Sanitize string input"""
        if not isinstance(input_str, str):
            return str(input_str)
        
        # Remove null bytes
        sanitized = input_str.replace('\x00', '')
        
        # Normalize whitespace
        sanitized = ' '.join(sanitized.split())
        
        # Limit string length
        max_length = 10000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + '... [truncated]'
        
        return sanitized
    
    def _mask_sensitive_data(self, content: str) -> Tuple[str, List[Dict]]:
        """Detect and mask sensitive data patterns"""
        masked_content = content
        findings = []
        
        for pattern in self.sensitive_data_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                finding = {
                    'pattern': pattern,
                    'start': match.start(),
                    'end': match.end(),
                    'matched_text': match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0)
                }
                findings.append(finding)
                
                # Mask the sensitive data
                mask = '*' * (match.end() - match.start())
                masked_content = masked_content[:match.start()] + mask + masked_content[match.end():]
        
        return masked_content, findings
    
    def validate_cloud_config_schema(self, config: Dict) -> Tuple[bool, Optional[str]]:
        """Validate cloud configuration schema"""
        try:
            if not isinstance(config, dict):
                return False, "Configuration must be a JSON object"
            
            # Check for required structure
            if not config:
                return False, "Configuration cannot be empty"
            
            # Validate resource types
            valid_prefixes = ['aws_', 'azurerm_', 'google_']
            for resource_type in config.keys():
                if not any(resource_type.startswith(prefix) for prefix in valid_prefixes):
                    return False, f"Invalid resource type prefix: {resource_type}"
            
            # Check for nested structure validity
            for resource_type, resources in config.items():
                if not isinstance(resources, (dict, list)):
                    return False, f"Resources for {resource_type} must be an object or array"
                
                if isinstance(resources, dict):
                    for resource_name, resource_config in resources.items():
                        if not isinstance(resource_config, dict):
                            return False, f"Resource configuration for {resource_name} must be an object"
            
            return True, None
            
        except Exception as e:
            return False, f"Schema validation error: {str(e)}"
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'
    
    def generate_security_report(self, validation_results: List[Dict]) -> Dict:
        """Generate security validation report"""
        total_files = len(validation_results)
        valid_files = sum(1 for r in validation_results if r.get('is_valid', False))
        sensitive_detections = sum(r.get('sensitive_data_detected', 0) for r in validation_results)
        
        return {
            'validation_summary': {
                'total_files': total_files,
                'valid_files': valid_files,
                'invalid_files': total_files - valid_files,
                'sensitive_data_detections': sensitive_detections
            },
            'security_level': 'HIGH' if valid_files == total_files and sensitive_detections == 0 else 'MEDIUM' if valid_files > 0 else 'LOW',
            'recommendations': self._generate_security_recommendations(validation_results)
        }
    
    def _generate_security_recommendations(self, validation_results: List[Dict]) -> List[str]:
        """Generate security recommendations based on validation results"""
        recommendations = []
        
        # Check for common issues
        for result in validation_results:
            if result.get('sensitive_data_detected'):
                recommendations.append("Remove sensitive data from configuration files and use secure credential management")
            
            if not result.get('is_valid', False):
                recommendations.append("Fix file format and structure issues before processing")
        
        # General recommendations
        if not recommendations:
            recommendations.append("All files passed security validation")
        
        recommendations.extend([
            "Regularly rotate access keys and secrets",
            "Implement least-privilege access controls",
            "Use encrypted storage for sensitive configurations"
        ])
        
        return list(set(recommendations))  # Remove duplicates
