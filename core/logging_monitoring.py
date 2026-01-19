import logging
import logging.handlers
import json
import time
import traceback
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import structlog
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import os

# Prometheus metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')
SECURITY_VIOLATIONS = Counter('security_violations_total', 'Total security violations', ['type'])
ANALYSIS_COUNT = Counter('analysis_total', 'Total drift analyses performed', ['result'])
ACTIVE_USERS = Gauge('active_users', 'Number of active users')
FILE_UPLOADS = Counter('file_uploads_total', 'Total file uploads', ['file_type', 'validation_result'])

class SecurityLogger:
    """Enhanced logging with security focus"""
    
    def __init__(self):
        self.setup_logging()
        self.setup_structlog()
    
    def setup_logging(self):
        """Setup comprehensive logging configuration"""
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Configure root logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.handlers.RotatingFileHandler(
                    log_dir / "app.log",
                    maxBytes=10*1024*1024,  # 10MB
                    backupCount=5
                ),
                logging.handlers.RotatingFileHandler(
                    log_dir / "security.log",
                    maxBytes=10*1024*1024,
                    backupCount=5
                ),
                logging.StreamHandler()
            ]
        )
        
        # Security-specific logger
        self.security_logger = logging.getLogger('security')
        security_handler = logging.handlers.RotatingFileHandler(
            log_dir / "security.log",
            maxBytes=10*1024*1024,
            backupCount=5
        )
        security_handler.setFormatter(
            logging.Formatter('%(asctime)s - SECURITY - %(levelname)s - %(message)s')
        )
        self.security_logger.addHandler(security_handler)
        self.security_logger.setLevel(logging.INFO)
        
        # Audit logger
        self.audit_logger = logging.getLogger('audit')
        audit_handler = logging.handlers.RotatingFileHandler(
            log_dir / "audit.log",
            maxBytes=10*1024*1024,
            backupCount=10
        )
        audit_handler.setFormatter(
            logging.Formatter('%(asctime)s - AUDIT - %(message)s')
        )
        self.audit_logger.addHandler(audit_handler)
        self.audit_logger.setLevel(logging.INFO)
    
    def setup_structlog(self):
        """Setup structured logging"""
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log security events"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "details": details
        }
        
        self.security_logger.log(
            getattr(logging, severity.upper()),
            json.dumps(event)
        )
        
        # Update Prometheus metrics
        SECURITY_VIOLATIONS.labels(type=event_type).inc()
    
    def log_audit_event(self, user_id: str, action: str, resource: str, result: str, details: Optional[Dict] = None):
        """Log audit events"""
        audit_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "result": result,
            "details": details or {}
        }
        
        self.audit_logger.info(json.dumps(audit_event))
    
    def log_file_upload(self, user_id: str, filename: str, file_size: int, validation_result: str, metadata: Dict):
        """Log file upload events"""
        self.log_audit_event(
            user_id=user_id,
            action="file_upload",
            resource=filename,
            result=validation_result,
            details={
                "file_size": file_size,
                "metadata": metadata
            }
        )
        
        # Update metrics
        file_type = Path(filename).suffix.lower()
        FILE_UPLOADS.labels(file_type=file_type, validation_result=validation_result).inc()
    
    def log_analysis_event(self, user_id: str, analysis_type: str, result: str, duration: float, details: Dict):
        """Log drift analysis events"""
        self.log_audit_event(
            user_id=user_id,
            action="drift_analysis",
            resource=analysis_type,
            result=result,
            details={
                "duration_seconds": duration,
                "details": details
            }
        )
        
        # Update metrics
        ANALYSIS_COUNT.labels(result=result).inc()

class MetricsCollector:
    """Collect and expose application metrics"""
    
    def __init__(self):
        self.metrics_port = int(os.getenv('METRICS_PORT', '9090'))
        self.start_metrics_server()
    
    def start_metrics_server(self):
        """Start Prometheus metrics server"""
        try:
            start_http_server(self.metrics_port)
            print(f"Prometheus metrics server started on port {self.metrics_port}")
        except Exception as e:
            print(f"Failed to start metrics server: {e}")
    
    def record_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record HTTP request metrics"""
        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status_code).inc()
        REQUEST_DURATION.observe(duration)
    
    def update_active_users(self, count: int):
        """Update active users gauge"""
        ACTIVE_USERS.set(count)

class SecurityMonitor:
    """Monitor security events and anomalies"""
    
    def __init__(self, security_logger: SecurityLogger):
        self.logger = security_logger
        self.suspicious_patterns = {
            'multiple_failed_logins': 5,
            'large_file_uploads': 50 * 1024 * 1024,  # 50MB
            'rapid_requests': 100,  # requests per minute
            'unusual_time_access': {'start': 22, 'end': 6}  # 10 PM to 6 AM
        }
    
    def detect_suspicious_activity(self, event_type: str, details: Dict[str, Any]) -> bool:
        """Detect suspicious activity patterns"""
        is_suspicious = False
        
        if event_type == "login_attempt":
            if details.get("failed", False):
                failed_attempts = details.get("failed_attempts", 1)
                if failed_attempts >= self.suspicious_patterns['multiple_failed_logins']:
                    is_suspicious = True
                    self.logger.log_security_event(
                        "multiple_failed_logins",
                        {
                            "user_id": details.get("user_id"),
                            "ip_address": details.get("ip_address"),
                            "failed_attempts": failed_attempts
                        },
                        "WARNING"
                    )
        
        elif event_type == "file_upload":
            file_size = details.get("file_size", 0)
            if file_size > self.suspicious_patterns['large_file_uploads']:
                is_suspicious = True
                self.logger.log_security_event(
                    "large_file_upload",
                    {
                        "user_id": details.get("user_id"),
                        "filename": details.get("filename"),
                        "file_size": file_size
                    },
                    "WARNING"
                )
        
        elif event_type == "api_request":
            current_hour = datetime.now().hour
            unusual_hours = self.suspicious_patterns['unusual_time_access']
            if unusual_hours['start'] <= current_hour or current_hour <= unusual_hours['end']:
                is_suspicious = True
                self.logger.log_security_event(
                    "unusual_time_access",
                    {
                        "user_id": details.get("user_id"),
                        "endpoint": details.get("endpoint"),
                        "hour": current_hour
                    },
                    "INFO"
                )
        
        return is_suspicious
    
    def check_rate_limiting(self, user_id: str, endpoint: str, current_count: int) -> bool:
        """Check if rate limiting threshold is exceeded"""
        if current_count > self.suspicious_patterns['rapid_requests']:
            self.logger.log_security_event(
                "rate_limit_exceeded",
                {
                    "user_id": user_id,
                    "endpoint": endpoint,
                    "request_count": current_count
                },
                "WARNING"
            )
            return True
        return False

# Initialize logging and monitoring
security_logger = SecurityLogger()
metrics_collector = MetricsCollector()
security_monitor = SecurityMonitor(security_logger)

# Export for use in other modules
__all__ = ['security_logger', 'metrics_collector', 'security_monitor']
