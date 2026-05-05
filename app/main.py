import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Depends, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic_settings import BaseSettings
import uvicorn
import os
from typing import List, Optional
import json
import asyncio
from datetime import datetime
import time
import logging
from contextlib import asynccontextmanager

from core.drift_detector import DriftDetector
from core.security_analyzer import SecurityAnalyzer
from core.activity_analyzer import ActivityAnalyzer
from core.terraform_generator import TerraformGenerator
from core.enhanced_security import enhanced_security, SecurityEvent, SecurityLevel
from core.observability import observability_manager, setup_observability_middleware
from core.auth_middleware import AuthManager, SecurityMiddleware, add_security_headers, require_permission
from core.logging_monitoring import security_logger, metrics_collector, security_monitor
from core.rate_limiter import RateLimitMiddleware, rate_limiter
from models.drift_report import DriftReport

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
import psutil

# OpenTelemetry setup
def setup_telemetry():
    """Setup OpenTelemetry for observability"""
    trace.set_tracer_provider(TracerProvider())
    tracer = trace.get_tracer(__name__)
    
    metric_reader = PrometheusMetricReader()
    meter_provider = MeterProvider(metric_readers=[metric_reader])
    
    return tracer, meter_provider

# Settings management
class Settings(BaseSettings):
    """Application settings with environment variable support"""
    app_name: str = "DevSecOps Drift Risk Detector"
    version: str = "3.0.0"
    environment: str = "development"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Security settings
    jwt_secret_key: str = "your-super-secret-jwt-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30
    
    # Rate limiting
    max_requests_per_minute: int = 60
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    
    # File upload
    max_file_size: str = "100MB"
    allowed_extensions: str = ".json,.hcl,.tf,.tfstate,.yml,.yaml"
    
    # CORS
    allowed_origins: str = "http://localhost:3000,http://localhost:8000"
    allowed_hosts: str = "*"
    
    # Redis
    redis_url: str = "redis://localhost:6379"
    
    # Metrics
    metrics_port: int = 9090
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    tracer, meter_provider = setup_telemetry()
    
    # Initialize monitoring
    metrics_collector.start_monitoring()
    
    # Log startup
    security_logger.log_audit_event(
        user_id="system",
        action="application_startup",
        resource="system",
        result="success",
        details={
            "version": settings.version,
            "environment": settings.environment,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        }
    )
    
    yield
    
    # Shutdown
    security_logger.log_audit_event(
        user_id="system",
        action="application_shutdown",
        resource="system",
        result="success"
    )

app = FastAPI(
    title=settings.app_name,
    description="Production-ready configuration drift and security risk detection with enhanced observability",
    version=settings.version,
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
    lifespan=lifespan,
    contact={
        "name": "DevSecOps Team",
        "email": "security@company.com"
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    }
)

# Instrument FastAPI with OpenTelemetry
FastAPIInstrumentor.instrument_app(app)
LoggingInstrumentor.instrument()

# Initialize security components
auth_manager = AuthManager()
security_middleware = SecurityMiddleware(auth_manager)
rate_limit_middleware = RateLimitMiddleware(rate_limiter)
security_validator = enhanced_security

# Setup observability middleware
setup_observability_middleware(app)

# Add security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts.split(",")
)

# Add HTTPS redirect middleware in production
if settings.environment == "production":
    app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    return add_security_headers(response)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Log request
    security_logger.log_audit_event(
        user_id=getattr(request.state, 'user_id', 'anonymous'),
        action="api_request",
        resource=f"{request.method} {request.url.path}",
        result="initiated",
        details={"client_ip": request.client.host if request.client else "unknown"}
    )
    
    response = await call_next(request)
    
    # Log response
    duration = time.time() - start_time
    metrics_collector.record_request(
        method=request.method,
        endpoint=request.url.path,
        status_code=response.status_code,
        duration=duration
    )
    
    return response

# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize core components
drift_detector = DriftDetector()
security_analyzer = SecurityAnalyzer()
activity_analyzer = ActivityAnalyzer()
terraform_generator = TerraformGenerator()

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.post("/login")
async def login(request: Request, credentials: dict):
    """Authenticate user and return JWT token"""
    try:
        username = credentials.get("username")
        password = credentials.get("password")
        
        if not username or not password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username and password required"
            )
        
        # Check rate limiting for auth
        await rate_limit_middleware.check_rate_limit(request, 'auth')
        
        # Check account lockout
        client_ip = request.client.host if request.client else "unknown"
        if auth_manager.is_account_locked(username):
            security_logger.log_security_event(
                "login_blocked",
                {"username": username, "ip_address": client_ip},
                "WARNING"
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account temporarily locked due to multiple failed attempts"
            )
        
        # Validate credentials (in production, use proper user database)
        # For demo, using environment variables
        valid_username = os.getenv("ADMIN_USERNAME", "admin")
        valid_password_hash = auth_manager.get_password_hash(os.getenv("ADMIN_PASSWORD", "admin123"))
        
        if username == valid_username and auth_manager.verify_password(password, valid_password_hash):
            # Clear failed login attempts
            auth_manager.clear_login_attempts(username)
            
            # Create access token
            access_token = auth_manager.create_access_token(
                data={"sub": username, "permissions": ["read", "analyze", "admin"]}
            )
            
            security_logger.log_audit_event(
                user_id=username,
                action="login",
                resource="authentication",
                result="success",
                details={"ip_address": client_ip}
            )
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": auth_manager.access_token_expire_minutes * 60
            }
        else:
            # Record failed login
            auth_manager.record_failed_login(username)
            
            security_logger.log_security_event(
                "login_failed",
                {"username": username, "ip_address": client_ip},
                "WARNING"
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    except HTTPException:
        raise
    except Exception as e:
        security_logger.log_security_event(
            "login_error",
            {"error": str(e), "username": username},
            "ERROR"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )

@app.post("/analyze")
async def analyze_drift(
    background_tasks: BackgroundTasks,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(auth_manager.security),
    terraform_file: Optional[UploadFile] = File(None),
    terraform_state: Optional[UploadFile] = File(None),
    cloud_config: UploadFile = File(...),
    activity_logs: Optional[UploadFile] = File(None),
    security_benchmarks: Optional[UploadFile] = File(None),
    git_history: Optional[UploadFile] = File(None)
):
    """Analyze drift and security with comprehensive validation"""
    try:
        # Authenticate request
        user_info = await security_middleware.authenticate_request(request, credentials)
        user_id = user_info.get("sub")
        
        # Enhanced anomaly detection
        security_events = enhanced_security.detect_anomalies(request, user_id)
        for event in security_events:
            enhanced_security.log_security_event(event)
            observability_manager.record_security_event(event.event_type, event.severity.value)
            
            if event.blocked:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Request blocked due to suspicious activity"
                )
        
        # Check rate limiting with enhanced security
        rate_info = await enhanced_security.check_rate_limit(request, 'analysis')
        if not rate_info.get('success', True):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=rate_info.get('error', 'Rate limit exceeded')
            )
        
        # Validate permissions
        if not auth_manager.has_permission(user_id, "analyze"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Analysis permission required"
            )
        
        start_time = time.time()
        validation_results = []
        
        # Validate and process uploaded files
        files_to_process = {
            'terraform_file': terraform_file,
            'terraform_state': terraform_state,
            'cloud_config': cloud_config,
            'activity_logs': activity_logs,
            'security_benchmarks': security_benchmarks,
            'git_history': git_history
        }
        
        validated_files = {}
        for file_type, file_obj in files_to_process.items():
            if file_obj:
                # Check rate limiting for uploads
                await rate_limit_middleware.check_rate_limit(request, 'upload')
                
                file_content = await file_obj.read()
                # Enhanced file validation
                is_valid, error_msg, metadata = enhanced_security.validate_file_content(
                    file_content, file_obj.filename
                )
                
                validation_results.append({
                    'filename': file_obj.filename,
                    'is_valid': is_valid,
                    'error_message': error_msg,
                    'metadata': metadata
                })
                
                if not is_valid:
                    security_logger.log_file_upload(
                        user_id=user_id,
                        filename=file_obj.filename,
                        file_size=len(file_content),
                        validation_result="failed",
                        metadata={"error": error_msg}
                    )
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"File validation failed for {file_obj.filename}: {error_msg}"
                    )
                
                # Sanitize content
                try:
                    if file_type == 'cloud_config':
                        json_content = json.loads(file_content.decode())
                        is_valid, sanitized_content, error = enhanced_security.sanitize_input(json_content)
                        if not is_valid:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Content sanitization failed: {error}"
                            )
                        validated_files[file_type] = sanitized_content
                    else:
                        # Sanitize text content
                        is_valid, sanitized_content, error = enhanced_security.sanitize_input(file_content.decode())
                        if not is_valid:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Content sanitization failed: {error}"
                            )
                        validated_files[file_type] = sanitized_content
                    
                    security_logger.log_file_upload(
                        user_id=user_id,
                        filename=file_obj.filename,
                        file_size=len(file_content),
                        validation_result="success",
                        metadata=metadata or {}
                    )
                    
                except json.JSONDecodeError as e:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid JSON in {file_obj.filename}: {str(e)}"
                    )
        
        # Enhanced cloud configuration schema validation
        if 'cloud_config' in validated_files:
            # Additional schema validation logic here
            is_valid, error_msg = True, None  # Placeholder for actual schema validation
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Cloud configuration schema error: {error_msg}"
                )
        
        # Perform analysis
        drift_results = await drift_detector.detect_drift(
            validated_files.get('terraform_file'),
            validated_files.get('terraform_state'),
            validated_files['cloud_config']
        )
        
        security_results = await security_analyzer.analyze_security(
            validated_files['cloud_config'],
            json.loads(validated_files.get('security_benchmarks', '{}'))
        )
        
        activity_results = await activity_analyzer.analyze_activity(
            json.loads(validated_files.get('activity_logs', '{}')),
            json.loads(validated_files.get('git_history', '{}'))
        )
        
        # Generate comprehensive report
        summary = f"Drift detected: {drift_results.drift_detected}, Risk level: {security_results.risk_level}, Resources affected: {len(drift_results.affected_resources)}"
        
        report = DriftReport(
            timestamp=datetime.now(),
            summary=summary,
            drift_detected=drift_results.drift_detected,
            risk_level=security_results.risk_level,
            affected_resources=drift_results.affected_resources,
            what_changed=drift_results.what_changed,
            who_changed_it=activity_results.who_changed_it,
            when_it_changed=activity_results.when_it_changed,
            why_this_is_risky=security_results.why_this_is_risky,
            recommended_fix=security_results.recommended_fix,
            terraform_remediation=await terraform_generator.generate_remediation(drift_results),
            preventive_controls=security_results.preventive_controls
        )
        
        # Convert to JSON-serializable dict manually
        report_data = report.model_dump()
        if report_data.get('when_it_changed'):
            report_data['when_it_changed'] = report_data['when_it_changed'].isoformat()
        if report_data.get('timestamp'):
            report_data['timestamp'] = report_data['timestamp'].isoformat()
        
        # Add validation summary
        report_data['security_validation'] = {
            'validation_results': validation_results,
            'total_files': len(validation_results),
            'valid_files': len([r for r in validation_results if r['is_valid']]),
            'invalid_files': len([r for r in validation_results if not r['is_valid']])
        }
        report_data['rate_limit'] = rate_info
        
        # Log successful analysis with enhanced metrics
        duration = time.time() - start_time
        observability_manager.record_analysis("success", security_results.risk_level.value)
        security_logger.log_analysis_event(
            user_id=user_id,
            analysis_type="drift_security",
            result="success",
            duration=duration,
            details={
                "drift_detected": drift_results.drift_detected,
                "risk_level": security_results.risk_level.value,
                "affected_resources": len(drift_results.affected_resources),
                "security_events": len(security_events) if 'security_events' in locals() else 0
            }
        )
        
        return JSONResponse(
            content=report_data,
            headers={
                "X-RateLimit-Limit": str(rate_info.get('limit', 60)),
                "X-RateLimit-Remaining": str(rate_info.get('remaining', 59)),
                "X-RateLimit-Reset": str(int(time.time()) + rate_info.get('window', 60)),
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        security_logger.log_security_event(
            "analysis_error",
            {"error": str(e), "user_id": user_id, "traceback": error_details},
            "ERROR"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed. Please try again later."
        )

@app.get("/health")
async def health_check():
    """Enhanced health check with system status"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": settings.version,
        "environment": settings.environment,
        "uptime_seconds": time.time() - start_time if 'start_time' in globals() else 0,
        "system": {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage_percent": psutil.disk_usage('/').percent
        },
        "security": {
            "rate_limiting": "active",
            "authentication": "required",
            "validation": "enabled",
            "middleware_count": len(app.middleware_stack)
        },
        "metrics": {
            "prometheus": f"http://localhost:{settings.metrics_port}/metrics",
            "tracing": "enabled",
            "logging": "structured"
        }
    }

@app.get("/user/profile")
async def get_user_profile(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(auth_manager.security)
):
    """Get current user profile"""
    user_info = await security_middleware.authenticate_request(request, credentials)
    user_id = user_info.get("sub")
    
    return {
        "user_id": user_id,
        "permissions": auth_manager.get_user_permissions(user_id),
        "token_expires": user_info.get("exp")
    }

@app.post("/logout")
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(auth_manager.security)
):
    """Logout user and revoke token"""
    user_info = await security_middleware.authenticate_request(request, credentials)
    user_id = user_info.get("sub")
    
    # Revoke token
    auth_manager.revoke_token(credentials.credentials)
    
    security_logger.log_audit_event(
        user_id=user_id,
        action="logout",
        resource="authentication",
        result="success"
    )
    
    return {"message": "Successfully logged out"}

if __name__ == "__main__":
    # Record start time
    start_time = time.time()
    
    # Start cleanup task
    asyncio.create_task(cleanup_task())
    
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info" if not settings.debug else "debug",
        access_log=True,
        workers=1 if settings.debug else 4,
        limit_concurrency=100,
        timeout_keep_alive=30
    )
