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
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn
import os
from typing import List, Optional
import json
import asyncio
from datetime import datetime
import time
import logging

from core.drift_detector import DriftDetector
from core.security_analyzer import SecurityAnalyzer
from core.activity_analyzer import ActivityAnalyzer
from core.terraform_generator import TerraformGenerator
from core.security_validator import SecurityValidator
from core.auth_middleware import AuthManager, SecurityMiddleware, add_security_headers, require_permission
from core.logging_monitoring import security_logger, metrics_collector, security_monitor
from core.rate_limiter import RateLimitMiddleware, rate_limiter
from models.drift_report import DriftReport

app = FastAPI(
    title="DevSecOps Drift Risk Detector",
    description="Production-ready configuration drift and security risk detection",
    version="2.0.0",
    docs_url="/docs" if os.getenv("ENVIRONMENT") != "production" else None,
    redoc_url="/redoc" if os.getenv("ENVIRONMENT") != "production" else None
)

# Initialize security components
auth_manager = AuthManager()
security_middleware = SecurityMiddleware(auth_manager)
rate_limit_middleware = RateLimitMiddleware(rate_limiter)
security_validator = SecurityValidator()

# Add security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.getenv("ALLOWED_HOSTS", "*").split(",")
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
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
        
        # Check rate limiting for analysis
        rate_info = await rate_limit_middleware.check_rate_limit(request, 'analysis')
        
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
                is_valid, error_msg, metadata = security_validator.validate_file_upload(
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
                        is_valid, sanitized_content, error = security_validator.sanitize_json_input(json_content)
                        if not is_valid:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Content sanitization failed: {error}"
                            )
                        validated_files[file_type] = sanitized_content
                    else:
                        validated_files[file_type] = file_content.decode()
                    
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
        
        # Validate cloud configuration schema
        if 'cloud_config' in validated_files:
            is_valid, error_msg = security_validator.validate_cloud_config_schema(validated_files['cloud_config'])
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
        security_report = security_validator.generate_security_report(validation_results)
        report_data['security_validation'] = security_report
        report_data['rate_limit'] = rate_info
        
        # Log successful analysis
        duration = time.time() - start_time
        security_logger.log_analysis_event(
            user_id=user_id,
            analysis_type="drift_security",
            result="success",
            duration=duration,
            details={
                "drift_detected": drift_results.drift_detected,
                "risk_level": security_results.risk_level.value,
                "affected_resources": len(drift_results.affected_resources)
            }
        )
        
        return JSONResponse(
            content=report_data,
            headers=rate_limiter.get_rate_limit_headers(rate_info)
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
        "version": "2.0.0",
        "security": {
            "rate_limiting": "active",
            "authentication": "required",
            "validation": "enabled"
        },
        "metrics": {
            "prometheus": f"http://localhost:{os.getenv('METRICS_PORT', '9090')}/metrics"
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
    # Start cleanup task
    asyncio.create_task(cleanup_task())
    
    uvicorn.run(
        "app.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("DEBUG", "false").lower() == "true",
        log_level="info",
        access_log=True
    )
