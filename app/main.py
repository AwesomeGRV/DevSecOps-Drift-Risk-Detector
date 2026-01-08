import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request
import uvicorn
import os
from typing import List, Optional
import json
import asyncio
from datetime import datetime

from core.drift_detector import DriftDetector
from core.security_analyzer import SecurityAnalyzer
from core.activity_analyzer import ActivityAnalyzer
from core.terraform_generator import TerraformGenerator
from models.drift_report import DriftReport

app = FastAPI(
    title="DevSecOps Drift Risk Detector",
    description="Production-ready configuration drift and security risk detection",
    version="1.0.0"
)

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

@app.post("/analyze")
async def analyze_drift(
    background_tasks: BackgroundTasks,
    terraform_file: Optional[UploadFile] = File(None),
    terraform_state: Optional[UploadFile] = File(None),
    cloud_config: UploadFile = File(...),
    activity_logs: Optional[UploadFile] = File(None),
    security_benchmarks: Optional[UploadFile] = File(None),
    git_history: Optional[UploadFile] = File(None)
):
    try:
        # Read uploaded files
        terraform_content = await terraform_file.read() if terraform_file else None
        terraform_state_content = await terraform_state.read() if terraform_state else None
        cloud_config_content = await cloud_config.read()
        activity_logs_content = await activity_logs.read() if activity_logs else None
        security_benchmarks_content = await security_benchmarks.read() if security_benchmarks else None
        git_history_content = await git_history.read() if git_history else None
        
        # Parse inputs
        terraform_config = json.loads(terraform_content.decode()) if terraform_content else None
        terraform_state_data = json.loads(terraform_state_content.decode()) if terraform_state_content else None
        cloud_resources = json.loads(cloud_config_content.decode())
        activity_data = json.loads(activity_logs_content.decode()) if activity_logs_content else None
        security_rules = json.loads(security_benchmarks_content.decode()) if security_benchmarks_content else None
        git_data = json.loads(git_history_content.decode()) if git_history_content else None
        
        # Perform analysis
        drift_results = await drift_detector.detect_drift(
            terraform_config, terraform_state_data, cloud_resources
        )
        
        security_results = await security_analyzer.analyze_security(
            cloud_resources, security_rules
        )
        
        activity_results = await activity_analyzer.analyze_activity(
            activity_data, git_data
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
        
        return JSONResponse(content=report_data)
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Analysis failed with error: {str(e)}")
        print(f"Full traceback: {error_details}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now()}

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
