from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class DriftReport(BaseModel):
    timestamp: datetime
    summary: str
    drift_detected: bool
    risk_level: RiskLevel
    affected_resources: List[str]
    what_changed: Dict[str, Any]
    who_changed_it: Optional[str]
    when_it_changed: Optional[datetime]
    why_this_is_risky: str
    recommended_fix: str
    terraform_remediation: Optional[str]
    preventive_controls: List[str]
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class DriftResult(BaseModel):
    drift_detected: bool
    affected_resources: List[str]
    what_changed: Dict[str, Any]
    missing_resources: List[str]
    extra_resources: List[str]
    configuration_changes: Dict[str, Dict[str, Any]]

class SecurityResult(BaseModel):
    risk_level: RiskLevel
    why_this_is_risky: str
    recommended_fix: str
    preventive_controls: List[str]
    security_violations: List[Dict[str, Any]]
    compliance_gaps: List[str]

class ActivityResult(BaseModel):
    who_changed_it: Optional[str]
    when_it_changed: Optional[datetime]
    change_source: str  # "manual", "pipeline", "unknown"
    confidence_score: float  # 0.0 to 1.0
    supporting_evidence: List[str]
