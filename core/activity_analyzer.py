from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from models.drift_report import ActivityResult
import re

class ActivityAnalyzer:
    def __init__(self):
        self.confidence_thresholds = {
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4
        }
    
    async def analyze_activity(
        self, 
        activity_logs: Optional[Dict] = None, 
        git_history: Optional[Dict] = None
    ) -> ActivityResult:
        """Analyze activity logs and git history to determine who made changes"""
        
        who_changed = None
        when_changed = None
        change_source = "unknown"
        confidence_score = 0.0
        supporting_evidence = []
        
        # Analyze cloud activity logs
        if activity_logs:
            cloud_analysis = self._analyze_cloud_activity(activity_logs)
            if cloud_analysis['confidence'] > confidence_score:
                who_changed = cloud_analysis['who']
                when_changed = cloud_analysis['when']
                change_source = cloud_analysis['source']
                confidence_score = cloud_analysis['confidence']
                supporting_evidence.extend(cloud_analysis['evidence'])
        
        # Analyze git history
        if git_history:
            git_analysis = self._analyze_git_history(git_history)
            if git_analysis['confidence'] > confidence_score:
                who_changed = git_analysis['who']
                when_changed = git_analysis['when']
                change_source = git_analysis['source']
                confidence_score = git_analysis['confidence']
                supporting_evidence.extend(git_analysis['evidence'])
        
        return ActivityResult(
            who_changed_it=who_changed,
            when_it_changed=when_changed,
            change_source=change_source,
            confidence_score=confidence_score,
            supporting_evidence=supporting_evidence
        )
    
    def _analyze_cloud_activity(self, activity_logs: Dict) -> Dict[str, Any]:
        """Analyze cloud provider activity logs"""
        analysis = {
            'who': None,
            'when': None,
            'source': 'cloud_logs',
            'confidence': 0.0,
            'evidence': []
        }
        
        # Handle different log formats
        if 'CloudTrail' in activity_logs or 'Events' in activity_logs:
            analysis.update(self._analyze_aws_cloudtrail(activity_logs))
        elif 'AzureActivity' in activity_logs or 'activityLogs' in activity_logs:
            analysis.update(self._analyze_azure_activity(activity_logs))
        elif 'auditLogs' in activity_logs or 'activity' in activity_logs:
            analysis.update(self._analyze_gcp_activity(activity_logs))
        else:
            # Generic log analysis
            analysis.update(self._analyze_generic_logs(activity_logs))
        
        return analysis
    
    def _analyze_aws_cloudtrail(self, logs: Dict) -> Dict[str, Any]:
        """Analyze AWS CloudTrail logs"""
        events = logs.get('CloudTrail', logs.get('Events', []))
        
        if not events:
            return {'confidence': 0.0, 'evidence': ['No CloudTrail events found']}
        
        # Find recent modification events
        modification_events = []
        for event in events:
            if self._is_modification_event(event):
                modification_events.append(event)
        
        if not modification_events:
            return {'confidence': 0.0, 'evidence': ['No modification events found']}
        
        # Get most recent event
        latest_event = max(modification_events, key=lambda x: self._parse_timestamp(x.get('eventTime')))
        
        user_identity = latest_event.get('userIdentity', {})
        username = (user_identity.get('userName') or 
                   user_identity.get('principalId') or 
                   user_identity.get('arn', 'unknown'))
        
        evidence = [
            f"CloudTrail event: {latest_event.get('eventName', 'unknown')}",
            f"Source IP: {latest_event.get('sourceIPAddress', 'unknown')}",
            f"User Agent: {latest_event.get('userAgent', 'unknown')}"
        ]
        
        return {
            'who': username,
            'when': self._parse_timestamp(latest_event.get('eventTime')),
            'confidence': 0.9,
            'evidence': evidence
        }
    
    def _analyze_azure_activity(self, logs: Dict) -> Dict[str, Any]:
        """Analyze Azure Activity logs"""
        activities = logs.get('AzureActivity', logs.get('activityLogs', []))
        
        if not activities:
            return {'confidence': 0.0, 'evidence': ['No Azure activity logs found']}
        
        # Find recent modification activities
        modification_activities = []
        for activity in activities:
            if self._is_azure_modification(activity):
                modification_activities.append(activity)
        
        if not modification_activities:
            return {'confidence': 0.0, 'evidence': ['No modification activities found']}
        
        # Get most recent activity
        latest_activity = max(modification_activities, key=lambda x: self._parse_timestamp(x.get('timestamp')))
        
        caller = latest_activity.get('caller', 'unknown')
        username = caller.split('@')[0] if '@' in caller else caller
        
        evidence = [
            f"Operation: {latest_activity.get('operationName', {}).get('value', 'unknown')}",
            f"Category: {latest_activity.get('category', 'unknown')}",
            f"Resource: {latest_activity.get('resourceId', 'unknown')}"
        ]
        
        return {
            'who': username,
            'when': self._parse_timestamp(latest_activity.get('timestamp')),
            'confidence': 0.85,
            'evidence': evidence
        }
    
    def _analyze_gcp_activity(self, logs: Dict) -> Dict[str, Any]:
        """Analyze GCP audit logs"""
        audit_logs = logs.get('auditLogs', logs.get('activity', []))
        
        if not audit_logs:
            return {'confidence': 0.0, 'evidence': ['No GCP audit logs found']}
        
        # Find recent modification activities
        modification_logs = []
        for log_entry in audit_logs:
            if self._is_gcp_modification(log_entry):
                modification_logs.append(log_entry)
        
        if not modification_logs:
            return {'confidence': 0.0, 'evidence': ['No modification activities found']}
        
        # Get most recent log
        latest_log = max(modification_logs, key=lambda x: self._parse_timestamp(x.get('timestamp')))
        
        principal = latest_log.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail', 'unknown')
        username = principal.split('@')[0] if '@' in principal else principal
        
        evidence = [
            f"Method: {latest_log.get('protoPayload', {}).get('methodName', 'unknown')}",
            f"Resource: {latest_log.get('resource', {}).get('type', 'unknown')}",
            f"Service: {latest_log.get('protoPayload', {}).get('serviceName', 'unknown')}"
        ]
        
        return {
            'who': username,
            'when': self._parse_timestamp(latest_log.get('timestamp')),
            'confidence': 0.85,
            'evidence': evidence
        }
    
    def _analyze_generic_logs(self, logs: Dict) -> Dict[str, Any]:
        """Analyze generic log format"""
        entries = logs.get('entries', logs.get('logs', []))
        
        if not entries:
            return {'confidence': 0.0, 'evidence': ['No log entries found']}
        
        # Look for user patterns in logs
        user_patterns = [
            r'user[:\s]+(\w+)',
            r'username[:\s]+(\w+)',
            r'principal[:\s]+([\w.@-]+)',
            r'caller[:\s]+([\w.@-]+)'
        ]
        
        latest_entry = max(entries, key=lambda x: self._parse_timestamp(x.get('timestamp', x.get('time'))))
        
        username = 'unknown'
        for pattern in user_patterns:
            match = re.search(pattern, str(latest_entry), re.IGNORECASE)
            if match:
                username = match.group(1)
                break
        
        evidence = [
            f"Log entry: {str(latest_entry)[:200]}...",
            "Generic log analysis - lower confidence"
        ]
        
        return {
            'who': username,
            'when': self._parse_timestamp(latest_entry.get('timestamp', latest_entry.get('time'))),
            'confidence': 0.4,
            'evidence': evidence
        }
    
    def _analyze_git_history(self, git_history: Dict) -> Dict[str, Any]:
        """Analyze git commit history"""
        commits = git_history.get('commits', [])
        
        if not commits:
            return {'confidence': 0.0, 'evidence': ['No git history found']}
        
        # Find recent infrastructure-related commits
        infra_commits = []
        for commit in commits:
            if self._is_infrastructure_commit(commit):
                infra_commits.append(commit)
        
        if not infra_commits:
            return {'confidence': 0.0, 'evidence': ['No infrastructure commits found']}
        
        # Get most recent infrastructure commit
        latest_commit = max(infra_commits, key=lambda x: self._parse_timestamp(x.get('date', x.get('timestamp'))))
        
        author = latest_commit.get('author', {}).get('name', latest_commit.get('author', 'unknown'))
        email = latest_commit.get('author', {}).get('email', '')
        
        evidence = [
            f"Commit: {latest_commit.get('hash', latest_commit.get('sha', 'unknown'))[:8]}",
            f"Message: {latest_commit.get('message', 'No message')[:100]}",
            f"Files changed: {len(latest_commit.get('files', []))}"
        ]
        
        return {
            'who': f"{author} ({email})" if email else author,
            'when': self._parse_timestamp(latest_commit.get('date', latest_commit.get('timestamp'))),
            'source': 'git_history',
            'confidence': 0.7,
            'evidence': evidence
        }
    
    def _is_modification_event(self, event: Dict) -> bool:
        """Check if event is a modification event"""
        modification_actions = [
            'Create', 'Update', 'Modify', 'Delete', 'Attach', 'Detach',
            'Start', 'Stop', 'Reboot', 'Run', 'Execute'
        ]
        
        event_name = event.get('eventName', '')
        return any(action in event_name for action in modification_actions)
    
    def _is_azure_modification(self, activity: Dict) -> bool:
        """Check if Azure activity is a modification"""
        modification_operations = [
            'write', 'create', 'update', 'delete', 'action', 'start', 'stop'
        ]
        
        operation_name = activity.get('operationName', {}).get('value', '').lower()
        return any(op in operation_name for op in modification_operations)
    
    def _is_gcp_modification(self, log_entry: Dict) -> bool:
        """Check if GCP log entry is a modification"""
        modification_methods = [
            'create', 'update', 'delete', 'patch', 'insert', 'start', 'stop'
        ]
        
        method_name = log_entry.get('protoPayload', {}).get('methodName', '').lower()
        return any(method in method_name for method in modification_methods)
    
    def _is_infrastructure_commit(self, commit: Dict) -> bool:
        """Check if commit is infrastructure-related"""
        infra_indicators = [
            '.tf', '.tfvars', 'terraform', 'infrastructure', 'cloud',
            'deploy', 'resource', 'provider', 'module'
        ]
        
        commit_text = (
            commit.get('message', '') + ' ' + 
            ' '.join(f.get('filename', '') for f in commit.get('files', []))
        ).lower()
        
        return any(indicator in commit_text for indicator in infra_indicators)
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse various timestamp formats"""
        if not timestamp_str:
            return None
        
        # Common timestamp formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S%z'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        # Try to extract datetime from string
        try:
            # Simple regex to find datetime-like patterns
            date_pattern = r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'
            match = re.search(date_pattern, timestamp_str)
            if match:
                date_str = match.group()
                for fmt in formats:
                    try:
                        return datetime.strptime(date_str, fmt)
                    except ValueError:
                        continue
        except:
            pass
        
        return None
