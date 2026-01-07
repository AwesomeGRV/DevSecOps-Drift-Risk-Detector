from typing import Dict, List, Any, Optional
from models.drift_report import SecurityResult, RiskLevel
import re

class SecurityAnalyzer:
    def __init__(self):
        self.security_rules = self._load_default_security_rules()
        self.risk_weights = {
            'public_access': 0.9,
            'overprivileged': 0.8,
            'unencrypted': 0.7,
            'weak_authentication': 0.85,
            'network_exposure': 0.75,
            'data_exposure': 0.8
        }
    
    async def analyze_security(
        self, 
        cloud_resources: Dict, 
        security_benchmarks: Optional[Dict] = None
    ) -> SecurityResult:
        """Analyze security risks in cloud resources"""
        
        # Use custom benchmarks if provided, otherwise use defaults
        rules = security_benchmarks if security_benchmarks else self.security_rules
        
        security_violations = []
        compliance_gaps = []
        
        # Analyze each resource type
        for resource_type, resources in cloud_resources.items():
            violations = self._analyze_resource_security(resource_type, resources, rules)
            security_violations.extend(violations)
        
        # Calculate overall risk level
        risk_level = self._calculate_risk_level(security_violations)
        
        # Generate recommendations
        why_risky, recommended_fix, preventive_controls = self._generate_security_recommendations(
            security_violations, risk_level
        )
        
        # Check compliance gaps
        compliance_gaps = self._check_compliance_gaps(cloud_resources, rules)
        
        return SecurityResult(
            risk_level=risk_level,
            why_this_is_risky=why_risky,
            recommended_fix=recommended_fix,
            preventive_controls=preventive_controls,
            security_violations=security_violations,
            compliance_gaps=compliance_gaps
        )
    
    def _load_default_security_rules(self) -> Dict[str, Any]:
        """Load default security rules based on CIS benchmarks"""
        return {
            'aws': {
                's3': {
                    'block_public_access': True,
                    'encryption_at_rest': True,
                    'versioning': True,
                    'access_logging': True
                },
                'ec2': {
                    'security_group_rules': {
                        'no_open_ssh_to_world': True,
                        'no_open_rdp_to_world': True,
                        'no_open_database_to_world': True
                    },
                    'iam_instance_profile': 'avoid_root_usage'
                },
                'iam': {
                    'no_root_access_keys': True,
                    'mfa_required': True,
                    'least_privilege': True,
                    'password_policy': {
                        'min_length': 12,
                        'require_symbols': True,
                        'require_numbers': True
                    }
                },
                'rds': {
                    'encryption_at_rest': True,
                    'encryption_in_transit': True,
                    'public_accessibility': False,
                    'backup_retention': {'min_days': 7}
                }
            },
            'azure': {
                'storage_account': {
                    'https_only': True,
                    'encryption_at_rest': True,
                    'network_rules': 'default_deny'
                },
                'virtual_machine': {
                    'public_ip': 'avoid_when_possible',
                    'managed_identity': True
                },
                'key_vault': {
                    'soft_delete': True,
                    'purge_protection': True,
                    'access_policies': 'least_privilege'
                }
            },
            'gcp': {
                'storage_bucket': {
                    'uniform_bucket_level_access': True,
                    'public_access_prevention': True,
                    'encryption_at_rest': True
                },
                'compute_instance': {
                    'shielded_vm': True,
                    'os_login': True,
                    'public_ip': 'avoid_when_possible'
                }
            }
        }
    
    def _analyze_resource_security(
        self, 
        resource_type: str, 
        resources: Any, 
        rules: Dict
    ) -> List[Dict[str, Any]]:
        """Analyze security for a specific resource type"""
        violations = []
        
        # Determine cloud provider and resource category
        provider, category = self._categorize_resource(resource_type)
        
        if not provider or not category:
            return violations
        
        # Get applicable rules
        applicable_rules = rules.get(provider, {}).get(category, {})
        
        # Handle different resource formats
        if isinstance(resources, dict):
            resource_items = resources.items()
        elif isinstance(resources, list):
            resource_items = [(f"resource_{i}", resource) for i, resource in enumerate(resources)]
        else:
            return violations
        
        for resource_name, resource_config in resource_items:
            resource_violations = self._check_resource_rules(
                resource_name, resource_config, applicable_rules, provider, category
            )
            violations.extend(resource_violations)
        
        return violations
    
    def _categorize_resource(self, resource_type: str) -> tuple:
        """Categorize resource by provider and type"""
        if resource_type.startswith('aws_'):
            return 'aws', resource_type[4:]
        elif resource_type.startswith('azurerm_'):
            return 'azure', resource_type[8:]
        elif resource_type.startswith('google_'):
            return 'gcp', resource_type[7:]
        return None, None
    
    def _check_resource_rules(
        self, 
        resource_name: str, 
        resource_config: Dict, 
        rules: Dict, 
        provider: str, 
        category: str
    ) -> List[Dict[str, Any]]:
        """Check resource against security rules"""
        violations = []
        
        # Check for public access
        if self._has_public_access(resource_config):
            violations.append({
                'resource': f"{provider}_{category}.{resource_name}",
                'violation_type': 'public_access',
                'severity': 'Critical',
                'description': 'Resource is publicly accessible',
                'risk_score': self.risk_weights['public_access']
            })
        
        # Check encryption
        if not self._is_encrypted(resource_config, category):
            violations.append({
                'resource': f"{provider}_{category}.{resource_name}",
                'violation_type': 'unencrypted',
                'severity': 'High',
                'description': 'Resource lacks encryption at rest',
                'risk_score': self.risk_weights['unencrypted']
            })
        
        # Check for over-privileged permissions
        if self._is_overprivileged(resource_config):
            violations.append({
                'resource': f"{provider}_{category}.{resource_name}",
                'violation_type': 'overprivileged',
                'severity': 'High',
                'description': 'Resource has excessive permissions',
                'risk_score': self.risk_weights['overprivileged']
            })
        
        # Provider-specific checks
        if provider == 'aws':
            violations.extend(self._check_aws_security(resource_name, resource_config, category))
        elif provider == 'azure':
            violations.extend(self._check_azure_security(resource_name, resource_config, category))
        elif provider == 'gcp':
            violations.extend(self._check_gcp_security(resource_name, resource_config, category))
        
        return violations
    
    def _has_public_access(self, config: Dict) -> bool:
        """Check if resource has public access"""
        public_indicators = [
            'public', '0.0.0.0/0', '::/0', 'internet', 'everyone', 'all_users'
        ]
        
        config_str = str(config).lower()
        return any(indicator in config_str for indicator in public_indicators)
    
    def _is_encrypted(self, config: Dict, category: str) -> bool:
        """Check if resource is encrypted"""
        encryption_fields = [
            'encrypted', 'encryption_at_rest', 'server_side_encryption',
            'encryption', 'kms_key_id', 'customer_managed_key'
        ]
        
        for field in encryption_fields:
            if field in config and config[field]:
                return True
        
        # Default to False for sensitive resource types
        sensitive_categories = ['s3', 'storage_account', 'storage_bucket', 'rds']
        return category not in sensitive_categories
    
    def _is_overprivileged(self, config: Dict) -> bool:
        """Check for over-privileged configurations"""
        overprivilege_indicators = [
            'admin', 'administrator', 'root', 'full_access', '*',
            'poweruser', 'owner', 'superuser'
        ]
        
        config_str = str(config).lower()
        return any(indicator in config_str for indicator in overprivilege_indicators)
    
    def _check_aws_security(self, resource_name: str, config: Dict, category: str) -> List[Dict]:
        """AWS-specific security checks"""
        violations = []
        
        if category == 's3_bucket':
            if not config.get('block_public_acls', True):
                violations.append({
                    'resource': f"aws_s3_bucket.{resource_name}",
                    'violation_type': 's3_public_acl',
                    'severity': 'Critical',
                    'description': 'S3 bucket allows public ACLs',
                    'risk_score': 0.9
                })
        
        elif category == 'security_group':
            for rule in config.get('ingress', []):
                if rule.get('cidr_blocks') == ['0.0.0.0/0'] and rule.get('from_port') in [22, 3389]:
                    violations.append({
                        'resource': f"aws_security_group.{resource_name}",
                        'violation_type': 'open_remote_access',
                        'severity': 'Critical',
                        'description': f"Open {rule.get('from_port')} to the world",
                        'risk_score': 0.85
                    })
        
        return violations
    
    def _check_azure_security(self, resource_name: str, config: Dict, category: str) -> List[Dict]:
        """Azure-specific security checks"""
        violations = []
        
        if category == 'storage_account':
            if not config.get('https_traffic_only_enabled', True):
                violations.append({
                    'resource': f"azurerm_storage_account.{resource_name}",
                    'violation_type': 'insecure_protocol',
                    'severity': 'Medium',
                    'description': 'Storage account allows HTTP traffic',
                    'risk_score': 0.6
                })
        
        return violations
    
    def _check_gcp_security(self, resource_name: str, config: Dict, category: str) -> List[Dict]:
        """GCP-specific security checks"""
        violations = []
        
        if category == 'storage_bucket':
            if not config.get('uniform_bucket_level_access_enabled', True):
                violations.append({
                    'resource': f"google_storage_bucket.{resource_name}",
                    'violation_type': 'acl_inconsistency',
                    'severity': 'Medium',
                    'description': 'Storage bucket uses object-level ACLs',
                    'risk_score': 0.5
                })
        
        return violations
    
    def _calculate_risk_level(self, violations: List[Dict]) -> RiskLevel:
        """Calculate overall risk level based on violations"""
        if not violations:
            return RiskLevel.LOW
        
        # Calculate weighted risk score
        total_risk = sum(v.get('risk_score', 0.5) for v in violations)
        max_risk = max(v.get('risk_score', 0.5) for v in violations)
        
        # Determine risk level
        if max_risk >= 0.85 or total_risk > 2.0:
            return RiskLevel.CRITICAL
        elif max_risk >= 0.7 or total_risk > 1.5:
            return RiskLevel.HIGH
        elif max_risk >= 0.5 or total_risk > 0.5:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _generate_security_recommendations(
        self, 
        violations: List[Dict], 
        risk_level: RiskLevel
    ) -> tuple:
        """Generate security recommendations"""
        
        if not violations:
            return (
                "No security violations detected",
                "Continue following security best practices",
                ["Regular security audits", "Automated compliance checks"]
            )
        
        # Group violations by type
        violation_types = {}
        for violation in violations:
            vtype = violation['violation_type']
            violation_types.setdefault(vtype, []).append(violation)
        
        # Generate why risky
        why_risky = f"Found {len(violations)} security violations including: "
        why_risky += ", ".join(violation_types.keys())
        
        # Generate recommended fix
        fixes = []
        for vtype, vlist in violation_types.items():
            if vtype == 'public_access':
                fixes.append("Remove public access and implement proper network controls")
            elif vtype == 'unencrypted':
                fixes.append("Enable encryption at rest for all sensitive resources")
            elif vtype == 'overprivileged':
                fixes.append("Apply least-privilege access controls")
            elif vtype == 'open_remote_access':
                fixes.append("Restrict SSH/RDP access to specific IP ranges")
        
        recommended_fix = "; ".join(fixes)
        
        # Generate preventive controls
        preventive_controls = [
            "Implement Infrastructure as Code (IaC) policies",
            "Enable cloud provider security monitoring",
            "Automated security scanning in CI/CD pipeline",
            "Regular access reviews and privilege audits",
            "Network segmentation and zero-trust architecture"
        ]
        
        return why_risky, recommended_fix, preventive_controls
    
    def _check_compliance_gaps(self, cloud_resources: Dict, rules: Dict) -> List[str]:
        """Check for compliance gaps"""
        gaps = []
        
        # Check for missing security controls
        if not any('encryption' in str(r).lower() for r in cloud_resources.values()):
            gaps.append("Missing encryption controls across resources")
        
        if not any('monitoring' in str(r).lower() for r in cloud_resources.values()):
            gaps.append("Missing security monitoring and logging")
        
        if not any('backup' in str(r).lower() for r in cloud_resources.values()):
            gaps.append("Missing backup and disaster recovery controls")
        
        return gaps
