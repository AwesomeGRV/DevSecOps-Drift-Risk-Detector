import pytest
from core.security_analyzer import SecurityAnalyzer
from models.drift_report import SecurityResult, RiskLevel

class TestSecurityAnalyzer:
    
    def setup_method(self):
        self.analyzer = SecurityAnalyzer()
    
    def test_no_security_violations(self):
        """Test that secure configurations pass analysis"""
        cloud_resources = {
            "aws_s3_bucket": {
                "secure_bucket": {
                    "bucket": "secure-bucket",
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                    "server_side_encryption_configuration": {
                        "rules": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}]
                    }
                }
            }
        }
        
        result = self.analyzer._analyze_resource_security(
            "aws_s3_bucket", 
            cloud_resources["aws_s3_bucket"], 
            self.analyzer.security_rules["aws"]["s3"]
        )
        
        # Should have no violations for secure configuration
        public_violations = [v for v in result if v['violation_type'] == 'public_access']
        assert len(public_violations) == 0
    
    def test_public_access_detection(self):
        """Test detection of public access"""
        cloud_resources = {
            "aws_s3_bucket": {
                "public_bucket": {
                    "bucket": "public-bucket",
                    "acl": "public-read"
                }
            }
        }
        
        result = self.analyzer._analyze_resource_security(
            "aws_s3_bucket", 
            cloud_resources["aws_s3_bucket"], 
            self.analyzer.security_rules["aws"]["s3"]
        )
        
        public_violations = [v for v in result if v['violation_type'] == 'public_access']
        assert len(public_violations) > 0
        assert public_violations[0]['severity'] == 'Critical'
    
    def test_missing_encryption_detection(self):
        """Test detection of missing encryption"""
        cloud_resources = {
            "aws_s3_bucket": {
                "unencrypted_bucket": {
                    "bucket": "unencrypted-bucket",
                    "acl": "private"
                }
            }
        }
        
        result = self.analyzer._analyze_resource_security(
            "aws_s3_bucket", 
            cloud_resources["aws_s3_bucket"], 
            self.analyzer.security_rules["aws"]["s3"]
        )
        
        encryption_violations = [v for v in result if v['violation_type'] == 'unencrypted']
        assert len(encryption_violations) > 0
        assert encryption_violations[0]['severity'] == 'High'
    
    def test_overprivileged_permissions_detection(self):
        """Test detection of over-privileged permissions"""
        cloud_resources = {
            "aws_iam_role": {
                "admin_role": {
                    "name": "admin-role",
                    "assume_role_policy": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "inline_policy": {
                        "admin_policy": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*"
                            }]
                        }
                    }
                }
            }
        }
        
        result = self.analyzer._analyze_resource_security(
            "aws_iam_role", 
            cloud_resources["aws_iam_role"], 
            self.analyzer.security_rules["aws"]["iam"]
        )
        
        overprivilege_violations = [v for v in result if v['violation_type'] == 'overprivileged']
        assert len(overprivilege_violations) > 0
    
    def test_aws_security_group_open_ssh(self):
        """Test detection of open SSH access in AWS security groups"""
        cloud_resources = {
            "aws_security_group": {
                "open_sg": {
                    "name": "open-security-group",
                    "ingress": [{
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }
        
        violations = self.analyzer._check_aws_security("open_sg", cloud_resources["aws_security_group"]["open_sg"], "security_group")
        
        ssh_violations = [v for v in violations if v['violation_type'] == 'open_remote_access']
        assert len(ssh_violations) > 0
        assert ssh_violations[0]['severity'] == 'Critical'
    
    def test_azure_insecure_protocol(self):
        """Test detection of insecure protocols in Azure"""
        cloud_resources = {
            "azurerm_storage_account": {
                "insecure_storage": {
                    "name": "insecurestorage",
                    "https_traffic_only_enabled": False
                }
            }
        }
        
        violations = self.analyzer._check_azure_security("insecure_storage", cloud_resources["azurerm_storage_account"]["insecure_storage"], "storage_account")
        
        protocol_violations = [v for v in violations if v['violation_type'] == 'insecure_protocol']
        assert len(protocol_violations) > 0
        assert protocol_violations[0]['severity'] == 'Medium'
    
    def test_risk_level_calculation(self):
        """Test risk level calculation based on violations"""
        # Test no violations
        risk_level = self.analyzer._calculate_risk_level([])
        assert risk_level == RiskLevel.LOW
        
        # Test low risk violations
        low_risk_violations = [
            {'risk_score': 0.3, 'violation_type': 'minor'},
            {'risk_score': 0.4, 'violation_type': 'small'}
        ]
        risk_level = self.analyzer._calculate_risk_level(low_risk_violations)
        assert risk_level == RiskLevel.LOW
        
        # Test high risk violations
        high_risk_violations = [
            {'risk_score': 0.9, 'violation_type': 'public_access'},
            {'risk_score': 0.8, 'violation_type': 'unencrypted'}
        ]
        risk_level = self.analyzer._calculate_risk_level(high_risk_violations)
        assert risk_level == RiskLevel.CRITICAL
        
        # Test critical risk
        critical_violations = [
            {'risk_score': 0.85, 'violation_type': 'open_remote_access'}
        ]
        risk_level = self.analyzer._calculate_risk_level(critical_violations)
        assert risk_level == RiskLevel.CRITICAL
    
    def test_security_recommendations_generation(self):
        """Test generation of security recommendations"""
        violations = [
            {'violation_type': 'public_access', 'resource': 'aws_s3_bucket.public'},
            {'violation_type': 'unencrypted', 'resource': 'aws_rds_instance.unencrypted'}
        ]
        
        why_risky, recommended_fix, preventive_controls = self.analyzer._generate_security_recommendations(
            violations, RiskLevel.HIGH
        )
        
        assert 'public_access' in why_risky
        assert 'unencrypted' in why_risky
        assert 'Remove public access' in recommended_fix
        assert 'Enable encryption' in recommended_fix
        assert len(preventive_controls) > 0
    
    @pytest.mark.asyncio
    async def test_full_security_analysis_pipeline(self):
        """Test the complete security analysis pipeline"""
        cloud_resources = {
            "aws_s3_bucket": {
                "public_bucket": {
                    "bucket": "public-bucket",
                    "acl": "public-read"
                }
            },
            "aws_security_group": {
                "open_sg": {
                    "name": "open-sg",
                    "ingress": [{
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }
        
        result = await self.analyzer.analyze_security(cloud_resources)
        
        assert isinstance(result, SecurityResult)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert len(result.security_violations) > 0
        assert result.why_this_is_risky is not None
        assert result.recommended_fix is not None
        assert len(result.preventive_controls) > 0
    
    def test_compliance_gaps_detection(self):
        """Test detection of compliance gaps"""
        cloud_resources = {
            "aws_instance": {
                "test_instance": {
                    "ami": "ami-12345"
                }
            }
        }
        
        gaps = self.analyzer._check_compliance_gaps(cloud_resources, self.analyzer.security_rules)
        
        # Should detect missing encryption and monitoring
        assert any('encryption' in gap.lower() for gap in gaps)
        assert any('monitoring' in gap.lower() for gap in gaps)

if __name__ == "__main__":
    pytest.main([__file__])
