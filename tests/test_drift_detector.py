import pytest
import json
from datetime import datetime
from core.drift_detector import DriftDetector
from models.drift_report import DriftResult

class TestDriftDetector:
    
    def setup_method(self):
        self.detector = DriftDetector()
    
    def test_no_drift_identical_configs(self):
        """Test that identical configurations show no drift"""
        terraform_config = {
            "resource": {
                "aws_s3_bucket": {
                    "test_bucket": {
                        "bucket": "my-test-bucket",
                        "acl": "private"
                    }
                }
            }
        }
        
        cloud_resources = {
            "aws_s3_bucket": {
                "test_bucket": {
                    "bucket": "my-test-bucket",
                    "acl": "private"
                }
            }
        }
        
        result = self.detector._compare_resources(
            self.detector._parse_terraform_config(terraform_config),
            self.detector._normalize_cloud_resources(cloud_resources)
        )
        
        assert not result.drift_detected
        assert len(result.affected_resources) == 0
        assert len(result.missing_resources) == 0
        assert len(result.extra_resources) == 0
    
    def test_missing_resource_detected(self):
        """Test detection of missing resources"""
        terraform_config = {
            "resource": {
                "aws_s3_bucket": {
                    "test_bucket": {
                        "bucket": "my-test-bucket"
                    }
                },
                "aws_instance": {
                    "test_instance": {
                        "ami": "ami-12345"
                    }
                }
            }
        }
        
        cloud_resources = {
            "aws_s3_bucket": {
                "test_bucket": {
                    "bucket": "my-test-bucket"
                }
            }
        }
        
        result = self.detector._compare_resources(
            self.detector._parse_terraform_config(terraform_config),
            self.detector._normalize_cloud_resources(cloud_resources)
        )
        
        assert result.drift_detected
        assert "aws_instance.test_instance" in result.missing_resources
        assert len(result.affected_resources) == 1
    
    def test_extra_resource_detected(self):
        """Test detection of extra resources"""
        terraform_config = {
            "resource": {
                "aws_s3_bucket": {
                    "test_bucket": {
                        "bucket": "my-test-bucket"
                    }
                }
            }
        }
        
        cloud_resources = {
            "aws_s3_bucket": {
                "test_bucket": {
                    "bucket": "my-test-bucket"
                }
            },
            "aws_instance": {
                "unmanaged_instance": {
                    "ami": "ami-67890"
                }
            }
        }
        
        result = self.detector._compare_resources(
            self.detector._parse_terraform_config(terraform_config),
            self.detector._normalize_cloud_resources(cloud_resources)
        )
        
        assert result.drift_detected
        assert "aws_instance.unmanaged_instance" in result.extra_resources
        assert len(result.affected_resources) == 1
    
    def test_configuration_changes_detected(self):
        """Test detection of configuration changes"""
        terraform_config = {
            "resource": {
                "aws_s3_bucket": {
                    "test_bucket": {
                        "bucket": "my-test-bucket",
                        "acl": "private"
                    }
                }
            }
        }
        
        cloud_resources = {
            "aws_s3_bucket": {
                "test_bucket": {
                    "bucket": "my-test-bucket",
                    "acl": "public-read"
                }
            }
        }
        
        result = self.detector._compare_resources(
            self.detector._parse_terraform_config(terraform_config),
            self.detector._normalize_cloud_resources(cloud_resources)
        )
        
        assert result.drift_detected
        assert "aws_s3_bucket.test_bucket" in result.configuration_changes
        assert len(result.affected_resources) == 1
    
    def test_ignored_fields_not_causing_drift(self):
        """Test that ignored fields don't cause false positives"""
        terraform_config = {
            "resource": {
                "aws_s3_bucket": {
                    "test_bucket": {
                        "bucket": "my-test-bucket",
                        "acl": "private"
                    }
                }
            }
        }
        
        cloud_resources = {
            "aws_s3_bucket": {
                "test_bucket": {
                    "bucket": "my-test-bucket",
                    "acl": "private",
                    "id": "bucket-id-123",
                    "arn": "arn:aws:s3:::my-test-bucket",
                    "created_at": "2023-01-01T00:00:00Z"
                }
            }
        }
        
        result = self.detector._compare_resources(
            self.detector._parse_terraform_config(terraform_config),
            self.detector._normalize_cloud_resources(cloud_resources)
        )
        
        assert not result.drift_detected
    
    def test_nested_configuration_changes(self):
        """Test detection of changes in nested configurations"""
        terraform_config = {
            "resource": {
                "aws_security_group": {
                    "test_sg": {
                        "name": "test-sg",
                        "ingress": [{
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                            "cidr_blocks": ["10.0.0.0/8"]
                        }]
                    }
                }
            }
        }
        
        cloud_resources = {
            "aws_security_group": {
                "test_sg": {
                    "name": "test-sg",
                    "ingress": [{
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }
        
        result = self.detector._compare_resources(
            self.detector._parse_terraform_config(terraform_config),
            self.detector._normalize_cloud_resources(cloud_resources)
        )
        
        assert result.drift_detected
        assert "aws_security_group.test_sg" in result.configuration_changes
    
    @pytest.mark.asyncio
    async def test_full_drift_detection_pipeline(self):
        """Test the complete drift detection pipeline"""
        terraform_config = {
            "resource": {
                "aws_s3_bucket": {
                    "test_bucket": {
                        "bucket": "my-test-bucket",
                        "acl": "private"
                    }
                }
            }
        }
        
        cloud_resources = {
            "aws_s3_bucket": {
                "test_bucket": {
                    "bucket": "my-test-bucket",
                    "acl": "public-read"
                }
            }
        }
        
        result = await self.detector.detect_drift(terraform_config, None, cloud_resources)
        
        assert isinstance(result, DriftResult)
        assert result.drift_detected
        assert len(result.affected_resources) > 0
        assert result.what_changed is not None

if __name__ == "__main__":
    pytest.main([__file__])
