from typing import Dict, List, Any, Optional
from models.drift_report import DriftResult

class TerraformGenerator:
    def __init__(self):
        self.resource_templates = {
            'aws_s3_bucket': self._generate_aws_s3_bucket,
            'aws_security_group': self._generate_aws_security_group,
            'aws_iam_role': self._generate_aws_iam_role,
            'aws_iam_policy': self._generate_aws_iam_policy,
            'azurerm_storage_account': self._generate_azure_storage_account,
            'azurerm_virtual_network': self._generate_azure_virtual_network,
            'google_storage_bucket': self._generate_gcp_storage_bucket,
            'google_compute_instance': self._generate_gcp_compute_instance
        }
    
    async def generate_remediation(self, drift_result: DriftResult) -> Optional[str]:
        """Generate Terraform code to remediate detected drift"""
        
        if not drift_result.drift_detected:
            return None
        
        remediation_blocks = []
        
        # Generate remediation for missing resources
        for resource in drift_result.missing_resources:
            block = self._generate_missing_resource_block(resource)
            if block:
                remediation_blocks.append(block)
        
        # Generate remediation for configuration changes
        for resource_key, changes in drift_result.configuration_changes.items():
            block = self._generate_config_fix_block(resource_key, changes)
            if block:
                remediation_blocks.append(block)
        
        # Generate removal blocks for extra resources
        for resource in drift_result.extra_resources:
            block = self._generate_removal_block(resource)
            if block:
                remediation_blocks.append(block)
        
        if not remediation_blocks:
            return None
        
        # Combine all blocks into complete Terraform file
        terraform_code = self._wrap_with_header_footer('\n\n'.join(remediation_blocks))
        
        return terraform_code
    
    def _generate_missing_resource_block(self, resource_key: str) -> Optional[str]:
        """Generate Terraform block for missing resource"""
        # Parse resource type and name
        parts = resource_key.split('.')
        if len(parts) < 2:
            return None
        
        resource_type = parts[0]
        resource_name = parts[1]
        
        # Get template for resource type
        template_func = self.resource_templates.get(resource_type)
        if template_func:
            return template_func(resource_name, {}, is_missing=True)
        
        # Generic template for unknown resource types
        return self._generate_generic_resource(resource_type, resource_name, {}, is_missing=True)
    
    def _generate_config_fix_block(self, resource_key: str, changes: Dict) -> Optional[str]:
        """Generate Terraform block to fix configuration drift"""
        parts = resource_key.split('.')
        if len(parts) < 2:
            return None
        
        resource_type = parts[0]
        resource_name = parts[1]
        
        # Use expected configuration as the target
        expected_config = changes.get('expected', {})
        
        # Get template for resource type
        template_func = self.resource_templates.get(resource_type)
        if template_func:
            return template_func(resource_name, expected_config, is_missing=False)
        
        # Generic template for unknown resource types
        return self._generate_generic_resource(resource_type, resource_name, expected_config, is_missing=False)
    
    def _generate_removal_block(self, resource_key: str) -> str:
        """Generate comment block for resource removal"""
        parts = resource_key.split('.')
        if len(parts) < 2:
            return f"# Manual removal required for unknown resource: {resource_key}"
        
        resource_type = parts[0]
        resource_name = parts[1]
        
        return f"""# EXTRA RESOURCE DETECTED - Manual Removal Required
# Resource {resource_key} exists in cloud but not in Terraform
# To remove, run: terraform destroy -target={resource_type}.{resource_name}
# Or add the resource to Terraform state first, then remove

# terraform import {resource_type}.{resource_name} <resource-id>
# terraform state rm {resource_type}.{resource_name}"""
    
    def _generate_aws_s3_bucket(self, name: str, config: Dict, is_missing: bool) -> str:
        """Generate AWS S3 bucket Terraform code"""
        return f"""resource "aws_s3_bucket" "{name}" {{
  bucket = "{name or config.get('bucket', name)}"
  
  # Security configurations
  force_destroy = {config.get('force_destroy', 'false')}
  
  # Block public access
  public_access_block {{
    block_public_acls   = true
    block_public_policy = true
    ignore_public_acls  = true
    restrict_public_buckets = true
  }}
  
  # Versioning
  versioning {{
    enabled = {config.get('versioning', 'true')}
  }}
  
  # Server-side encryption
  server_side_encryption_configuration {{
    rule {{
      apply_server_side_encryption_by_default {{
        sse_algorithm = "AES256"
      }}
    }}
  }}
  
  # Access logging
  logging {{
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }}
  
  tags = {{
    Environment = "{config.get('environment', 'production')}"
    ManagedBy   = "terraform"
    Remediated  = "true"
  }}
}}"""
    
    def _generate_aws_security_group(self, name: str, config: Dict, is_missing: bool) -> str:
        """Generate AWS security group Terraform code"""
        return f"""resource "aws_security_group" "{name}" {{
  name        = "{name}"
  description = "{config.get('description', 'Security group for ' + name)}"
  vpc_id      = {config.get('vpc_id', 'aws_vpc.main.id')}
  
  # SSH access - restricted to specific IPs
  ingress {{
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["{config.get('ssh_cidr', '10.0.0.0/8')}"]
  }}
  
  # HTTPS access
  ingress {{
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  # outbound internet access
  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  tags = {{
    Name        = "{name}"
    Environment = "{config.get('environment', 'production')}"
    ManagedBy   = "terraform"
    Remediated  = "true"
  }}
}}"""
    
    def _generate_aws_iam_role(self, name: str, config: Dict, is_missing: bool) -> str:
        """Generate AWS IAM role Terraform code"""
        return f"""resource "aws_iam_role" "{name}" {{
  name = "{name}"
  
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {{
          Service = "{config.get('service', 'ec2.amazonaws.com')}"
        }}
      }}
    ]
  }})
  
  tags = {{
    Environment = "{config.get('environment', 'production')}"
    ManagedBy   = "terraform"
    Remediated  = "true"
  }}
}}"""
    
    def _generate_aws_iam_policy(self, name: str, config: Dict, is_missing: bool) -> str:
        """Generate AWS IAM policy Terraform code"""
        return f"""resource "aws_iam_policy" "{name}" {{
  name        = "{name}"
  description = "{config.get('description', 'IAM policy for ' + name)}"
  
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Action = {config.get('actions', ['"logs:*"', '"s3:GetObject"'])}
        Resource = {config.get('resources', ['"*"'])}
      }}
    ]
  }})
  
  tags = {{
    Environment = "{config.get('environment', 'production')}"
    ManagedBy   = "terraform"
    Remediated  = "true"
  }}
}}"""
    
    def _generate_azure_storage_account(self, name: str, config: Dict, is_missing: bool) -> str:
        """Generate Azure storage account Terraform code"""
        return f"""resource "azurerm_storage_account" "{name}" {{
  name                     = "{name}"
  resource_group_name      = {config.get('resource_group_name', 'azurerm_resource_group.main.name')}
  location                 = {config.get('location', 'azurerm_resource_group.main.location')}
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  # Security configurations
  min_tls_version = "TLS1_2"
  https_traffic_only_enabled = true
  
  # Network rules
  network_rules {{
    default_action = "Deny"
    ip_rules       = {config.get('ip_rules', '[]')}
    virtual_network_subnet_ids = {config.get('subnet_ids', '[]')}
  }}
  
  # Blob encryption
  blob_properties {{
    versioning_enabled = true
  }}
  
  tags = {{
    Environment = "{config.get('environment', 'production')}"
    ManagedBy   = "terraform"
    Remediated  = "true"
  }}
}}"""
    
    def _generate_azure_virtual_network(self, name: str, config: Dict, is_missing: bool) -> str:
        """Generate Azure virtual network Terraform code"""
        return f"""resource "azurerm_virtual_network" "{name}" {{
  name                = "{name}"
  address_space       = {config.get('address_space', '["10.0.0.0/16"]')}
  location            = {config.get('location', 'azurerm_resource_group.main.location')}
  resource_group_name = {config.get('resource_group_name', 'azurerm_resource_group.main.name')}
  
  tags = {{
    Environment = "{config.get('environment', 'production')}"
    ManagedBy   = "terraform"
    Remediated  = "true"
  }}
}}"""
    
    def _generate_gcp_storage_bucket(self, name: str, config: Dict, is_missing: bool) -> str:
        """Generate GCP storage bucket Terraform code"""
        return f"""resource "google_storage_bucket" "{name}" {{
  name          = "{name}"
  location      = "{config.get('location', 'US-CENTRAL1')}"
  force_destroy = {config.get('force_destroy', 'false')}
  
  # Security configurations
  uniform_bucket_level_access = true
  public_access_prevention = "enforced"
  
  # Versioning
  versioning {{
    enabled = true
  }}
  
  # Encryption
  encryption {{
    default_kms_key_name = {config.get('kms_key_name', 'null')}
  }}
  
  # Logging
  logging {{
    log_bucket = "gs://{config.get('log_bucket', name + '-logs')}"
    log_object_prefix = "access-logs/"
  }}
  
  labels = {{
    environment = "{config.get('environment', 'production')}"
    managed_by  = "terraform"
    remediated  = "true"
  }}
}}"""
    
    def _generate_gcp_compute_instance(self, name: str, config: Dict, is_missing: bool) -> str:
        """Generate GCP compute instance Terraform code"""
        return f"""resource "google_compute_instance" "{name}" {{
  name         = "{name}"
  machine_type = "{config.get('machine_type', 'e2-medium')}"
  zone         = "{config.get('zone', 'us-central1-a')}"
  
  # Boot disk with encryption
  boot_disk {{
    initialize_params {{
      image = "{config.get('image', 'debian-cloud/debian-11')}"
      type  = "pd-balanced"
    }}
  }}
  
  # Network interface - no public IP by default
  network_interface {{
    network = "default"
    access_config {{
      # Empty to remove public IP
    }}
  }}
  
  # Shielded VM configuration
  shielded_instance_config {{
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }}
  
  # Service account with minimal permissions
  service_account {{
    email  = {config.get('service_account_email', 'null')}
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }}
  
  labels = {{
    environment = "{config.get('environment', 'production')}"
    managed_by  = "terraform"
    remediated  = "true"
  }}
}}"""
    
    def _generate_generic_resource(self, resource_type: str, name: str, config: Dict, is_missing: bool) -> str:
        """Generate generic Terraform resource block"""
        return f"""resource "{resource_type}" "{name}" {{
  # TODO: Configure this resource properly
  # This is a generic template - review and customize
  
  name = "{name}"
  
  # Add required configuration parameters here
  # Example:
  # parameter = "{config.get('parameter', 'default_value')}"
  
  tags = {{
    Environment = "{config.get('environment', 'production')}"
    ManagedBy   = "terraform"
    Remediated  = "true"
    Generated   = "auto"
  }}
}}"""
    
    def _wrap_with_header_footer(self, terraform_code: str) -> str:
        """Wrap remediation code with header and footer"""
        header = """# Terraform Remediation Code
# Generated by DevSecOps Drift Risk Detector
# WARNING: Review this code before applying
# Run: terraform plan first to review changes

terraform {{
  required_version = ">= 1.0"
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
    azurerm = {{
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }}
    google = {{
      source  = "hashicorp/google"
      version = "~> 4.0"
    }}
  }}
}}

"""
        
        footer = """

# Remediation Instructions:
# 1. Review the generated code above
# 2. Run 'terraform plan' to see proposed changes
# 3. Run 'terraform apply' to implement fixes
# 4. Verify resources are properly configured
# 5. Update your main Terraform files with these changes

# For extra resources that need manual removal:
# 1. Import them to state: terraform import <resource_type>.<name> <resource-id>
# 2. Remove from state: terraform state rm <resource_type>.<name>
# 3. Or manually delete via cloud console
"""
        
        return header + terraform_code + footer
