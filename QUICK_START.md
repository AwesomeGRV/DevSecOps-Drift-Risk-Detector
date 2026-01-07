# Quick Start Guide

## 🚀 Running the Application

The DevSecOps Drift Risk Detector is now running at: **http://localhost:8000**

## 📋 Testing with Sample Data

I've created sample data files to demonstrate the application functionality:

### Available Sample Files:
- `sample_data/cloud_resources.json` - Live AWS resources (with security issues)
- `sample_data/terraform_config.json` - Expected Terraform configuration
- `sample_data/activity_logs.json` - AWS CloudTrail logs
- `sample_data/security_benchmarks.json` - Custom security rules
- `sample_data/git_history.json` - Git commit history

### 🧪 Test Scenario:
The sample data demonstrates:
1. **Configuration Drift**: Extra S3 bucket and different security group
2. **Security Issues**: Public S3 bucket, open SSH access
3. **Change Attribution**: Who made changes and when
4. **Risk Assessment**: Critical and High severity issues

## 🔍 How to Test:

1. **Open the Dashboard**: Navigate to http://localhost:8000
2. **Upload Files**: 
   - **Required**: `sample_data/cloud_resources.json`
   - **Optional**: Add the other sample files for complete analysis
3. **Click "Analyze Drift & Security"**
4. **Review Results**: Examine the comprehensive report

## 📊 Expected Results:

- **Drift Detected**: Yes
- **Risk Level**: Critical
- **Affected Resources**: Multiple
- **Security Issues**: Public S3 bucket, open SSH access
- **Terraform Remediation**: Generated code to fix issues

## 🛠️ Key Features Demonstrated:

1. **Drift Detection**: Compares IaC vs live resources
2. **Security Analysis**: Identifies vulnerabilities
3. **Activity Analysis**: Attributes changes to users
4. **Risk Scoring**: Automated severity assessment
5. **Remediation**: Generates Terraform fixes
6. **Preventive Controls**: Policy recommendations

## 📝 Sample Data Analysis:

### Security Issues Detected:
- **Critical**: S3 bucket with public-read ACL
- **Critical**: Security group with SSH open to 0.0.0.0/0
- **High**: Missing encryption on S3 bucket
- **Medium**: No access logging configured

### Configuration Drift:
- **Extra Resource**: `public_bucket` exists in cloud but not in Terraform
- **Missing Resource**: `secure_sg` defined in Terraform but not deployed
- **Configuration Changes**: Different security group rules

### Change Attribution:
- **Who**: john.doe modified security group rules
- **When**: 2024-01-07T12:30:00Z
- **Source**: CloudTrail logs with high confidence

## 🎯 Next Steps:

1. **Try Your Own Data**: Replace sample files with your actual configurations
2. **Customize Rules**: Modify security benchmarks for your requirements
3. **Integrate**: Add to CI/CD pipeline for automated checks
4. **Monitor**: Set up regular drift detection schedules

## 🔧 Troubleshooting:

If you encounter issues:
1. Check the console output for error messages
2. Ensure JSON files are valid format
3. Verify required files are uploaded
4. Check browser console for JavaScript errors

## 📚 Documentation:

- Full documentation: `README.md`
- API documentation: http://localhost:8000/docs
- Health check: http://localhost:8000/health
