import json
from typing import Dict, List, Any, Optional
from deepdiff import DeepDiff
from models.drift_report import DriftResult

class DriftDetector:
    def __init__(self):
        self.ignored_fields = {
            'id', 'arn', 'created_at', 'updated_at', 'last_modified', 
            'etag', 'version', 'resource_id', 'unique_id'
        }
    
    async def detect_drift(
        self, 
        terraform_config: Optional[Dict], 
        terraform_state: Optional[Dict], 
        cloud_resources: Dict
    ) -> DriftResult:
        """Detect configuration drift between IaC and live resources"""
        
        # Get expected resources from Terraform
        expected_resources = {}
        if terraform_config:
            expected_resources.update(self._parse_terraform_config(terraform_config))
        if terraform_state:
            expected_resources.update(self._parse_terraform_state(terraform_state))
        
        # Normalize cloud resources
        actual_resources = self._normalize_cloud_resources(cloud_resources)
        
        # Compare resources
        drift_result = self._compare_resources(expected_resources, actual_resources)
        
        return drift_result
    
    def _parse_terraform_config(self, config: Dict) -> Dict[str, Any]:
        """Parse Terraform HCL configuration"""
        resources = {}
        
        if 'resource' in config:
            for resource_type, resource_configs in config['resource'].items():
                for resource_name, resource_config in resource_configs.items():
                    resource_key = f"{resource_type}.{resource_name}"
                    resources[resource_key] = {
                        'type': resource_type,
                        'name': resource_name,
                        'config': self._flatten_config(resource_config),
                        'source': 'terraform_config'
                    }
        
        return resources
    
    def _parse_terraform_state(self, state: Dict) -> Dict[str, Any]:
        """Parse Terraform state file"""
        resources = {}
        
        if 'resources' in state:
            for resource in state['resources']:
                resource_key = f"{resource['type']}.{resource['name']}"
                resources[resource_key] = {
                    'type': resource['type'],
                    'name': resource['name'],
                    'config': self._extract_state_values(resource),
                    'source': 'terraform_state'
                }
        
        return resources
    
    def _normalize_cloud_resources(self, cloud_resources: Dict) -> Dict[str, Any]:
        """Normalize cloud provider resources to standard format"""
        normalized = {}
        
        for resource_type, resources in cloud_resources.items():
            if isinstance(resources, dict):
                for resource_name, resource_config in resources.items():
                    resource_key = f"{resource_type}.{resource_name}"
                    normalized[resource_key] = {
                        'type': resource_type,
                        'name': resource_name,
                        'config': self._flatten_config(resource_config),
                        'source': 'cloud_live'
                    }
            elif isinstance(resources, list):
                for i, resource_config in enumerate(resources):
                    resource_name = resource_config.get('name', f"resource_{i}")
                    resource_key = f"{resource_type}.{resource_name}"
                    normalized[resource_key] = {
                        'type': resource_type,
                        'name': resource_name,
                        'config': self._flatten_config(resource_config),
                        'source': 'cloud_live'
                    }
        
        return normalized
    
    def _flatten_config(self, config: Dict, parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """Flatten nested configuration"""
        items = []
        
        for k, v in config.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(self._flatten_config(v, new_key, sep).items())
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        items.extend(self._flatten_config(item, f"{new_key}{sep}{i}", sep).items())
                    else:
                        items.append((f"{new_key}{sep}{i}", item))
            else:
                items.append((new_key, v))
        
        return dict(items)
    
    def _extract_state_values(self, resource: Dict) -> Dict[str, Any]:
        """Extract values from Terraform state resource"""
        values = {}
        
        if 'instances' in resource:
            for instance in resource['instances']:
                if 'attributes' in instance:
                    values.update(instance['attributes'])
        elif 'values' in resource:
            values.update(resource['values'])
        
        return self._flatten_config(values)
    
    def _compare_resources(
        self, 
        expected: Dict[str, Any], 
        actual: Dict[str, Any]
    ) -> DriftResult:
        """Compare expected vs actual resources"""
        
        expected_keys = set(expected.keys())
        actual_keys = set(actual.keys())
        
        # Find missing and extra resources
        missing_resources = list(expected_keys - actual_keys)
        extra_resources = list(actual_keys - expected_keys)
        
        # Find common resources with configuration changes
        common_resources = expected_keys & actual_keys
        configuration_changes = {}
        affected_resources = []
        what_changed = {}
        
        for resource_key in common_resources:
            expected_config = expected[resource_key]['config']
            actual_config = actual[resource_key]['config']
            
            # Remove ignored fields
            expected_clean = {k: v for k, v in expected_config.items() 
                            if k not in self.ignored_fields}
            actual_clean = {k: v for k, v in actual_config.items() 
                          if k not in self.ignored_fields}
            
            # Compare configurations
            diff = DeepDiff(expected_clean, actual_clean, ignore_order=True)
            
            if diff:
                affected_resources.append(resource_key)
                configuration_changes[resource_key] = {
                    'expected': expected_clean,
                    'actual': actual_clean,
                    'differences': self._format_diff(diff)
                }
                what_changed[resource_key] = self._summarize_changes(diff)
        
        # Compile comprehensive what_changed
        if missing_resources:
            what_changed['missing_resources'] = missing_resources
        if extra_resources:
            what_changed['extra_resources'] = extra_resources
        if configuration_changes:
            what_changed['configuration_changes'] = configuration_changes
        
        drift_detected = bool(missing_resources or extra_resources or configuration_changes)
        
        return DriftResult(
            drift_detected=drift_detected,
            affected_resources=affected_resources + missing_resources + extra_resources,
            what_changed=what_changed,
            missing_resources=missing_resources,
            extra_resources=extra_resources,
            configuration_changes=configuration_changes
        )
    
    def _format_diff(self, diff: DeepDiff) -> Dict[str, Any]:
        """Format DeepDiff output for human readability"""
        formatted = {}
        
        if 'values_changed' in diff:
            formatted['changed_values'] = diff['values_changed']
        if 'dictionary_item_added' in diff:
            formatted['added_properties'] = diff['dictionary_item_added']
        if 'dictionary_item_removed' in diff:
            formatted['removed_properties'] = diff['dictionary_item_removed']
        if 'iterable_item_added' in diff:
            formatted['added_items'] = diff['iterable_item_added']
        if 'iterable_item_removed' in diff:
            formatted['removed_items'] = diff['iterable_item_removed']
        
        return formatted
    
    def _summarize_changes(self, diff: DeepDiff) -> str:
        """Create human-readable summary of changes"""
        changes = []
        
        if 'values_changed' in diff:
            for path, change in diff['values_changed'].items():
                changes.append(f"Changed {path}: {change['old_value']} → {change['new_value']}")
        
        if 'dictionary_item_added' in diff:
            for item in diff['dictionary_item_added']:
                changes.append(f"Added property: {item}")
        
        if 'dictionary_item_removed' in diff:
            for item in diff['dictionary_item_removed']:
                changes.append(f"Removed property: {item}")
        
        return "; ".join(changes) if changes else "Configuration differences detected"
