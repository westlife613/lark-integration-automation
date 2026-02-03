"""
Unified security event handler using Strategy Pattern.
Supports GuardDuty and SecurityHub findings with a single, maintainable interface.
"""

import uuid
import hashlib
from datetime import datetime
from db_handler import store_finding


def parse_datetime(dt_str):
    """Parse ISO8601 datetime and return components (year, month, day, time)."""
    try:
        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        return {
            'year': str(dt.year),
            'month': f"{dt.month:02d}",
            'day': f"{dt.day:02d}",
            'time': f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
        }
    except Exception:
        return {'year': None, 'month': None, 'day': None, 'time': None}


# ============= GuardDuty Strategy =============

def normalize_guardduty_finding(event_envelope, finding):
    """
    Transform a GuardDuty finding into a normalized event for unified storage.
    
    Args:
        event_envelope: The outer EventBridge envelope
        finding: The GuardDuty finding detail
    
    Returns:
        Dict with normalized fields
    """
    
    # Extract basic fields
    name = finding.get('Title', '')
    description = finding.get('Description', '')
    account_name = finding.get('AwsAccountName', '')
    region = finding.get('Region', '')
    severity = finding.get('Severity', {}).get('Normalized', 0) / 10
    
    # Parse time into components
    finding_time_str = event_envelope.get('time', '')
    time_parts = parse_datetime(finding_time_str)
    
    # Extract principal details
    principal_id = None
    principal_name = None
    principal_type = None
    
    resources = finding.get('Resources', [])
    if resources:
        resource = resources[0]
        details = resource.get('Details', {})
        access_key = details.get('AwsIamAccessKey', {})
        principal_id = access_key.get('PrincipalId', '')
        principal_name = access_key.get('PrincipalName', '')
        principal_type = access_key.get('PrincipalType', '')
    
    # Build normalized object
    normalized = {
        'Finding_name': name,
        'Finding_description': description,
        'year': time_parts['year'],
        'month': time_parts['month'],
        'day': time_parts['day'],
        'time': time_parts['time'],
        'principal_id': principal_id,
        'principal_name': principal_name,
        'principal_type': principal_type,
        'account_name': account_name,
        'region': region,
        'severity': severity,
        'source': 'aws.guardduty'
    }
    
    return normalized


# ============= SecurityHub Strategy =============

def normalize_securityhub_finding(event_envelope, finding, user_name=None):
    """
    Transform a SecurityHub finding into a normalized event for unified storage.
    
    Args:
        event_envelope: The outer EventBridge envelope
        finding: The SecurityHub finding detail
        user_name: Optional username of the person who triggered the event
    
    Returns:
        Dict with normalized fields
    """
    
    # Extract basic fields
    name = finding.get('Title', '')
    description = finding.get('Description', '')
    account_name = finding.get('AwsAccountName', '')
    region = finding.get('Region', '')
    severity = finding.get('Severity', {}).get('Normalized', 0) / 10
    
    # Parse time into components
    finding_time_str = event_envelope.get('time', '')
    time_parts = parse_datetime(finding_time_str)
    
    # Extract security group details
    sg_id = None
    sg_name = None
    ingress_rules = None
    
    resources = finding.get('Resources', [])
    if resources:
        resource = resources[0]
        sg_id = resource.get('Id', '')
        sg_details = resource.get('Details', {}).get('AwsEc2SecurityGroup', {})
        sg_name = sg_details.get('GroupName', '')
        
        # Format ingress rules
        rules_list = sg_details.get('IpPermissions', [])
        if rules_list:
            formatted_rules = []
            for rule in rules_list:
                from_port = rule.get('FromPort', 'N/A')
                to_port = rule.get('ToPort', 'N/A')
                protocol = rule.get('IpProtocol', 'N/A')
                ip_ranges = [ip.get('CidrIp', 'N/A') for ip in rule.get('IpRanges', [])]
                ip_ranges_str = ', '.join(ip_ranges) if ip_ranges else 'N/A'
                formatted_rules.append(f"Protocol: {protocol}, Ports: {from_port}-{to_port}, IP Ranges: {ip_ranges_str}")
            ingress_rules = '\n'.join(formatted_rules)
    
    # Build normalized object
    normalized = {
        'Finding_name': name,
        'Finding_description': description,
        'year': time_parts['year'],
        'month': time_parts['month'],
        'day': time_parts['day'],
        'time': time_parts['time'],
        'security_group_id': sg_id,
        'security_group_name': sg_name,
        'account_name': account_name,
        'region': region,
        'severity': severity,
        'ingress_rules': ingress_rules or 'No ingress rules',
        'user_name': user_name,
        'source': 'aws.securityhub'
    }
    
    return normalized


# ============= Strategy Registry =============

NORMALIZERS = {
    'aws.guardduty': normalize_guardduty_finding,
    'aws.securityhub': normalize_securityhub_finding
}


# ============= Unified Interface =============

class UnifiedSecurityHandler:
    """
    Unified handler for all security event sources.
    Uses strategy pattern to normalize different event types.
    """
    
    @staticmethod
    def build_event_envelope(outer_event, finding, source=None, user_name=None):
        """
        Build a unified event envelope for any security finding.
        
        Args:
            outer_event: The EventBridge outer envelope
            finding: The finding detail
            source: Optional source override (auto-detected from outer_event if not provided)
            user_name: Optional username of the person who triggered the event (for SecurityHub)
        
        Returns:
            Complete event dict ready for store_finding()
        """
        
        # Auto-detect source
        if not source:
            source = outer_event.get('source', '')
        
        # Select appropriate normalizer
        normalizer = NORMALIZERS.get(source)
        if not normalizer:
            raise ValueError(f"Unsupported event source: {source}")
        
        # Normalize the finding (pass user_name for SecurityHub)
        if source == 'aws.securityhub':
            normalized = normalizer(outer_event, finding, user_name=user_name)
        else:
            normalized = normalizer(outer_event, finding)

        # Deterministic record id to support idempotent writes
        finding_id = finding.get('Id') or finding.get('GeneratorId') or outer_event.get('id', '')
        event_time = outer_event.get('time') or finding.get('UpdatedAt') or finding.get('LastObservedAt') or ''
        identity = f"{source}|{finding_id}|{event_time}"
        record_id = hashlib.sha1(identity.encode()).hexdigest()
        
        # Build envelope
        event_envelope = {
            'version': outer_event.get('version', '0'),
            'id': outer_event.get('id', str(uuid.uuid4())),
            'detail-type': outer_event.get('detail-type', f'{source} Finding'),
            'source': source,
            'account': outer_event.get('account'),
            'time': outer_event.get('time'),
            'region': outer_event.get('region'),
            'record_id': record_id,
            'detail': normalized
        }
        
        return event_envelope
    
    @staticmethod
    def store_finding_to_db(outer_event, finding, source=None, user_name=None):
        """
        Store any security finding to DynamoDB using unified storage handler.
        
        Args:
            outer_event: The EventBridge outer envelope
            finding: The security finding detail
            source: Optional source override
            user_name: Optional username of the person who triggered the event (for SecurityHub)
        
        Returns:
            Boolean indicating success/failure
        """
        try:
            event_envelope = UnifiedSecurityHandler.build_event_envelope(
                outer_event, finding, source, user_name=user_name
            )
            store_finding(event_envelope)
            print(f"✓ Stored {source or outer_event.get('source')} finding to DynamoDB: {finding.get('Id', 'unknown')}")
            return True
        except Exception as e:
            print(f"Error storing to DynamoDB: {e}")
            return False


# ============= Backward Compatibility Helpers =============

def build_event_envelope(outer_event, finding, user_name=None):
    """Legacy function for backward compatibility."""
    return UnifiedSecurityHandler.build_event_envelope(outer_event, finding, user_name=user_name)


def store_finding_to_db(outer_event, finding, user_name=None):
    """Legacy function for backward compatibility."""
    return UnifiedSecurityHandler.store_finding_to_db(outer_event, finding, user_name=user_name)
