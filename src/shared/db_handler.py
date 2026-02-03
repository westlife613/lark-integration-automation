"""
DynamoDB storage handler for security findings.
Handles all database operations independently from Lambda business logic.
"""

import os
import uuid
import boto3
from datetime import datetime
from decimal import Decimal

# Set dummy AWS credentials for local testing if not already set
if not os.environ.get('AWS_ACCESS_KEY_ID'):
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
if not os.environ.get('AWS_SECRET_ACCESS_KEY'):
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'


class SecurityEventsDBHandler:
    """Encapsulates DynamoDB operations for security events (GuardDuty, SecurityHub, etc.)."""
    
    def __init__(self, table_name=None, region=None, endpoint_url=None):
        """
        Initialize the DynamoDB handler.
        
        Args:
            table_name: DynamoDB table name (default: security-events)
            region: AWS region (default: us-east-1)
            endpoint_url: DynamoDB endpoint URL (optional, for local testing)
        """
        self.table_name = table_name or os.environ.get('DDB_TABLE', 'security-events')
        self.region = region or os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION') or 'us-east-1'
        self.endpoint_url = endpoint_url or os.environ.get('DYNAMODB_ENDPOINT')
        
        # Initialize DynamoDB client with proper credentials
        if self.endpoint_url and ('localhost' in self.endpoint_url or '127.0.0.1' in self.endpoint_url):
            # For local DynamoDB testing
            self.dynamodb = boto3.resource(
                'dynamodb',
                endpoint_url=self.endpoint_url,
                region_name=self.region,
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID', 'testing'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY', 'testing')
            )
        else:
            # For production AWS DynamoDB
            self.dynamodb = boto3.resource('dynamodb', region_name=self.region)
        
        self.table = self.dynamodb.Table(self.table_name)
    
    @staticmethod
    def _split_datetime(dt_str):
        """
        Parse ISO8601 datetime string and return year, month, day, time as strings.
        
        Args:
            dt_str: ISO8601 formatted datetime string
            
        Returns:
            Tuple of (year, month, day, time) as strings, or (None, None, None, None) on failure
        """
        try:
            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            return str(dt.year), f"{dt.month:02d}", f"{dt.day:02d}", f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
        except Exception:
            return None, None, None, None
    
    @staticmethod
    def _convert_value(value):
        """
        Convert values to DynamoDB-compatible types.
        
        Args:
            value: Value to convert
            
        Returns:
            DynamoDB-compatible value
        """
        if isinstance(value, float):
            return Decimal(str(value))
        elif isinstance(value, dict):
            return {k: SecurityEventsDBHandler._convert_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [SecurityEventsDBHandler._convert_value(item) for item in value]
        else:
            return value
    
    def _flatten_dict(self, d, prefix=''):
        """
        Flatten nested dictionary structure.
        Special handling for datetime fields: splits them into year, month, day, time components.
        
        Args:
            d: Dictionary to flatten
            prefix: Prefix for keys (used in recursion)
            
        Returns:
            Flattened dictionary
        """
        item = {}
        
        def flatten_recursive(d, prefix=''):
            for key, value in d.items():
                full_key = f"{prefix}{key}" if prefix else key
                
                if isinstance(value, dict):
                    new_prefix = "" if full_key == "detail" else f"{full_key}_"
                    flatten_recursive(value, new_prefix)
                elif isinstance(value, str) and 'T' in value and ('Z' in value or '+' in value):
                    # Handle datetime fields
                    year, month, day, time_part = self._split_datetime(value)
                    if year:
                        if full_key == "time":
                            # For top-level 'time' field, use simple names
                            item["year"] = year
                            item["month"] = month
                            item["day"] = day
                            item["time"] = time_part
                        else:
                            # For other datetime fields, use prefix
                            item[f"{full_key}_year"] = year
                            item[f"{full_key}_month"] = month
                            item[f"{full_key}_day"] = day
                            item[f"{full_key}_time"] = time_part
                    # Don't save the full timestamp for 'time' field
                    if full_key != "time":
                        item[full_key] = value
                else:
                    item[full_key] = self._convert_value(value)
        
        flatten_recursive(d, prefix)
        return item
    
    def store_finding(self, event_dict):
        """
        Store a security event (e.g., GuardDuty, SecurityHub) in DynamoDB.
        
        The event is flattened so that nested 'detail' fields become top-level columns.
        Datetime fields are automatically split into year, month, day, and time components.
        A unique record_id is generated for each record.
        
        Args:
            event_dict: The complete event dictionary (GuardDuty, SecurityHub, etc.)
            
        Returns:
            record_id of the stored item
            
        Raises:
            Exception: If DynamoDB operation fails
        """
        # Flatten the event dictionary
        item = self._flatten_dict(event_dict)
        
        # Add unique record identifier (prefer provided deterministic id)
        record_id = event_dict.get('record_id') or str(uuid.uuid4())
        item['record_id'] = record_id
        
        # Store in DynamoDB
        self.table.put_item(Item=item)
        
        return record_id


# Module-level convenience functions for easy integration
_default_handler = None


def get_db_handler():
    """Get or create the default database handler instance."""
    global _default_handler
    if _default_handler is None:
        _default_handler = SecurityEventsDBHandler()
    return _default_handler


def store_finding(event_dict):
    """
    Convenience function to store a finding using the default handler.
    
    Args:
        event_dict: The security event dictionary
        
    Returns:
        record_id of the stored item
    """
    handler = get_db_handler()
    return handler.store_finding(event_dict)
