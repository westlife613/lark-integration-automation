"""
CloudTrail helper to query and extract user information from security group events.
Used to identify who created/modified security group rules for @ mentioning in Lark.
"""

import boto3
import re
import json
from datetime import datetime, timedelta


class CloudTrailHelper:
    """Helper to query CloudTrail for security group events and extract user info."""
    
    def __init__(self, region_name='us-east-1'):
        """Initialize CloudTrail client."""
        self.client = boto3.client('cloudtrail', region_name=region_name)
    
    
    def query_security_group_events(self, sg_id):
        """
        Query CloudTrail for AuthorizeSecurityGroupIngress events related to a security group.
        
        Args:
            sg_id: Security group ID (e.g., 'sg-1234567890abcdef0')
        
        Returns:
            List of matching events with user info, or empty list on error
        """
        try:
            # Query CloudTrail (default supports 90 days of events)
            response = self.client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'ResourceName',
                        'AttributeValue': sg_id
                    }
                ],
                EventNames=['AuthorizeSecurityGroupIngress'],
                MaxResults=50
            )
            
            return response.get('Events', [])
        except Exception as e:
            print(f"Error querying CloudTrail for {sg_id}: {e}")
            return []
    
    @staticmethod
    def extract_email_from_principal_id(principal_id):
        """
        从principalId字符串中提取邮箱地址。
        例如：'AROA6IRLQSYCFV5MSLRBY:user@example.com' -> 'user@example.com'
        """
        if not principal_id or '@' not in principal_id:
            return None
        # 匹配邮箱格式
        match = re.search(r'([\w\.-]+@[\w\.-]+)', principal_id)
        if match:
            return match.group(1)
        return None
    
    def get_sg_creator_email(self, sg_id):
        """
        获取安全组创建者的邮箱地址。
        
        Args:
            sg_id: Security group ID
        
        Returns:
            创建者邮箱地址，如果未找到则返回 None
        """
        events = self.query_security_group_events(sg_id)
        for event in events:
            try:
                cloud_trail_event = event.get('CloudTrailEvent')
                if isinstance(cloud_trail_event, str):
                    cloud_trail_event = json.loads(cloud_trail_event)
                user_identity = cloud_trail_event.get('userIdentity', {})
                principal_id = user_identity.get('principalId')
                if principal_id:
                    email = self.extract_email_from_principal_id(principal_id)
                    if email:
                        print(f"Found SG creator email: {email}")
                        return email
            except Exception as e:
                print(f"Error parsing CloudTrail event: {e}")
                continue
        return None
    
    def get_sg_creator_lark_id(self, sg_id, app_id, app_secret):
        """
        获取安全组创建者的Lark open_id（用于@提及）。
        
        Args:
            sg_id: Security group ID
            app_id: Lark App ID
            app_secret: Lark App Secret
        
        Returns:
            创建者的 Lark open_id，如果未找到则返回 None
        """
        import requests
        
        email = self.get_sg_creator_email(sg_id)
        if not email:
            return None
        
        try:
            # 获取 tenant_access_token
            auth_response = requests.post(
                'https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal',
                json={
                    'app_id': app_id,
                    'app_secret': app_secret
                },
                headers={'Content-Type': 'application/json'}
            )
            auth_data = auth_response.json()
            if auth_data.get('code') != 0:
                print(f"Failed to get tenant_access_token: {auth_data}")
                return None
            
            token = auth_data['tenant_access_token']
            
            # 调用 batch_get_id API
            api_response = requests.post(
                'https://open.feishu.cn/open-apis/contact/v3/users/batch_get_id?user_id_type=open_id',
                json={'emails': [email]},
                headers={
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json'
                }
            )
            
            result = api_response.json()
            if result.get('code') == 0 and result.get('data', {}).get('user_list'):
                open_id = result['data']['user_list'][0]['user_id']
                print(f"Found Lark user open_id: {open_id} for email: {email}")
                return open_id
            else:
                print(f"User not found in Lark for email: {email}. Response: {result}")
        except Exception as e:
            print(f"Error querying Lark API: {e}")
        
        return None
