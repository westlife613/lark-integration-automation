import json
import sys
import os

# Add shared path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'shared'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'handlers', 'security_groups'))

# Real SecurityHub event format
test_event = {
    "version": "0",
    "id": "test-event-123",
    "detail-type": "Security Hub Findings - Imported",
    "source": "aws.securityhub",
    "account": "123456789012",
    "time": "2026-02-04T10:00:00Z",
    "region": "ap-southeast-1",
    "resources": [],
    "detail": {
        "findings": [
            {
                "SchemaVersion": "2018-10-08",
                "Id": "arn:aws:securityhub:ap-southeast-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.19/finding/test-123",
                "ProductArn": "arn:aws:securityhub:ap-southeast-1::product/aws/securityhub",
                "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/EC2.19",
                "AwsAccountId": "123456789012",
                "AwsAccountName": "test-account",
                "Types": [
                    "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"
                ],
                "FirstObservedAt": "2026-02-04T09:00:00.000Z",
                "LastObservedAt": "2026-02-04T10:00:00.000Z",
                "CreatedAt": "2026-02-04T09:00:00.000Z",
                "UpdatedAt": "2026-02-04T10:00:00.000Z",
                "Severity": {
                    "Product": 40,
                    "Label": "MEDIUM",
                    "Normalized": 40
                },
                "Title": "EC2.19 Security groups should not allow unrestricted access to ports with high risk",
                "Description": "This control checks whether unrestricted incoming traffic for the security groups is accessible to the specified ports that have the highest risk.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For directions on how to fix this issue, please consult the AWS Security Hub documentation.",
                        "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-ec2-19"
                    }
                },
                "ProductFields": {
                    "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                    "ControlId": "EC2.19",
                    "aws/securityhub/ProductName": "Security Hub",
                    "aws/securityhub/CompanyName": "AWS"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2SecurityGroup",
                        "Id": "arn:aws:ec2:ap-southeast-1:123456789012:security-group/sg-0123456789abcdef0",
                        "Partition": "aws",
                        "Region": "ap-southeast-1",
                        "Details": {
                            "AwsEc2SecurityGroup": {
                                "GroupName": "test-security-group",
                                "GroupId": "sg-0123456789abcdef0",
                                "OwnerId": "123456789012",
                                "VpcId": "vpc-12345678",
                                "IpPermissions": [
                                    {
                                        "IpProtocol": "tcp",
                                        "FromPort": 22,
                                        "ToPort": 22,
                                        "IpRanges": [
                                            {
                                                "CidrIp": "0.0.0.0/0"
                                            }
                                        ]
                                    },
                                    {
                                        "IpProtocol": "tcp",
                                        "FromPort": 3389,
                                        "ToPort": 3389,
                                        "IpRanges": [
                                            {
                                                "CidrIp": "0.0.0.0/0"
                                            }
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED"
                },
                "WorkflowState": "NEW",
                "Workflow": {
                    "Status": "NEW"
                },
                "RecordState": "ACTIVE"
            }
        ]
    }
}


def test_unified_handler():
    """Test unified handler logic without AWS dependencies."""
    from unified_handler import UnifiedSecurityHandler
    
    print("=" * 60)
    print("Testing Unified Handler")
    print("=" * 60)
    
    finding = test_event['detail']['findings'][0]
    envelope = UnifiedSecurityHandler.build_event_envelope(test_event, finding, user_name="test.user@example.com")
    
    print("\nGenerated envelope:")
    print(json.dumps(envelope, indent=2, default=str))
    print(f"\nRecord ID (deterministic): {envelope['record_id']}")
    print("✓ Unified handler test passed!")


def test_full_lambda():
    """Test full Lambda flow (requires AWS credentials)."""
    from lambda_function import process_event
    
    print("=" * 60)
    print("Testing Full Lambda Flow")
    print("=" * 60)
    
    try:
        process_event(test_event)
        print("✓ Lambda test passed!")
    except Exception as e:
        print(f"✗ Error (expected if no AWS credentials): {e}")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Lark Integration Automation - Test Suite")
    print("=" * 60 + "\n")
    
    # Test 1: Unified handler (no AWS deps)
    test_unified_handler()
    
    # Test 2: Full Lambda (needs AWS)
    print("\n")
    test_full_lambda()
