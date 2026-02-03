import json
import sys
import os
import boto3
import lark_oapi as lark
from lark_oapi.api.im.v1 import *

# Import from shared layer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'shared'))
from unified_handler import UnifiedSecurityHandler
from cloudtrail_helper import CloudTrailHelper


def get_secure_param(ssm, name):
    response = ssm.get_parameter(
        Name=name,
        WithDecryption=True
    )
    return response['Parameter']['Value']


def post_message(app_id, app_secret, chat_id, finding_time, finding, region):
    if finding.get("AwsAccountId") == "871573024438":
        print("Ignore VIG account")
        return
    else:
        print("Posting message")

    account_name = finding.get("AwsAccountName")
    severity_code = finding.get("Severity").get("Normalized", 0)/10
    title = finding.get("Title")
    description = finding.get("Description")

    if severity_code <= 3.9:
        severity_emoji = "🟢"
    elif severity_code <= 6.9:
        severity_emoji = "🟠"
    else:
        severity_emoji = "🔴"

    client = lark.Client.builder() \
        .app_id(app_id) \
        .app_secret(app_secret) \
        .log_level(lark.LogLevel.DEBUG) \
        .build()

    for resource in finding.get("Resources"):
        print("Iterate resources")
        sg_id = resource.get("Details").get("AwsEc2SecurityGroup").get("GroupId")
        sg_name = resource.get("Details").get("AwsEc2SecurityGroup").get("GroupName")
        sg_arn = resource.get("Id")
        ingress_ip_permission = resource.get("Details").get("AwsEc2SecurityGroup").get("IpPermissions")
        formatted_permissions = []
        for ip_permission in ingress_ip_permission:
            from_port = ip_permission.get("FromPort", "N/A")
            to_port = ip_permission.get("ToPort", "N/A")
            protocol = ip_permission.get("IpProtocol", "N/A")
            ip_ranges = ", ".join([ip_range.get("CidrIp", "N/A") for ip_range in ip_permission.get("IpRanges", [])])

            formatted_permissions.append(f"Protocol: {protocol}, Ports: {from_port}-{to_port}, IP Ranges: {ip_ranges}")

        formatted_permissions_str = "\n".join(formatted_permissions)
        
        # Query CloudTrail for SG creator and get Lark open_id for @mention
        ct_helper = CloudTrailHelper(region_name=region)
        creator_open_id = ct_helper.get_sg_creator_lark_id(sg_id, app_id, app_secret)
        creator_mention = f"\n<b>Creator</b>: <at user_id=\"{creator_open_id}\"></at>" if creator_open_id else ""
        
        content_dict = {
            "text": f"{severity_emoji} \n<b>Finding Name</b>: {title} \n<b>Finding Description</b>: {description} \n<b>Finding Time</b>: {finding_time}\n<b>Security Group ID</b>: {sg_arn} \n<b>Security Group Name</b>: {sg_name} \n<b>Account Name</b>: {account_name} \n<b>Region</b>: {region} \n<b>Severity</b>: {severity_code} \n<b>Ingress rules</b>: \n{formatted_permissions_str}{creator_mention}"
        }

        request: CreateMessageRequest = CreateMessageRequest.builder() \
            .receive_id_type("chat_id") \
            .request_body(CreateMessageRequestBody.builder() \
            .receive_id(chat_id) \
            .msg_type("text") \
            .content(json.dumps(content_dict)) \
            .build()) \
            .build()

        response: CreateMessageResponse = client.im.v1.message.create(request)

        if response.success():
            print("Message posted successfully")
        else:
            print(f"Failed to post message. Status: {response.code}. Reason: {response.msg}")
            lark.logger.error(
                f"client.im.v1.message.create failed, code: {response.code}, msg: {response.msg}, log_id: {response.get_log_id()}")


def process_event(event):
    ssm = boto3.client('ssm')
    app_id = get_secure_param(ssm, "SYD-Audit-Security-Automation-PROD-Parameter-Lark-APP-ID")
    app_secret = get_secure_param(ssm, "SYD-Audit-Security-Automation-PROD-Parameter-Lark-APP-Secret")
    chat_id = get_secure_param(ssm, "SYD-Audit-Security-Automation-PROD-Parameter-Lark-Chat-ID")
    message = event
    finding_time = message.get("time")
    region = message.get("region")
    
    for finding in message.get("detail").get("findings"):
        # Query CloudTrail for SG creator/modifier
        sg_id = finding.get("Resources", [{}])[0].get("Details", {}).get("AwsEc2SecurityGroup", {}).get("GroupId")
        ct_helper = CloudTrailHelper(region_name=region)
        creator_email = ct_helper.get_sg_creator_email(sg_id) if sg_id else None
        
        # Store to DynamoDB using unified handler (with user_name for SecurityHub)
        UnifiedSecurityHandler.store_finding_to_db(message, finding, user_name=creator_email)
        
        post_message(app_id, app_secret, chat_id, finding_time, finding, region)


def lambda_handler(event, context):
    # show the event in the log
    print(json.dumps(event))

    process_event(event)
