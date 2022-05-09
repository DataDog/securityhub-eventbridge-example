
import boto3
import json
import logging
import sys
import uuid

from copy import deepcopy
from datetime import datetime


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
stdout_handler = logging.StreamHandler(sys.stdout)
handlers = [stdout_handler]
logging.basicConfig(
    format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s',
    handlers=handlers
)

SUCCESS_MESSAGE = {
    'statusCode': 200,
    'body': json.dumps("Datadog event successfully sent to security hub.")
}

# Only Cloud SIEM is supported in initial release
SUPPORTED_FINDING_TYPES = ["Security Monitoring"]
SUPPORT_SOURCE_TYPES = ["cloudtrail"]
EXCLUDED_TYPES = []

RESOURCE_DATASTRUCTURE = dict(
    Type=None,
    Id=None,
    Partition=None,
    Region=None,
    Tags=dict(),
    Details=None
)

SECURITHUB_DATASTRUCTURE = dict(
    AwsAccountId=None,
    Title=None,
    Description=None, # 1024 Character Limit
    CreatedAt=None, # Must be ISO8601
    UpdatedAt=None, # Must be ISO8601,
    GeneratorId=None, # Should be rule id
    Id=None, # Generated UUID region/acct-id/uuid4.hex 
    ProductArn=None, # arn:aws:securityhub:us-west-2:222222222222:product/generico/secure-pro
    Resources=None, # A list of the effected resources
    SchemaVersion="2018-10-08",
    Severity=dict(Label=None,Original=None),
    Types=None # namespace/category/classifier,
)


def generate_id(event):
    aws_account_id = event["detail"]["meta"]["signal"]["attributes"]["custom"]["recipientAccountId"]
    region = event["detail"]["meta"]["signal"]["logs_sample"][0]["content"]["custom"]["awsRegion"]
    unique_id = uuid.uuid4().hex
    return f"{aws_account_id}/{region}/{unique_id}"


def map_severity(severity):
    if severity == "info":
        return "INFORMATIONAL"
    else:
        return severity.upper()

def ts_to_iso(timestamp):
    timestamp = timestamp / 1000
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def datadog_finding_to_asff4(event):
    logger.debug("Attempting conversion of finding to ASFF formatting")
    event_bridge_region = event["region"]
    event_bridge_acct_id = event["account"]

    asff_event = deepcopy(SECURITHUB_DATASTRUCTURE)
    asff_event['AwsAccountId'] = event["detail"]["meta"]["signal"]["attributes"]["custom"]["recipientAccountId"]
    asff_event['Title'] = event["detail"]["meta"]["signal"]["rule"]["name"]
    asff_event['Description'] = event["detail"]["msg_title"]
    asff_event['CreatedAt'] = str(ts_to_iso(event["detail"]["date_detected"]))
    asff_event['UpdatedAt'] = str(ts_to_iso(event["detail"]["last_updated"]))
    asff_event['GeneratorId'] = event["detail"]["meta"]["signal"]["rule"]["id"]
    asff_event["Id"] = generate_id(event)
    asff_event["ProductArn"] = f"arn:aws:securityhub:{event_bridge_region}:{event_bridge_acct_id}:product/{event_bridge_acct_id}/default"
    asff_event["Resources"] = [
        dict(
            Type=event["detail"]["meta"]["signal"]["logs_sample"][0]["content"]["custom"]["eventSource"],
            Id=json.dumps(event["detail"]["meta"]["signal"]["logs_sample"][0]["content"]["custom"]["requestParameters"])
        )
    ] # How the heck do I get this
    asff_event["Severity"] = dict(
        Label=map_severity(event["detail"]["meta"]["signal"]["severity"]),
        Original=event["detail"]["meta"]["signal"]["severity"]
    )
    asff_event["Types"] = ["TTPs"] # Need to add this metadata to our alert tags
    return asff_event


def send_to_security_hub(client, findings):
    try:
        resp = client.batch_import_findings(
            Findings=findings
        )
    except Exception as e:
        resp = None
        print(e)
    return resp


def handle(event={}, context={}):
    if event["detail"]["source_type_name"] in SUPPORTED_FINDING_TYPES:

        try:
            client = boto3.client('securityhub')
        except ClientException as e:
            logger.error(f"SecurityHub client could not be initialized due to: {e}.")

        # Initialize a list to store findings in the Security Hub format
        findings = []
        findings.append(datadog_finding_to_asff4(event))
        send_to_security_hub(client, findings)
        logger.debug("Datadog event to security hub function active.")
    return SUCCESS_MESSAGE