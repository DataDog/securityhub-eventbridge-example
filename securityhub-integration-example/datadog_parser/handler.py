import boto3
import botocore
import json
import logging
import sys
import uuid

from copy import deepcopy
from datetime import datetime
from distutils.log import error


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
logging.getLogger("s3transfer").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
stdout_handler = logging.StreamHandler(sys.stdout)
handlers = [stdout_handler]
logging.basicConfig(
    format="[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s",
    handlers=handlers,
)


SUCCESS_MESSAGE = {
    "statusCode": 200,
    "body": json.dumps("Datadog event successfully sent to security hub."),
}

FAILURE_MESSAGE = {
    "statusCode": 500,
    "body": json.dumps("Datadog event failed to send to security hub."),
}


# Only Cloud SIEM is supported in initial release
SUPPORTED_FINDING_TYPES = ["Security Monitoring"]
SUPPORT_SOURCE_TYPES = ["cloudtrail"]


RESOURCE_DATASTRUCTURE = dict(
    Type=None, Id=None, Partition=None, Region=None, Tags=dict(), Details=None
)


SECURITHUB_DATASTRUCTURE = dict(
    AwsAccountId=None,
    Title=None,
    Description=None,  # 1024 Character Limit
    CreatedAt=None,  # Must be ISO8601
    UpdatedAt=None,  # Must be ISO8601,
    GeneratorId=None,  # Should be rule id
    Id=None,  # Generated UUID region/acct-id/uuid4.hex
    ProductArn=None,  # arn:aws:securityhub:us-west-2:222222222222:product/generico/secure-pro
    Resources=None,  # A list of the effected resources
    SchemaVersion="2018-10-08",
    Severity=dict(Label=None, Original=None),
    Types=None,  # namespace/category/classifier,
)


def generate_id(event):
    aws_account_id = event["detail"]["meta"]["signal"]["attributes"]["custom"][
        "recipientAccountId"
    ]
    region = event["detail"]["meta"]["signal"]["logs_sample"][0]["content"]["custom"][
        "awsRegion"
    ]
    unique_id = uuid.uuid4().hex
    return f"{aws_account_id}/{region}/{unique_id}"


def map_severity(severity):
    if severity == "info":
        return "INFORMATIONAL"
    # All other Datadog severity is aligned with the spec.
    else:
        return severity.upper()


def ts_to_iso(timestamp):
    timestamp = timestamp / 1000
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def get_asff4_event_tag(event):
    # Section for creating Security Hub ASFF
    asff4_event_tag = ""
    detail_tags = event["detail"]
    event_tags = detail_tags["tags"]
    logger.debug(f"This is the tag format {event_tags}")

    asff4_event_tags = []

    for x in event_tags:
        if x == "iaas:aws":
            for y in event_tags:
                logger.debug(f"event_tag: {y}")

                if y == "tactic:ta0001-initital-access":
                    asff4_event_tag = "TTPs/Inititial Access"
                    asff4_event_tags.append(asff4_event_tag)
                elif y == "tactic:ta0002-execution":
                    asff4_event_tag = "TTPs/Execution"
                    asff4_event_tags.append(asff4_event_tag)

                elif y == "tactic:ta0003-persistence":
                    asff4_event_tag = "TTPs/Persistence"
                    asff4_event_tags.append(asff4_event_tag)

                elif y == "tactic:ta0004-privilege-escalation":
                    asff4_event_tag = "TTPs/Privilege Escalation"
                    asff4_event_tags.append(asff4_event_tag)

                elif y == "tactic:ta0005-defense-evasion":
                    asff4_event_tag = "TTPs/Defense Evasion"
                    asff4_event_tags.append(asff4_event_tag)

                elif y == "tactic:ta0006-credential-access":
                    asff4_event_tag = "TTPs/Credential Access"
                    asff4_event_tags.append(asff4_event_tag)

                elif y == "tactic:ta0007-discovery":
                    asff4_event_tag = "TTPs/Discovery"
                    asff4_event_tags.append(asff4_event_tag)

                elif y == "tactic:ta0008-lateral-movement":
                    asff4_event_tag = "TTPs/Lateral Movement"
                    asff4_event_tags.append(asff4_event_tag)

                elif y == "tactic:ta0009-Collection":
                    asff4_event_tag = "TTPs/Collection"
                    asff4_event_tags.append(asff4_event_tag)

                elif y == "tactic:ta0011-command-control":
                    asff4_event_tag = "TTPs/Command and Control"
                    asff4_event_tags.append(asff4_event_tag)


    logger.debug(f"asf44_tag: {asff4_event_tag}")

    return asff4_event_tags


def datadog_finding_to_asff4(event):
    logger.debug("Attempting conversion of finding to ASFF formatting")
    event_bridge_region = event["region"]
    event_bridge_acct_id = event["account"]

    asff_event = deepcopy(SECURITHUB_DATASTRUCTURE)
    asff_event["AwsAccountId"] = event["detail"]["meta"]["signal"]["attributes"][
        "custom"
    ]["recipientAccountId"]
    asff_event["Title"] = event["detail"]["meta"]["signal"]["rule"]["name"]
    asff_event["Description"] = event["detail"]["msg_title"]
    asff_event["CreatedAt"] = str(ts_to_iso(event["detail"]["date_detected"]))
    asff_event["UpdatedAt"] = str(ts_to_iso(event["detail"]["last_updated"]))
    asff_event["GeneratorId"] = event["detail"]["meta"]["signal"]["rule"]["id"]
    asff_event["Id"] = generate_id(event)
    asff_event[
        "ProductArn"
    ] = f"arn:aws:securityhub:{event_bridge_region}:{event_bridge_acct_id}:product/{event_bridge_acct_id}/default"
    asff_event["Resources"] = [
        dict(
            Type=event["detail"]["meta"]["signal"]["logs_sample"][0]["content"][
                "custom"
            ]["eventSource"],
            Id=json.dumps(
                event["detail"]["meta"]["signal"]["logs_sample"][0]["content"][
                    "custom"
                ]["requestParameters"]
            ),
        )
    ]
    asff_event["Severity"] = dict(
        Label=map_severity(event["detail"]["meta"]["signal"]["severity"]),
        Original=event["detail"]["meta"]["signal"]["severity"],
    )
    asff_event["Types"] = get_asff4_event_tag(
        event
    )  # Need to add this metadata to our alert tags

    asff_event_type_debug = asff_event["Types"]
    logger.debug(f"Here are the types for the asff event: {asff_event_type_debug}")
    return asff_event


def send_to_security_hub(client, findings):
    try:
        resp = client.batch_import_findings(Findings=findings)
    except Exception as e:
        resp = None
        logger.error(f"Findings could not be sent to security hub due to: {e}")
    return resp


def is_eligible_event(event):
    eligible = False
    if event["detail"]["source_type_name"] in SUPPORTED_FINDING_TYPES:
        eligible = True 
        logger.debug(f"The event is not eligible to be sent to security hub.")

    if "iaas:aws" in event["detail"]["tags"]:
        eligible = True
    
    if "securityhub" in event["detail"]["tags"]:
        eligible = True

    logger.debug(f"The event eligibility to send to security hub is: {eligible}.")
    return eligible



def handle(event={}, context={}):
    if is_eligible_event(event):
        try:
            client = boto3.client("securityhub")
        except botocore.exceptions.ClientError as e:
            logger.error(f"SecurityHub client could not be initialized due to: {e}.")

        # Initialize a list to store findings in the Security Hub format
        findings = []
        findings.append(datadog_finding_to_asff4(event))
        send_to_security_hub(client, findings)
        logger.debug("Datadog event to security hub function active.")
        return SUCCESS_MESSAGE
    else:
        logger.debug("The event can not be sent to security hub.")
        return FAILURE_MESSAGE
