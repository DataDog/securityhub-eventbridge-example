import json
import os

EVENT_FIXTURE = None


fh = open("fixtures/eventbridge.json")
EVENT_FIXTURE = json.loads(fh.read())
fh.close()


def test_handler():
    os.environ["AWS_DEFAULT_REGION"] = "us-west-2"
    from datadog_parser import handler

    event = EVENT_FIXTURE
    result = handler.handle(event, context={})
    assert result["statusCode"] == 200
