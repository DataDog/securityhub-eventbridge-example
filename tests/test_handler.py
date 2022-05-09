import json


EVENT_FIXTURE = None


fh = open('fixtures/eventbridge.json')
EVENT_FIXTURE = json.loads(fh.read())
fh.close()


def test_handler():
    import handler
    event = EVENT_FIXTURE
    result = handler.handle(event, context={})
    assert result['statusCode'] == 200