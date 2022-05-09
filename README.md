# Datadog Security Hub Integration

This Cloudformation and accompanying Lambda function seek to create a one-way integration from Datadog's security products to AWS Security Hub.

## Deployment

1. Configure the Datadog Event Bridge Integration
2. Create a notification rule naming @awseventbridge-YOUR_BRIDGE_NAME as the destination
3. Deploy the datadog-security-hub.yml Cloudformation Stack in your account.  The only parameter it takes is the name of the EventBus

## Architecture Diagram

TBD

## Testing

1. Run `make build` _This builds the testing docker container_
2. Run `make test`


### License

This project is licensed under the Apache 2 License