FROM python:3.9-slim-buster

RUN pip3 install poetry pytest pytest-watch boto3 moto black

RUN mkdir /opt/sechub-integration

WORKDIR /opt/sechub-integration