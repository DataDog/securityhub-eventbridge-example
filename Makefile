ROOT_DIR	:= $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
PARENTDIR   := $(realpath ../)
GITHASH 	:= $(shell git rev-parse --short HEAD)


.PHONY:all
all:
	@echo 'Available make targets:'
	@grep '^[^#[:space:]\.PHONY.*].*:' Makefile

.PHONY:build
build:
	docker build . -t testing-container

.PHONY:format
format:
	docker run -ti -v $(ROOT_DIR):/opt/sechub-integration testing-container black .

.PHONY:test
test:
	docker run -ti -v $(ROOT_DIR)/securityhub-integration-example:/opt/sechub-integration testing-container pytest

.PHONY:watch
watch:
	docker run -ti -v $(ROOT_DIR)/securityhub-integration-example:/opt/sechub-integration testing-container pytest-watch -- --log-cli-level=DEBUG --capture=tee-sys