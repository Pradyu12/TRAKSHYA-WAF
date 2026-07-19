-include .env
export

.PHONY: build run smoke regression test clean certs lint pre-commit-run \
        docker-build docker-up docker-down docker-push k8s-apply k8s-rollout openapi-validate changelog help

REPO_ROOT := $(shell pwd)
BUILD_DIR := $(REPO_ROOT)/build
CARGO ?= cargo

help:
	@echo "TRAKSHYA-WAF Make targets"
	@echo ""
	@echo "  build               - build proxy/api/c daemon"
	@echo "  run                 - run local services"
	@echo "  test                - smoke + regression"
	@echo "  smoke               - run smoke tests"
	@echo "  regression          - run regression suite"
	@echo "  lint                - pre-commit run on all files"
	@echo "  pre-commit-run      - pre-commit run on changed files"
	@echo "  certs               - generate localhost dev certs"
	@echo "  docker-build        - build docker images"
	@echo "  docker-up           - docker compose up"
	@echo "  docker-down         - docker compose down"
	@echo "  docker-push         - docker compose build and push"
	@echo "  k8s-apply           - apply kubernetes manifests"
	@echo "  k8s-rollout         - rolling restart kubernetes deployments"
	@echo "  openapi-validate    - validate openapi.yml schema"
	@echo "  changelog           - show unreleased changes"
	@echo "  clean               - remove build artifacts"

build:
	@bash scripts/build-all.sh

run:
	@bash scripts/run-all.sh

smoke:
	@python3 scripts/smoke-test.py

regression:
	@python3 scripts/regression.py

test: build
	@bash scripts/test-all.sh

lint:
	@if [ -x /tmp/precommit-venv/bin/pre-commit ]; then \
		/tmp/precommit-venv/bin/pre-commit run --all-files; \
	else \
		pre-commit run --all-files; \
	fi

pre-commit-run:
	@if [ -x /tmp/precommit-venv/bin/pre-commit ]; then \
		/tmp/precommit-venv/bin/pre-commit run --files; \
	else \
		pre-commit run --files; \
	fi

certs:
	@bash scripts/generate-dev-certs.sh

docker-build:
	docker compose -f docker-compose.stack.yml build

docker-up:
	docker compose -f docker-compose.stack.yml up -d --build

docker-down:
	docker compose -f docker-compose.stack.yml down

docker-push:
	docker compose -f docker-compose.stack.yml build
	docker compose -f docker-compose.stack.yml push

k8s-apply:
	kubectl apply -f k8s/

k8s-rollout:
	kubectl rollout restart deployment/trakshya-proxy deployment/trakshya-api deployment/trakshya-dashboard -n trakshya-waf
	kubectl rollout status deployment/trakshya-proxy -n trakshya-waf
	kubectl rollout status deployment/trakshya-api -n trakshya-waf
	kubectl rollout status deployment/trakshya-dashboard -n trakshya-waf

openapi-validate:
	@command -v openapi-generator >/dev/null 2>&1 || (echo "missing openapi-generator-cli, try: npm i -g @openapitools/openapi-generator-cli" && exit 1)
	openapi-generator validate -i openapi.yml

changelog:
	@sed -n '/## Unreleased/,/## [0-9]/p' CHANGELOG.md | sed '$$d'

clean:
	rm -rf $(BUILD_DIR) rust/target go/trakshya-api c/build
