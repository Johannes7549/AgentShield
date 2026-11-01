.PHONY: test lint

test:
	go test ./runtime/gateway/... ./runtime/identity/... ./runtime/policy-engine/...
	python -m unittest discover -s tests -v
	PYTHONPATH=apps/intelligence-engine python -m unittest discover -s apps/intelligence-engine/tests -v
	npm test

lint:
	test -z "$$(gofmt -l runtime)"
	python -m ruff check apps/intelligence-engine tests
	npm run lint
