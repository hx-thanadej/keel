.PHONY: dev api web test lint build image

GOLANGCI_LINT := github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 # keep in sync with ci.yml

# Run API and portal together (Ctrl-C stops both).
dev:
	@trap 'kill 0' INT TERM; $(MAKE) api & $(MAKE) web & wait

api:
	go run ./cmd/keel-api

web:
	cd web && pnpm install --frozen-lockfile && pnpm dev

test:
	go test -race ./...

lint:
	go vet ./...
	go run $(GOLANGCI_LINT) run
	test -z "$$(gofmt -l .)"
	cd web && pnpm lint

build:
	go build ./...
	cd web && pnpm build

image:
	docker build -t keel-api:dev .
