.PHONY: dev api web test lint build image

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
	test -z "$$(gofmt -l .)"
	cd web && pnpm lint

build:
	go build ./...
	cd web && pnpm build

image:
	docker build -t keel-api:dev .
