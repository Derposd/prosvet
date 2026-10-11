VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test test-short lint cover tidy snapshot demo gif map clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/prosvet ./cmd/prosvet

test:
	go test -count=1 ./...

test-short:
	go test -short ./...

lint:
	golangci-lint run ./...

cover:
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

tidy:
	go mod tidy

snapshot:
	goreleaser release --snapshot --clean

demo: build
	./bin/prosvet demo

gif: build
	vhs docs/vhs/demo.tape

map:
	go run ./cmd/prosvet-map -results results -out site

clean:
	rm -rf bin dist site coverage.out
