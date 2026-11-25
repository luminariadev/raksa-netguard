APP := raksa-netguard
PKG := ./cmd/raksa-netguard
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: build test test-race cover vet clean docker-build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(APP) $(PKG)

test:
	go test -v ./...

test-race:
	go test -race -v ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vet:
	go vet ./...

clean:
	rm -rf bin dist coverage.out

docker-build:
	docker build -t $(APP):$(VERSION) .
