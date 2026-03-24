BINARY := defense-kit
BUILD_DIR := bin
VERSION ?= dev

.PHONY: build test clean lint

build:
	go build -ldflags="-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY) ./cmd/defense-kit

test:
	go test ./... -v -race -cover

clean:
	rm -rf $(BUILD_DIR)

lint:
	go vet ./...
