.PHONY: build run test lint clean

BIN_DIR := bin
BINARY  := $(BIN_DIR)/csar-authn

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BINARY) ./cmd/csar-authn

run: build
	$(BINARY) -config config.yaml

test:
	go test ./... -count=1

test-race:
	go test ./... -race -count=1

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BIN_DIR) keys
