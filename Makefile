GO ?= go
BIN := scomp

.PHONY: build vet lint test bench check clean

# Same checks as CI: build, vet, golangci-lint (v2.15.0), tests with -race.
check: build vet lint test

build: $(BIN)

$(BIN): main.go go.mod go.sum $(shell find . -name '*.go' -not -name '*_test.go')
	$(GO) build -o $@ .

vet:
	$(GO) vet ./...

lint:
	golangci-lint run

test:
	$(GO) test -race ./...

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./internal/tui/ ./internal/scanner/ ./internal/repo/

clean:
	rm -f $(BIN)
