.PHONY: all build test fmt hooks clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/bugrouter ./cmd/bugrouter

test:
	go vet ./...
	go test -race -v ./...

fmt:
	go fmt ./...

hooks:
	mkdir -p .git/hooks
	cp scripts/commit-msg .git/hooks/commit-msg
	chmod +x .git/hooks/commit-msg

clean:
	rm -rf bin/
