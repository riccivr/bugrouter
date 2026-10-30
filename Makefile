.PHONY: all build test fmt hooks release-dry-run clean

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

release-dry-run:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/bugrouter-linux-amd64 ./cmd/bugrouter
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/bugrouter-linux-arm64 ./cmd/bugrouter
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/bugrouter-darwin-amd64 ./cmd/bugrouter
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/bugrouter-darwin-arm64 ./cmd/bugrouter
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/bugrouter-windows-amd64.exe ./cmd/bugrouter
	cd dist && sha256sum bugrouter-* > SHA256SUMS
	@echo "Dry-run release artifacts compiled in dist/:"
	@ls -lh dist/

clean:
	rm -rf bin/ dist/
