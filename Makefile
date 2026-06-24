.PHONY: fmt test race vet wasm check clean

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w ./cmd ./internal

wasm:
	mkdir -p dist/wasm
	GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -o dist/wasm/wallet.wasm ./cmd/walletwasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" dist/wasm/wasm_exec.js
	chmod 644 dist/wasm/wallet.wasm dist/wasm/wasm_exec.js

check: fmt test vet wasm

clean:
	rm -rf dist
