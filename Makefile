.PHONY: test vet fmt wasm extension package

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w ./cmd ./internal

wasm:
	GOOS=js GOARCH=wasm go build -trimpath -o extension/wallet.wasm ./cmd/walletwasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" extension/wasm_exec.js

extension: fmt test vet wasm

package: extension
	cd extension && zip -r ../go-web3-wallet-extension.zip .
