.PHONY: test vet fmt js-check manifest wasm extension package

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w ./cmd ./internal

js-check:
	node --check extension/popup.js

manifest:
	go test ./internal/extensioncheck

wasm:
	GOOS=js GOARCH=wasm go build -trimpath -o extension/wallet.wasm ./cmd/walletwasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" extension/wasm_exec.js

extension: fmt test vet js-check manifest wasm

package: extension
	rm -f go-web3-wallet-extension.zip
	cd extension && zip -r ../go-web3-wallet-extension.zip .
