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
	GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -o extension/wallet.wasm ./cmd/walletwasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" extension/wasm_exec.js
	chmod 644 extension/wallet.wasm extension/wasm_exec.js

extension: fmt test vet js-check manifest wasm

package: extension
	rm -f fluxo-web3-wallet-opensource-extension.zip
	cd extension && zip -r ../fluxo-web3-wallet-opensource-extension.zip .
