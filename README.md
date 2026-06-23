# go-web3-wallet

Minimal Ethereum wallet browser extension powered by a Go WebAssembly core.

The extension is local-first: it does not call RPC providers, does not broadcast transactions, does not inject a provider into pages, and does not send wallet data to any server. The current scope is intentionally narrow: create an encrypted local vault, unlock it locally, show the address, and sign EIP-191 messages.

## Architecture

- `internal/walletcore`: Go wallet core for secp256k1 key generation, Ethereum address derivation, and EIP-191 message signing.
- `cmd/walletwasm`: small WASM bridge that exposes the Go wallet core to the extension.
- `extension`: Manifest V3 popup UI, local encrypted vault, and WebCrypto storage.

The private key is generated in the Go WASM core. The popup encrypts it with AES-GCM using a PBKDF2-SHA256 key derived from the user's vault password, then stores only the encrypted vault in `chrome.storage.local`.

## Build

```sh
make extension
```

This writes:

- `extension/wallet.wasm`
- `extension/wasm_exec.js`

## Load Locally

1. Run `make extension`.
2. Open Chrome or a Chromium-based browser.
3. Go to `chrome://extensions`.
4. Enable Developer Mode.
5. Click "Load unpacked".
6. Select the `extension/` directory.

## Package

```sh
make package
```

The zip file is created as `go-web3-wallet-extension.zip`.

## Current Capabilities

- Generate a local Ethereum private key.
- Derive the Ethereum address.
- Encrypt the private key locally with AES-GCM.
- Unlock the vault for the current popup session.
- Sign EIP-191 messages.
- Copy address and signature.
- Reset the local vault.

## Non-Goals

- No hosted custody.
- No token balances.
- No RPC calls.
- No transaction broadcasting.
- No page provider injection.
- No dapp permissions system yet.

Those are intentionally omitted to keep the security surface small.

## Security

See [SECURITY.md](SECURITY.md).
