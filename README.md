![Fluxo Web3 Wallet banner](docs/assets/fluxo-banner.png)

# Fluxo Web3 Wallet

Fluxo is a minimal open-source Ethereum wallet browser extension powered by a Go WebAssembly core.

The extension is local-first: it does not call RPC providers, does not broadcast transactions, does not inject a provider into pages, and does not send wallet data to any server. The current scope is intentionally narrow: create an encrypted local vault, unlock it locally, show the address, and sign EIP-191 messages.

## Architecture

- `internal/walletcore`: Go wallet core for secp256k1 key generation, Ethereum address derivation, and EIP-191 message signing.
- `internal/vault`: Go-owned vault encryption, metadata validation, v1 migration, and in-memory session locking.
- `internal/walletruntime`: application boundary that creates/unlocks vaults and signs messages only through session IDs.
- `cmd/walletwasm`: small WASM bridge exposing the session-based wallet API to the extension.
- `extension`: Manifest V3 popup UI that stores only the encrypted vault JSON in `chrome.storage.local`.

The private key is generated, encrypted, decrypted, and used for signing inside the Go WASM core. JavaScript receives an address, encrypted vault JSON, and short-lived `sessionId`; it does not receive the private key.

## Vault v2

New vaults use the v2 format:

- KDF: Argon2id, 256 MiB memory, 4 passes, `p=1`, 32-byte salt, 32-byte key.
- Cipher: XChaCha20-Poly1305 with a 24-byte nonce.
- AAD: canonical vault header metadata, including version, cipher, KDF params, address, and creation time.
- Storage: `chrome.storage.local` contains only encrypted vault JSON.
- Migration: legacy v1 PBKDF2-SHA256/AES-GCM vaults are decrypted only during unlock and immediately re-encrypted as v2.

The KDF policy does not silently downgrade below the v2 defaults.

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

The zip file is created as `fluxo-web3-wallet-opensource-extension.zip`.

## Current Capabilities

- Generate a local Ethereum private key.
- Derive the Ethereum address.
- Encrypt the private key in Go WASM with XChaCha20-Poly1305.
- Unlock the vault into a short-lived in-memory Go session.
- Sign EIP-191 messages by `sessionId`.
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

## WASM API

The extension calls these Go-owned methods:

- `createVault(password) -> { vault, address, sessionId }`
- `unlockVault(vault, password) -> { address, sessionId, migratedVault? }`
- `signMessage(sessionId, message) -> { address, hash, signature }`
- `lock(sessionId)`
- `lockAll()`

The API intentionally has no method that returns a private key.

## Security

See [SECURITY.md](SECURITY.md).
