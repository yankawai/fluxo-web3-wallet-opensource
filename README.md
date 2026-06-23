![Fluxo Web3 Wallet banner](docs/assets/fluxo-banner.png)

# Fluxo Web3 Wallet

Fluxo is a minimal open-source Web3 wallet browser extension powered by a Go WebAssembly core.

The extension is local-first for custody: seed phrases are generated, encrypted, decrypted, and used for signing inside the Go WASM core. The popup stores only encrypted vault JSON and uses public RPC endpoints only to read native balances.

## Architecture

- `internal/walletcore`: Go wallet core for BIP39 seed phrases, BIP44 Ethereum account derivation, address derivation, and EIP-191 message signing.
- `internal/networks`: built-in EVM network registry for Ethereum, Sepolia, Polygon, Arbitrum, Optimism, and Base.
- `internal/vault`: Go-owned vault encryption, metadata validation, v1 migration, and in-memory session locking.
- `internal/walletruntime`: application boundary that creates/unlocks vaults and signs messages only through session IDs.
- `cmd/walletwasm`: small WASM bridge exposing the session-based wallet API to the extension.
- `extension`: Manifest V3 popup UI that stores only the encrypted vault JSON in `chrome.storage.local`.

The seed phrase is generated, encrypted, decrypted, and used for account derivation inside the Go WASM core. JavaScript receives the seed phrase only once during wallet creation so the user can back it up. After that, JavaScript receives an address, encrypted vault JSON, network metadata, native balances, and a short-lived `sessionId`; it does not receive private keys.

## Vault v3

New vaults use the v3 HD format:

- KDF: Argon2id, 256 MiB memory, 4 passes, `p=1`, 32-byte salt, 32-byte key.
- Cipher: XChaCha20-Poly1305 with a 24-byte nonce.
- AAD: canonical vault header metadata, including version, kind, cipher, KDF params, address, and creation time.
- Storage: `chrome.storage.local` contains only encrypted vault JSON.
- Migration: legacy v1 PBKDF2-SHA256/AES-GCM vaults are decrypted only during unlock and immediately re-encrypted as legacy private-key v2 vaults.

The KDF policy does not silently downgrade below the v3 defaults.

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

- Generate and back up a 12-word seed phrase.
- Import an existing BIP39 seed phrase.
- Derive the first Ethereum account at `m/44'/60'/0'/0/0`.
- Encrypt the seed phrase in Go WASM with XChaCha20-Poly1305.
- Unlock the vault into a short-lived in-memory Go session.
- Switch between Ethereum, Sepolia, Polygon, Arbitrum, Optimism, and Base.
- Read native balances through public RPC endpoints.
- Sign EIP-191 messages by `sessionId`.
- Copy address and signatures.
- Open the account in the active chain explorer.
- Reset the local vault.

## Non-Goals

- No hosted custody.
- No ERC-20 token balances yet.
- No transaction broadcasting.
- No page provider injection.
- No dapp permissions system yet.

Those are intentionally omitted to keep the security surface small.

## WASM API

The extension calls these Go-owned methods:

- `createVault(password) -> { vault, address, sessionId }`
- `importVault(password, mnemonic) -> { vault, address, sessionId }`
- `unlockVault(vault, password) -> { address, sessionId, migratedVault? }`
- `signMessage(sessionId, message) -> { address, hash, signature }`
- `lock(sessionId)`
- `lockAll()`

The API intentionally has no method that returns a private key.

## Security

See [SECURITY.md](SECURITY.md).
