# Security Audit Checklist

Use this checklist before positioning Fluxo as custody-grade infrastructure.

## Cryptography

- [ ] Vault v3 AAD covers every mutable metadata field.
- [ ] Argon2id parameters cannot be downgraded in production unlock paths.
- [ ] XChaCha20-Poly1305 nonces are unique per encryption.
- [ ] Wrong password and tampered metadata/ciphertext fail without plaintext leakage.
- [ ] EIP-191 signing vectors match independently generated Ethereum vectors.
- [ ] Signature verification recovers the expected address.

## Secret Handling

- [ ] Public APIs do not return private keys.
- [ ] Import and unlock flows do not return mnemonics.
- [ ] Create-wallet flow returns mnemonic only once for backup.
- [ ] Session IDs are not durable credentials.
- [ ] Sessions expire and can be explicitly locked.
- [ ] Logging paths do not include passwords, seed phrases, private keys, plaintext vaults, or session internals.

## Secure Element Track

- [ ] Host commands cannot export seed or private key material.
- [ ] Signing requires user presence under the default policy.
- [ ] Attestation binds challenge, firmware version, and device identity.
- [ ] Firmware rejects rollback to older versions.
- [ ] Debug interfaces are disabled or locked in production.
- [ ] Hardware-in-the-loop tests cover derive, sign, lock, and attestation paths.

## Integration

- [ ] Storage adapter persists only encrypted vault JSON.
- [ ] RPC providers are configurable and disclosed to users.
- [ ] Transaction signing requires a separate review surface before broadcast.
- [ ] Dependency update policy is documented.
- [ ] Release artifacts are reproducible or independently verifiable.

## Review Gates

- [ ] `make check` passes.
- [ ] Race-sensitive session code has targeted tests.
- [ ] A fresh clone can build the WASM adapter.
- [ ] Security limitations are documented without "unhackable" claims.
- [ ] A third-party review has been completed before recommending meaningful funds.
