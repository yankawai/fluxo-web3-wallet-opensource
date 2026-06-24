# Contributing

Fluxo is a wallet-core project. Changes should keep the security boundary explicit and avoid adding application UI, RPC providers, transaction broadcast, telemetry, or custody claims without a dedicated design review.

## Local Checks

Run the full project check before opening a pull request:

```sh
make check
```

## Security Rules

- Do not include mnemonics, private keys, passwords, vault plaintext, production vaults, or real signatures in issues, tests, fixtures, screenshots, or logs.
- Keep private-key operations behind session APIs.
- Do not add methods that export private keys.
- Document any change to vault format, KDF policy, signing behavior, or secure-element protocol.
- Treat the software secure-element emulator as test infrastructure, not a custody boundary.

## Pull Requests

Keep pull requests focused. Include the behavior change, security impact, and validation commands. Public API changes should include tests and documentation updates.
