# Fluxo Secure Element Firmware Boundary

This directory defines the firmware-facing contract for a future Fluxo hardware secure element port.

There is no claim that the current repository is a certified hardware wallet. Real secure-element firmware requires a concrete chip target, vendor SDK, secure boot chain, fused keys, anti-rollback counters, side-channel review, production provisioning, and independent lab review. The Go implementation under `internal/secureelement` is a protocol emulator and test harness, not a hardware security boundary.

## Target Responsibilities

A real secure element implementation must keep seed and private key material inside the secure boundary. The host application may request operations, but it must never receive:

- raw seed phrase;
- BIP32 seed;
- private key;
- signing nonce;
- attestation private key;
- firmware signing keys.

## Command Set

The host talks to the secure element through a small command surface:

| Opcode | Command | Secret export |
| --- | --- | --- |
| `OpcodePing` | Health check | never |
| `OpcodeGenerateMnemonic` | Generate and seal a seed into a slot | never |
| `OpcodeProvisionMnemonic` | Import a seed into a slot for migration/recovery | input only |
| `OpcodeDeriveAddress` | Return a public address for an account index | never |
| `OpcodeSignEIP191Message` | Sign an EIP-191 message after authorization | signature only |
| `OpcodeAttest` | Bind firmware/device metadata to a host challenge | signature only |
| `OpcodeLock` | Lock a slot/session | never |

The Go contract is in `internal/secureelement/protocol.go`.
Bounded host/device frame encoding is in `internal/secureelement/codec.go`.

## Firmware Requirements

- Secure boot must verify firmware before execution.
- Anti-rollback must reject older firmware versions once a newer trusted version runs.
- Device attestation must bind a host-provided challenge, firmware version, device identity, and public key material.
- Signing commands must require explicit user presence unless a product-specific policy disables it for low-risk flows.
- Secret export commands must not exist in production firmware.
- Host-provided inputs must be length-checked and parsed with bounded buffers.
- Signing operations must use deterministic or hardened nonce generation appropriate for the chip and curve implementation.
- Debug interfaces must be disabled or cryptographically locked in production.
- Provisioning must not reuse device attestation keys across devices.
- Failure responses must avoid leaking whether a secret exists beyond the minimum needed status.

## Porting Plan

1. Pick a target secure element and vendor SDK.
2. Implement the command parser for the opcodes above.
3. Store slot metadata and encrypted seed material in secure non-volatile memory.
4. Implement account derivation and EIP-191 signing entirely inside the secure boundary.
5. Implement user-presence verification using the target device UX.
6. Implement device attestation with per-device keys.
7. Run the Go software emulator test vectors against the target transport.
8. Add hardware-in-the-loop tests before enabling transaction signing.

## Non-Goals

- The software emulator is not suitable for custody.
- This repository does not include vendor SDK code.
- This repository does not include production provisioning keys.
- This repository does not claim Common Criteria, FIPS, or similar certification.
