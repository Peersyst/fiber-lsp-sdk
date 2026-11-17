---
title: Under the hood
description: An index of the Fiber LSP SDK's design documents on GitHub, for readers who want the internals.
---

# Under the hood

This site tells you how to use the SDK. The repository's design documents tell you how it works inside, module by module, with the reasoning behind each rule and the Fiber code it follows. They are dense, written for contributors and reviewers, and they are the source of truth when this site summarizes.

## The design documents

| Document                                                                                      | What it explains                                                                                                       |
| --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| [sdk.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/sdk.md)                     | The `FiberLspSdk` facade: its options and effects, events and errors, the poller, and every operation step by step     |
| [derivation.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/derivation.md)       | How every key and nonce derives from the master seed, and where the master seed comes from                             |
| [digest.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/digest.md)               | How the device rebuilds the four messages Fiber signs, so it never signs blind                                         |
| [signing.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/signing.md)             | How a signing request is answered: the musig2 engine, deterministic nonces, the tenant identity and the watchtower     |
| [policy.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/policy.md)               | What the device refuses: the checks in order, sign-once, the balance rule and the watchtower's rules                   |
| [persistence.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/persistence.md)     | What the storage holds, how concurrent writes are kept safe, and what a restore cannot bring back                      |
| [protocol.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/protocol.md)           | The two signing statuses the node publishes, and how the device reads each one strictly                                |
| [rpc.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/rpc.md)                     | The JSON-RPC client: how calls are made, the three errors they fail with, and every method it speaks                   |
| [invoice.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/invoice.md)             | How the device reads and writes Fiber's invoice strings itself, and where it is stricter than Fiber                    |
| [react-native.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/react-native.md)   | What a React Native app provides: the storage, a `fetch` with a timeout, and behavior in the background                |
| [e2e-agent.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/e2e-agent.md)         | How the SDK runs Fiber's own end-to-end suites, and its own scenarios on a development chain or testnet                |
| [interop/README.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/interop/README.md)    | The Rust harness that checks the SDK against Fiber's code, and how to re-validate it on a new Fiber release            |

The full index, with a longer summary of each, is [docs/README.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/README.md).

## Where to start

- **Auditing what the device signs:** [policy.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/policy.md), then [digest.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/digest.md) and [signing.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/signing.md).
- **Recoverability:** [derivation.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/derivation.md) and [persistence.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/persistence.md).
- **Following a new Fiber release:** [interop/README.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/interop/README.md).

## See also

- [Security model](/docs/resources/security)
- [Compatibility](/docs/resources/compatibility)
