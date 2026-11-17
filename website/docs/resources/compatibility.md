---
title: Compatibility
description: The Fiber version the SDK is pinned to, how it is checked against Fiber's Rust code, and the runtimes it supports.
---

# Compatibility

The device and the LSP node must agree on every byte: the keys, the messages they sign, the invoice strings and the JSON-RPC forms. This page says which Fiber the SDK agrees with, how that agreement is tested, and which runtimes it runs on.

## Fiber version

| What                  | Pinned to                                                                                                   |
| --------------------- | ----------------------------------------------------------------------------------------------------------- |
| Fiber node            | The head of the hosted-LSP pull request [nervosnetwork/fiber#1623](https://github.com/nervosnetwork/fiber/pull/1623), commit `d8dd6d28` |
| Key derivation        | Byte for byte the one of `d8dd6d28`, itself identical to Fiber `v0.9.0-rc7` (`b71a61c3`)                     |
| Derivation scheme     | `DERIVATION_SCHEME_VERSION` = `1`                                                                           |

The node must run the hosted-LSP code of that PR: the tenant API, the signing statuses the device polls and the watchtower's spends all come from it. A stock Fiber release without it does not host tenants.

:::warning
Until the PR is merged and released, treat any Fiber change as potentially breaking. See [Status and known limitations](/docs/resources/status).
:::

## Cross-implementation vectors

The SDK's TypeScript is checked against Fiber's own Rust code, not against itself. A Rust harness in the repository builds test vectors with Fiber's crates, pinned to the same commit:

- **Key derivation**: Fiber's derivation functions, ported verbatim, plus an independent implementation of the SDK's own derivations (the master seed path, the identity key, the channel seed, the nonce seed).
- **Signed messages**: the four messages Fiber signs, built and hashed by Fiber's own types.
- **JSON-RPC forms**: the params and results of every method the client speaks, serialized by Fiber's own JSON types, and the SDK's encoded params read back by Fiber's deserializers.
- **Invoices**: strings written by Fiber's own encoder, and the SDK's strings read back by Fiber's decoder.
- **Signing requests and watchtower spends**: one request per transition as a node writes it, with the answer the device owes, and the watchtower's spends with their signatures.
- **Tenant registration and funding lock**: the registration payload, its signature and the tenant id; the funding lock and the channel id an opening is checked against.

Every `pnpm test` run checks the SDK against these vectors, with no Rust toolchain needed. On each pull request that touches the code they pin, CI regenerates the vectors (and fails on any difference), and verifies a partial signature the SDK produced with the same `musig2` crate Fiber uses.

Learn more: [interop/README.md](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/interop/README.md).

## Runtimes

| Runtime              | Supported                                                                                                   |
| -------------------- | ----------------------------------------------------------------------------------------------------------- |
| Node.js              | 20.19 or later (`require(esm)` for the CommonJS build); CI runs Node 20.19                                  |
| Browsers             | Any with ES2022 support, `fetch` and `TextEncoder`                                                          |
| React Native         | Checked on Expo 55, React Native 0.83, Hermes and the new architecture, bundled by Metro with no configuration |
| TypeScript           | Types ship with the package; one declaration file serves both ESM and CommonJS                              |

The React Native notes cover Android; iOS has its own background rules, which are not documented yet. See [Runtimes](/docs/get-started/runtimes).

## How compatibility is kept

When Fiber moves, the harness is re-run against the new commit: the derivation is diffed and re-ported, the pinned crates are bumped, and all vectors are regenerated.

- **A green run** means Fiber did not move in any way the SDK depends on.
- **A red derivation** is a decision point, not a bug fix. The derivation scheme is versioned and additive-only: channels derived under one scheme stay on it, so changing it would strand existing channels. A new scheme would be added beside the old one.
- **A red RPC form or invoice layer** means the SDK's codecs follow the new form.

The SDK's own derivations are also pinned by hardcoded values in its test suite. Those values are the recoverability contract: changing them would make existing channels unrecoverable, so they never change.

## See also

- [Keys and recovery](/docs/concepts/keys-and-recovery)
- [Under the hood](/docs/resources/under-the-hood)
