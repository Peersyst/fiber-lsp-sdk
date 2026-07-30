# AGENTS.md

Guidance for AI coding agents working on this repository.

## What this is

`fiber-lsp-sdk` is the device signer SDK for Fiber (Nervos Lightning) hosted-LSP integrations: the LSP runs the fiber node, the
device (a mobile wallet) holds the channel keys, derives all channel secrets from a host-provided master seed, produces musig2
(BIP-327) partial signatures on request, and enforces a signing policy so it never blind-signs.

Upstream reference: `nervosnetwork/fiber` @ `b71a61c3` (v0.9.0-rc7). The key derivation scheme ports fiber's
`InMemorySigner` derivation (`crates/fiber-types/src/channel.rs`) byte for byte; re-validate it against new fiber releases.

## Hard constraints

- **Runtimes**: the SDK must run unmodified in Node, browsers, and React Native (Hermes). No platform APIs anywhere in `src/`
  (lint-enforced): no `node:*` imports, no globals like `process` or `window`. Every external effect is injected: `SignerStorage`,
  a WebSocket factory, `fetch`.
- **Dependencies**: runtime deps are exactly `@noble/curves`, `@noble/hashes`, `@scure/bip32`, `@scure/btc-signer`, declared as
  caret ranges (`^2.2.0`) so a host app that already depends on them dedupes to a single copy instead of installing a second one.
  Do not add runtime dependencies, and do not pin these to exact versions; the caret floor must stay at the lowest version whose
  API the SDK actually uses. Dev dependencies stay pinned exactly.
- **Determinism**: every derivation (channel seeds, keys, nonces) is a deterministic function of the master seed. The derivation
  scheme is versioned and additive-only: changing it breaks recoverability of existing channels.
- **Secrets**: the master seed enters once via the constructor and stays in SDK memory. No API returns a private key, except the
  scoped settlement-key delegation of the remote-signing protocol.
- **Signing safety**: deterministic nonces + persisted sign-once store; never sign two different messages for the same
  (channel, commitment number, context) slot. Policy checks run before every signature; no blind signing.

## Commands

```bash
pnpm install
pnpm lint          # eslint (includes the no-platform-API guard)
pnpm check-types   # tsc --noEmit
pnpm test          # jest (ESM mode)
pnpm build         # tsup -> dist/ (dual ESM + CJS, types per condition)
pnpm format        # prettier
```

## Code style

- TypeScript strict, ESM only; relative imports use explicit `.js` extensions (NodeNext).
- Prettier: 4-space indent, double quotes, semicolons, trailing commas, 140 char width.
- Zero tolerance for `any`: use `unknown` with type guards or proper generics; constrain type parameters.
- Prefer `??` over `||` when `0` or `""` are valid values; optional chaining over unguarded access.
- String enums / literal unions for anything serialized; validate external data shapes, never trust them.
- Amounts on the public surface are integer strings in shannons; conversion to fiber's 0x-hex u128 happens only in the `rpc`
  module. No native `number` for on-chain amounts.
- Barrel `index.ts` files re-export the public API only.
- Default to no code comments; when one is unavoidable, state a constraint the code cannot show.

## Testing

- Every module ships unit tests next to it (`*.spec.ts`).
- Derivation changes must keep the cross-implementation vectors green; those vectors are the compatibility contract with fiber's
  Rust implementation.
- Policy: test every refusal path and the idempotent already-signed path, not just the happy path.
