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
  (lint-enforced): no `node:*` imports, no globals like `process` or `window`. Every external effect is injected: `ISignerStorage`,
  a WebSocket factory, `fetch`.
- **Dependencies**: runtime deps are exactly `@noble/curves`, `@noble/hashes`, `@scure/bip32`, `@scure/btc-signer`, declared as
  caret ranges (`^2.2.0`) so a host app on the same major converges on a single copy instead of installing a second one; a host
  still on v1 installs both lines until it upgrades, and pinning exactly would make that permanent.
  Do not add runtime dependencies, and do not pin these to exact versions; the caret floor must stay at the lowest version whose
  API the SDK actually uses. Dev dependencies stay pinned exactly.
- **Determinism**: every derivation (channel seeds, keys, nonces) is a deterministic function of the master seed. The derivation
  scheme is versioned and additive-only: changing it breaks recoverability of existing channels.
- **Secrets**: the master seed enters once via the constructor and stays in SDK memory. No API returns a private key, except the
  scoped settlement-key delegation of the remote-signing protocol and `deriveMasterSeed`, a pure function that returns to the
  host the seed the host itself will pass back in. No SDK instance ever holds anything above the master seed.
- **Signing safety**: deterministic nonces + persisted sign-once store; never sign two different messages for the same
  (channel, commitment number, context) slot. Policy checks run before every signature; no blind signing.

## Layout

```text
src/
  common/         Cross-module helpers that belong to no single module (input guards)
  derivation/     Fiber key scheme port + SDK-owned derivations
  signer/         Signer-protocol dispatch, musig2 signing engine
  policy/         Policy engine + persisted per-channel records
  session/        Signer session client: challenge auth, correlation, resume
  protocol/       Wire types of the remote signing protocol
  rpc/            Typed fiber JSON-RPC client
  sdk/            Public facade wiring the above
  index.ts        Public entrypoint; every export here is a published commitment

test/
  tests/          Specs mirroring the src tree one-to-one
  utils/          Shared test helpers (vector loading, fixtures)

docs/             Long-form docs, indexed by docs/README.md
interop/          Rust harness + generated cross-implementation vectors
```

Inside a module: `<module>.constants.ts`, `<module>.types.ts`, `utils/`, `interfaces/`, and one file per cohesive unit of
behavior. A module is only split further when a file stops having a single subject. A helper lives in `common/` only once it is
generic enough that naming it after a module would be wrong; anything a single module owns stays inside it.

## Commands

```bash
pnpm install
pnpm lint          # eslint (no-platform-API guard + JSDoc conventions)
pnpm check-types   # tsc --noEmit
pnpm test          # jest (ESM mode)
pnpm build         # tsup -> dist/ (dual ESM + CJS, one shared index.d.ts)
pnpm format        # prettier

# Regenerate the cross-implementation vectors (needs a Rust toolchain; `pnpm test` does not)
cargo run --release --manifest-path interop/rust/Cargo.toml -- gen-vectors interop/vectors/vectors.json
```

## Code style

- TypeScript strict, ESM only; relative imports carry no file extension (`moduleResolution: bundler`), which holds only because
  tsup bundles: a build emitting file per file would need every extension back. Dependency subpaths keep the extension their own
  `exports` map declares (`@noble/hashes/blake2.js`).
- Prettier: 4-space indent, double quotes, semicolons, trailing commas, 140 char width.
- Zero tolerance for `any`: use `unknown` with type guards or proper generics; constrain type parameters.
- Prefer `??` over `||` when `0` or `""` are valid values; optional chaining over unguarded access.
- String enums / literal unions for anything serialized; validate external data shapes, never trust them.
- Amounts on the public surface are integer strings in shannons; conversion to fiber's 0x-hex u128 happens only in the `rpc`
  module. No native `number` for on-chain amounts.

### File naming

`kebab-case`, with a role suffix when the file holds one kind of thing: `*.constants.ts`, `*.types.ts`, `*.utils.ts`,
`*.error.ts`. Interfaces live in `interfaces/` as `i-<name>.ts` and are named `I<Name>`. A file that _is_ a concept takes the
concept's name with no suffix (`fiber-scheme.ts`, `device-scheme.ts`).

### Barrels

Every folder has an `index.ts`, and it is imported as the folder (`../common`), never as `../common/index`. Barrels re-export
wholesale with `export *`. Two exceptions list their exports one by one: `src/derivation/index.ts`, which keeps scheme internals
out of reach of the other modules, and `src/index.ts`, which is the published surface. A test pins each of those two lists, so
never widen one without meaning to.

### Comments

All of the below is lint-enforced through `eslint-plugin-jsdoc`; `pnpm lint` is the source of truth. Never run `--fix` on a
JSDoc error: it inserts empty tag stubs instead of writing the missing text.

Block comments always span multiple lines, never `/** text */` on one line:

```ts
/**
 * Port of fiber's `blake2b_hash_with_salt`.
 * @param data Data to hash.
 * @param salt Domain separator, hashed before the data, opposite to the argument order.
 * @returns The 32-byte digest.
 */
```

Exported functions carry JSDoc in that shape: a description that fits on one line, then `@param` per parameter and `@returns`.
The description is the whole story: no extra paragraphs — when something more needs saying, it belongs in `docs/`, cross-linked,
not in the JSDoc. `//` is only for a note inside a function body.

Everything else — types, constants, interfaces, modules — takes a comment only when it earns one by saying what the code cannot:
an upstream quirk, the reason a bound exists, an invariant a reader would otherwise break.

## Testing

- Specs live in `test/tests/`, mirroring `src/` one-to-one (`src/derivation/fiber-scheme.ts` →
  `test/tests/derivation/fiber-scheme.spec.ts`). Doubles of the injected effects go in `test/mocks/`, mirroring `src/` the same
  way and named `*.mock.ts`; every other shared helper goes in `test/utils/`. Neither is ever named `*.spec.ts`.
- Fixtures are written out literally in the spec that uses them, never produced by a factory that fills in defaults: a factory
  that supplies the field a test meant to omit turns a refusal path green.
- `test/` may use `node:*` imports and platform globals (it only ever runs under Node); `src/` may not, and lint enforces both
  bans there.
- Derivation changes must keep the cross-implementation vectors green (`interop/`, see its README): those vectors are the
  compatibility contract with fiber's Rust implementation, and they are generated, never hand-edited.
- The SDK-owned derivations are additionally pinned by hardcoded values in `test/tests/derivation/device-scheme.spec.ts`. They are
  the recoverability contract, not a snapshot to update: changing them strands existing channels.
- Policy: test every refusal path and the idempotent already-signed path, not just the happy path.
