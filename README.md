# fiber-lsp-sdk

Device signer SDK for [Fiber](https://github.com/nervosnetwork/fiber) (Nervos Lightning) hosted-LSP integrations. It makes a mobile
wallet the key holder of Fiber channels hosted at an LSP: the node runs server-side, the device derives all channel secrets from a
host-provided master seed, produces musig2 (BIP-327) partial signatures on request, and enforces a signing policy so it never
blind-signs.

## Key properties

- **Runs anywhere**: framework-agnostic TypeScript, shipped as both ESM and CommonJS. The same code runs unmodified in Node,
  browsers, and React Native (Hermes).
- **No I/O of its own**: the SDK performs no platform calls. The host injects every external effect: an `ISignerStorage` (key-value
  persistence), a WebSocket factory, and `fetch`.
- **Minimal, audited dependency surface**: the only runtime dependencies are `@noble/curves`, `@noble/hashes`, `@scure/bip32`, and
  `@scure/btc-signer`, accepted as `^2.2.0` so a host app on the same major converges on a single copy of each.
- **Recoverable by design**: every derivation is a deterministic function of the master seed, so channel keys are recoverable from
  the wallet mnemonic alone. `deriveMasterSeed` owns the step above that, the hardened BIP32 path the master seed comes from, so
  the chain has no link left to host convention. The keys, not the signing state: rebuilding what a lost storage took with it is
  not implemented today ([persistence.md](./docs/persistence.md)).

These properties reflect the current specification and may evolve with it while the SDK is under active design.

## Modules

| Module                           | Responsibility                                                                                |
| -------------------------------- | --------------------------------------------------------------------------------------------- |
| [`derivation`](./src/derivation) | Fiber key scheme port + SDK-owned derivations (channel seed, wallet identity key, nonce seed) |
| [`digest`](./src/digest)         | Rebuilds the four messages fiber signs, so the device never blind-signs                       |
| [`signer`](./src/signer)         | Dispatches signer-protocol methods, musig2 signing engine                                     |
| [`policy`](./src/policy)         | Policy engine + persisted per-channel records                                                 |
| `session`                        | Signer session client: challenge auth, correlation, resume                                    |
| [`protocol`](./src/protocol)     | Wire types of the remote signing protocol                                                     |
| `rpc`                            | Typed fiber JSON-RPC client (Biscuit-authed)                                                  |
| `sdk`                            | Public facade wiring the above                                                                |

`derivation`, `digest`, `policy` and the signing engine of `signer` are implemented; the signer-protocol dispatch,
`session`, `rpc` and `sdk` are still placeholders, so the public entrypoint stays small while the API settles.

## Repository layout

```text
src/            SDK source, one folder per module (see above), plus common/ for helpers no single module owns
test/tests/     Specs, mirroring the src tree one-to-one
test/mocks/     Doubles of the injected effects, one folder per module
test/utils/     Shared test helpers
docs/           Long-form documentation, indexed by docs/README.md
interop/        Rust harness and the generated cross-implementation vectors
```

## Documentation

Full index in [docs/README.md](./docs/README.md). The load-bearing ones:

- [How keys are derived](./docs/derivation.md): what each channel key protects, the primitives behind the scheme, the full
  derivation tree, and why nonces are deterministic.
- [What the device signs](./docs/digest.md): the four message constructions rebuilt on the device, and the trust model of
  the inputs they take.
- [How signatures are produced](./docs/signing.md): the musig2 engine, its deterministic nonces, and the conditions that
  make them safe.
- [What the device refuses](./docs/policy.md): the five checks every request passes, and the sign-once rule those
  conditions rest on.
- [Cross-implementation harness](./interop/README.md): how the vectors are generated and re-validated against a new fiber
  release.

## Development

```bash
corepack enable
pnpm install
pnpm lint
pnpm check-types
pnpm test
pnpm build
```

Node version: see `.nvmrc`.

### Cross-implementation vectors

The key derivation is a compatibility contract with fiber's Rust implementation: the node derives the public halves of the same
keys. `pnpm test` checks every derivation against `interop/vectors/vectors.json`, so the contract is verified on every run without
a Rust toolchain; regenerating the vectors is what needs one. The interop workflow closes the loop in the other direction on
every pull request: it regenerates the vectors and verifies a partial signature the SDK produced under fiber's own musig2 crate.
See [`interop/README.md`](./interop/README.md) and [`docs/derivation.md`](./docs/derivation.md).

### Build output

`pnpm build` emits a dual bundle in `dist/`: `index.js` for `require`, `index.mjs` for `import`, both with source maps. Both
conditions resolve types through a single `index.d.ts`. The runtime dependencies stay external and are ESM-only packages, so the
CommonJS entry loads them through `require(esm)` — this is why the package requires Node >= 20.19.

```js
import { PROTOCOL_VERSION } from "@peersyst/fiber-lsp-sdk";
const { PROTOCOL_VERSION } = require("@peersyst/fiber-lsp-sdk");
```

### Deriving the master seed

The SDK never sees the mnemonic. The host expands it into a BIP39 seed and gets the 32 bytes the SDK is built from:

```js
import { deriveMasterSeed } from "@peersyst/fiber-lsp-sdk";

const masterSeed = deriveMasterSeed(bip39Seed); // BIP32 m/1017'/309'/0', all levels hardened
```

The function is pure and keeps nothing: the BIP39 seed is an argument, and only the result crosses into the SDK. See
[`docs/derivation.md`](./docs/derivation.md) for why that path and not another.

## License

To be decided; this repo has no license file yet.
