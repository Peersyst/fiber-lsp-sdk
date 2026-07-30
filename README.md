# fiber-lsp-sdk

Device signer SDK for [Fiber](https://github.com/nervosnetwork/fiber) (Nervos Lightning) hosted-LSP integrations. It makes a mobile
wallet the key holder of Fiber channels hosted at an LSP: the node runs server-side, the device derives all channel secrets from a
host-provided master seed, produces musig2 (BIP-327) partial signatures on request, and enforces a signing policy so it never
blind-signs.

## Key properties

- **Runs anywhere**: framework-agnostic TypeScript, shipped as both ESM and CommonJS. The same code runs unmodified in Node,
  browsers, and React Native (Hermes).
- **No I/O of its own**: the SDK performs no platform calls. The host injects every external effect: a `SignerStorage` (key-value
  persistence), a WebSocket factory, and `fetch`.
- **Minimal, audited dependency surface**: the only runtime dependencies are `@noble/curves`, `@noble/hashes`, `@scure/bip32`, and
  `@scure/btc-signer`, accepted as `^2.2.0` so they dedupe with the versions a host app already installs.
- **Recoverable by design**: every derivation is a deterministic function of the master seed, so channels are recoverable from the
  wallet mnemonic alone.

These properties reflect the current specification and may evolve with it while the SDK is under active design.

## Modules

| Module       | Responsibility                                                                       |
| ------------ | ------------------------------------------------------------------------------------ |
| `derivation` | Fiber key scheme port + SDK-owned derivations (channel seed, device key, nonce seed) |
| `signer`     | Dispatches signer-protocol methods, musig2 signing engine                            |
| `policy`     | Policy engine + persisted per-channel records                                        |
| `session`    | Signer session client: challenge auth, correlation, resume                           |
| `protocol`   | Wire types of the remote signing protocol                                            |
| `rpc`        | Typed fiber JSON-RPC client (Biscuit-authed)                                         |
| `sdk`        | Public facade wiring the above                                                       |

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

### Build output

`pnpm build` emits a dual bundle in `dist/`: `index.js` + `index.d.ts` for `import`, `index.cjs` + `index.d.cts` for `require`,
both with source maps. The runtime dependencies stay external and are ESM-only packages, so the CommonJS entry loads them through
`require(esm)` — this is why the package requires Node >= 20.19.

```js
import { PROTOCOL_VERSION } from "@peersyst/fiber-lsp-sdk";
const { PROTOCOL_VERSION } = require("@peersyst/fiber-lsp-sdk");
```

## License

To be decided; this repo has no license file yet.
