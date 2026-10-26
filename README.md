# fiber-lsp-sdk

Device signer SDK for [Fiber](https://github.com/nervosnetwork/fiber) (Nervos Lightning) hosted-LSP integrations. It makes a mobile
wallet the key holder of Fiber channels hosted at an LSP: the node runs server-side, the device derives all channel secrets from a
host-provided master seed, produces musig2 (BIP-327) partial signatures on request, and enforces a signing policy so it never
blind-signs.

## Key properties

- **Runs anywhere**: framework-agnostic TypeScript, shipped as both ESM and CommonJS. The same code runs unmodified in Node,
  browsers, and React Native (Hermes).
- **No I/O of its own**: the SDK performs no platform calls. The host injects every external effect: an `ISignerStorage` (key-value
  persistence), `fetch` and a timer, the last two defaulting to the runtime's own; the clock defaults to `Date.now`.
- **Minimal, audited dependency surface**: the only runtime dependencies are `@noble/curves`, `@noble/hashes`, `@scure/bip32`, and
  `@scure/btc-signer`, accepted as `^2.2.0` so a host app on the same major converges on a single copy of each.
- **Recoverable by design**: every derivation is a deterministic function of the master seed, so channel keys are recoverable from
  the wallet mnemonic alone. `deriveMasterSeed` owns the step above that, the hardened BIP32 path the master seed comes from, so
  the chain has no link left to host convention. The keys, not the signing state: rebuilding what a lost storage took with it is
  not implemented today ([persistence.md](./docs/persistence.md)).

These properties reflect the current specification and may evolve with it while the SDK is under active design.

## Modules

| Module                           | Responsibility                                                                                                                                                                                   |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [`derivation`](./src/derivation) | Fiber key scheme port + SDK-owned derivations (channel seed, wallet identity key, nonce seed)                                                                                                    |
| [`digest`](./src/digest)         | Rebuilds the four messages fiber signs, so the device never blind-signs; reads a watchtower spend's tx hash and settlement unlock; an opening's funding lock and channel id                      |
| [`invoice`](./src/invoice)       | Fiber's invoice string, read and written bit for bit, so the device knows what it pays and what it asked for                                                                                     |
| [`signer`](./src/signer)         | The entry of a signing request: the checks before the claim, the musig2 engine, the public material, the tenant identity, the watchtower's signature                                             |
| [`policy`](./src/policy)         | Policy engine + persisted per-channel records, and the watchtower's rules                                                                                                                        |
| [`wire`](./src/wire)             | How fiber writes values in JSON, the readers that refuse anything else, and the writers that produce it                                                                                          |
| [`protocol`](./src/protocol)     | Fiber's two signing statuses read strictly: the transition, its slot, the plaintext, the peer's evidence; the watchtower's spend                                                                 |
| [`rpc`](./src/rpc)               | Typed fiber JSON-RPC client (Biscuit-authed)                                                                                                                                                     |
| [`sdk`](./src/sdk)               | Public facade wiring the above: `FiberLspSdk`, its lifecycle, events and errors, the time index, the registration, the evidence, the channel opening and listing, the poller and its three steps |

`derivation`, `digest`, `invoice`, `signer`, `policy`, `wire`, `protocol` and `rpc` are implemented; `sdk` has its core,
construction, `connect`/`disconnect`, the events, the tenant's registration and token, a channel's evidence, and the
channel opening, checked against what was asked before anything is signed, with the listing of the node's channels,
while invoices and payments land next, so the public API is not settled yet. The upstream reference is the head of Fiber's hosted-LSP PR (nervosnetwork/fiber#1623, `8db6a117`), whose polled
signing protocol the modules under the facade are being aligned to: `digest` and `policy` know both commitment-lock
layouts, `rpc` writes the tenant API's forms, `invoice` reads the trampoline route hint every tenant invoice carries,
and `signer` answers the node's signing status, which the facade's poller reads and answers on every tick, and the
watchtower's requests to spend a force-closed commitment, signed only toward a destination the host approved (today
fiber's watchtower pays the LSP node's own lock, so approving it is trusting the LSP after a force close:
[signing.md](./docs/signing.md)); `signer` also holds the tenant identity that signs the registration, which the facade
exposes. A test double of the tenant's node runs fiber's tenant opening, its sequences of signing requests and its
watchtower's spends through that poller, and shows that under Fiber's current nonces a channel still stalls at the settlement of a payment
it sends and at its second payment received, even with `nonceReuse: "allow"` ([policy.md](./docs/policy.md), "The known
cost").

## Repository layout

```text
src/            SDK source, one folder per module (see above), plus common/ for what no single module owns
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
- [What the device signs](./docs/digest.md): the four message constructions rebuilt on the device, the trust model of
  the inputs they take, the settlement unlock a watchtower's spend carries, and an opening's funding lock and channel id.
- [How signatures are produced](./docs/signing.md): the musig2 engine, its deterministic nonces, the conditions that
  make them safe, the dispatch that gates every musig2 signature at one call site, the tenant identity's registration
  signature, and the watchtower's signature with the trust its destination takes.
- [What the device refuses](./docs/policy.md): the six checks every musig2 request passes, the sign-once rule those
  conditions rest on, and the rules a watchtower's spend passes instead.
- [What crosses the wire](./docs/protocol.md): the two signing statuses the node publishes, each transition with its slot
  and plaintext, the watchtower's spend with its key, and the forms it refuses.
- [How an invoice is read](./docs/invoice.md): fiber's string decoded and written by the device itself, one string per
  invoice, and where the reader is stricter than fiber's.
- [How the node is called](./docs/rpc.md): one POST per call over the host's fetch, the three errors a call fails
  with, split by what the caller can conclude, and the channel, invoice, payment and signing methods on top.
- [What a wallet talks to](./docs/sdk.md): the facade, the effects it is given and their defaults, `connect` and
  `disconnect`, the events and the errors, the time index a wipe cannot reset, the channel opening and the listing, and
  the poller with its channel, signing and watchtower steps.
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
The same harness pins fiber's RPC forms in `interop/vectors/rpc.json`, params and results serialized by fiber's own JSON types,
which the `rpc` module is tested against. See [`interop/README.md`](./interop/README.md) and
[`docs/derivation.md`](./docs/derivation.md).

### Build output

`pnpm build` emits a dual bundle in `dist/`: `index.js` for `require`, `index.mjs` for `import`, both with source maps. Both
conditions resolve types through a single `index.d.ts`. The runtime dependencies stay external and are ESM-only packages, so the
CommonJS entry loads them through `require(esm)`, which is why the package requires Node >= 20.19.

```js
import { FiberLspSdk } from "@peersyst/fiber-lsp-sdk";
const { FiberLspSdk } = require("@peersyst/fiber-lsp-sdk");
```

### Constructing the SDK

```js
import { FiberLspSdk } from "@peersyst/fiber-lsp-sdk";

const sdk = new FiberLspSdk(masterSeed, {
  network: "testnet",
  storage, // ISignerStorage or IAsyncSignerStorage: the host's key-value persistence
  rpcUrl: "https://lsp.example/rpc",
  biscuitToken,
  lspPubkey, // the LSP node's key, 33 bytes; signTenantRegistration checks the challenge names it
  nonceReuse: "allow", // Fiber's current nonces ask a second session of some slots; drop it once they are strict
  watchtower: { destination, maxFeeShannons: "100000" }, // omitted: every watchtower request is refused
});

const unsubscribe = sdk.onEvent((event) => {
  if (event.type === "SIGNING" && event.outcome === "refused") log(event.channelId, event.error.code);
  if (event.type === "WATCHTOWER_SIGNING" && event.outcome === "refused") log(event.channelId, event.error.code);
  if (event.type === "ERROR") log(event.error.code, event.error.cause);
});
sdk.connect(); // on foreground: the polling of the node
sdk.disconnect(); // on background
```

### Registering as a tenant

The device signs; the host, or its backend, makes the two operator calls and hands the tenant's token back:

```js
const challenge = await backend.getRegistryNonce(sdk.rootSignerPubkey); // lsp_get_tenant_registry_nonce, decoded to bytes
const { rootSignerPubkey, nonce, signature, tenantId } = sdk.signTenantRegistration(challenge);
const { tenant, accessToken } = await backend.registerTenant({ rootSignerPubkey, nonce, signature }); // lsp_register_tenant
if (tenant.tenantId !== tenantId) throw new Error("the LSP registered another tenant"); // as fiber's own client checks
sdk.setBiscuitToken(accessToken); // from the next call on
```

### Opening a channel

The user's lock funds the channel and is where the device's side of a close pays; the amount is decimal shannons, the
reserve included. The SDK checks and pins the node's answer before the host signs anything:

```js
const channelId = await sdk.openChannel(amountShannons, userLock, async (unsignedFundingTx) => {
  return wallet.signInputs(unsignedFundingTx); // the host's signer checks what the inputs pay before it signs them
});
// userLockCellDeps, the last argument of both forms, only for a lock whose cell deps are not among the chain's genesis scripts

// or in two steps, the host signing in between
const opening = await sdk.prepareChannelOpen(amountShannons, userLock); // channelId, unsignedFundingTx, openingContext
await sdk.submitFundingTx(opening.channelId, await wallet.signInputs(opening.unsignedFundingTx));

sdk.onEvent((event) => {
  if (event.type === "CHANNEL_READY") show(event.channelId);
  if (event.type === "CHANNEL_CLOSED") hide(event.channelId); // an opening fiber aborted unfunded included
});
const channels = await sdk.listChannels(); // channelId, state, the four balances, hasRecord
```

A retry with the same arguments resumes the opening the node still holds. A custom `network` object needs its
`fundingLock` template beside its `commitmentLock`.

### Reading a channel's evidence

```js
const evidence = await sdk.channelEvidence(channelId); // revocations, each view's last commitment, the watchtower's signatures
```

Every event and error a wallet sees is in [`docs/sdk.md`](./docs/sdk.md).

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
