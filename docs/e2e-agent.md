# The device agent for fiber's e2e suites

Fiber's hosted-LSP pull request ships its own device for its end-to-end suites: `tests/fiber-lsp-sdk-agent`, a Rust
process that registers a tenant, holds its keys and answers the node's signing requests, driven by the Bruno suites
through a small HTTP control port. `e2e/agent/` is the same device run by this SDK: a Node process that speaks that
control contract to the letter, so fiber's six LSP suites (`e2e/lsp`, `e2e/lsp-remote-signer` and the four
`e2e/lsp-remote-signer-watchtower*`) run unchanged with the SDK signing.

It is a private package of the repository, never published (`files` holds `dist` alone). It depends on the SDK through
`link:../..`, so it imports the built package by its `exports` map, the surface an npm user gets, and nothing of `src/`.

## Running it against fiber's devnet

`<sdk-checkout>` is this repository, `<fiber-checkout>` fiber at the hosted-LSP pull request's head.

```bash
# in <sdk-checkout>
pnpm install && pnpm build
pnpm --dir e2e/agent install && pnpm --dir e2e/agent build
e2e/agent/devnet/install.sh <fiber-checkout>

# in <fiber-checkout>, one suite at a time
PATH="<sdk-checkout>/e2e/agent/devnet:$PATH" REMOVE_OLD_STATE=y ./tests/nodes/start.sh e2e/lsp-remote-signer

# in another shell in <fiber-checkout>, once tests/nodes/wait.sh returns
(cd tests/bruno && npm exec -- @usebruno/cli@1.20.0 run e2e/lsp-remote-signer -r --env test)
```

Fiber's `tests/nodes/start.sh` runs the agent from a fixed path, `target/debug/fiber-lsp-sdk-agent`, and builds the Rust
agent there on every start, which re-links the binary. So `e2e/agent/devnet/` holds three pieces, and nothing in fiber's
tree is edited:

| File                  | What it does                                                                                                |
| --------------------- | ----------------------------------------------------------------------------------------------------------- |
| `fiber-lsp-sdk-agent` | The wrapper, linked at that path: it runs `node e2e/agent/dist/src/main.js` with the same arguments         |
| `cargo`               | A shim first in `PATH`: it skips the build of the Rust agent and passes every other cargo call through      |
| `install.sh`          | Links the wrapper into `target/debug/`, moving the Rust binary aside; `--restore` puts the Rust binary back |

`install.sh` takes the `debug` profile alone: the agent pins fiber's debug epoch (2 s, `MILLI_SECONDS_PER_EPOCH` in a
debug build) as the SDK's `millisecondsPerEpoch`, which a release build's nodes do not run.

## The contract

The flags and their environment variables are fiber's (`--rpc`, `--store`, `--status-file`, `--control-addr`,
`--operator-token`, `--interval-ms`, `--contracts-dir`); `--ckb-rpc` is accepted and unused, since the SDK has no chain
client. `--contracts-dir` and `--ckb-rpc` have no environment variable, as in fiber's agent. `--once` is refused, the
agent has no single-poll mode, and so is `--interval-ms 0`, since the SDK's poll interval is a timer delay of at least
1 ms. The control port answers:

| Request              | Answer                                                                                                  |
| -------------------- | ------------------------------------------------------------------------------------------------------- |
| `GET /status`        | The status file, or 503 before it exists                                                                |
| `POST /open-channel` | `{ result }` with the node's `OpenTenantChannelResult`, once the SDK checked and pinned it; else 400    |
| `POST /authorize`    | `{ result: { authorized: true } }` for `Invoice`, `ReleasePreimage`, `Close` and `Watchtower`; else 400 |
| `POST /shutdown`     | `{ status: "restarting" }`, then the process exits 0 and `start.sh`'s loop restarts it on its store     |

Every failure of `/open-channel` and `/authorize` is a 400 with `{ error }`, as in fiber's agent; one that is not a
refusal of the request is also logged in full.

On start the agent serves the port, then initializes, retrying every second until the node answers: it reads the LSP's
node id (`node_info`, with the operator token), builds the facade with `nonceReuse: "allow"`, and, unless its store
holds a token, registers the tenant (`lsp_get_tenant_registry_nonce`, `signTenantRegistration`,
`lsp_register_tenant`), checks the tenant id and hands the token to the facade. The store keeps the master seed, the
SDK's storage and `agent.json` (the token, the LSP's id, the channels opened with both close scripts, and the
authorizations), so a restart makes no operator call and keeps the token.

Every SDK event is logged as one JSON line on stdout. The status file is rewritten from `channelEvidence` at
initialization, after an open or an authorization that succeeded, and on every SDK event.

## Where it parts from fiber's agent

Fiber's agent drives fiber's own SDK, whose model differs from this one's in places; each difference is the SDK's
position, kept here rather than bent to the contract.

| Fiber's agent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | This agent                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `channel_open_signer_material` is the next opening block, allocated before the open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `{ "allocated_at_open": true }` until a channel is bound, then `null`: the SDK derives the block in `prepareChannelOpen`, at an index it allocates then, so the `external_channel_signer` the driver sends back is ignored                                                                                                                                                                                                                                                       |
| `/open-channel` takes fiber's open params whole                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Only what `prepareChannelOpen` sends: the LSP as peer, a private channel, the shutdown script equal to the funding lock, fiber's default delay and fee rate (compared by value), no UDT and none of the other options fiber's params have; any of those is a 400, and a key fiber's params do not have is ignored, as serde does                                                                                                                                                 |
| `Invoice` hands the SDK the terms and a preimage the driver chose; fiber's `authorize_invoice` refuses terms that are not `inbound` and a preimage that does not hash to `payment_hash`                                                                                                                                                                                                                                                                                                                                                                                            | The agent makes the same two refusals and keeps the terms and the preimage: the SDK derives its own preimages and holds no other, and signs an incoming TLC under its balance rule whatever its hash                                                                                                                                                                                                                                                                             |
| `ReleasePreimage` (fiber's `authorize_preimage_release` and `release_preimage`) requires: the channel bound; its funding cell live on chain with the approved output and data; the invoice known, inbound, not cancelled, and the preimage hashing to it under its algorithm; the latest local commitment with a complete signature, not revoked, holding the incoming TLC with that hash, the invoice's amount and its algorithm; and that TLC's expiry past now plus the safety margin (two thirds of the commitment delay). Then it calls `settle_invoice` or `create_preimage` | Ported: the channel bound, an `Invoice` with that hash on that channel (inbound, checked when it was given), and the preimage hashing to it under the invoice's algorithm; nothing cancels an invoice here. Not ported: the funding cell, since the SDK has no chain client, and the commitment and TLC checks, since the SDK's public evidence carries no TLC set. Then the agent calls the node itself                                                                         |
| `Close` sets the fee shares the SDK's close check takes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | The agent checks both scripts against the open's and records it; the SDK signs a close by its pins and its fee bound, with no per-close authorization                                                                                                                                                                                                                                                                                                                            |
| `Watchtower` approves a destination and a fee cap per channel                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | One approval, the SDK's `watchtower` option, which it takes at construction: the agent retires the facade (closes its fetch, disconnects, waits until its last request settled) and builds another with the approval. The same channel's approval replaces the last; another channel's that differs in destination or fee cap is a 400. When the new facade cannot be built or the approval cannot be written, a facade over the previous state runs on and the request is a 400 |
| `revoked_commitments` carries each revoked commitment's `tx_hash`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `{ for_remote, version }` alone: the evidence keeps the revocation, not the hash of what it revoked                                                                                                                                                                                                                                                                                                                                                                              |
| Never lists channels: under it, the force close of `-evict` after `lsp_evict_tenant` runs against a cold tenant                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | While the agent's channel is open, the SDK's channel step lists the tenant's channels every tick to see it close, and fiber's `list_channels` reactivates the tenant (`supervisor.ensure`), so the tenant is running again within a tick of the eviction; the suite asserts only the eviction's response                                                                                                                                                                         |
| A control body over 1 MiB drops the connection unanswered and ends the control task; a closed control queue is a 503                                                                                                                                                                                                                                                                                                                                                                                                                                                               | A body over 1 MiB is a 400 and the port serves on; there is no queue to close. The `error` messages are this agent's and the SDK's own wording                                                                                                                                                                                                                                                                                                                                   |

## Scenarios

Fiber's suites drive the device through its control contract alone: they open, authorize and restart it. `e2e/agent/scenarios/`
holds six scenarios of the SDK's own that the contract cannot express, `node:test` specs that build the facade in process
over the same devnet under `nonceReuse: "allow"`, as the agent runs, each with a tenant and a channel of its own, and
inject faults through the `fetch` it is given:

| Scenario           | What it asserts                                                                                                                                                                                                                    |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `late-signer`      | A device disconnected while node 1 pays its invoice: the node holds the request and the payment stays `Inflight`; once it connects, the request is signed with its deadline reported and still ahead, and the invoice is paid      |
| `restart-pending`  | The first submission of the payment's first signature lost before it reaches the node: a new facade over the same store serves the same request with the same bytes, with no third session                                         |
| `non-hosted-payer` | Node 3 pays the SDK's invoice through node 1 and the LSP, routed by the invoice's trampoline hint                                                                                                                                  |
| `two-tenants`      | Two devices paid at once: each signs and polls only its own channel, and one tenant's token reading the other's channel is refused (`channel ... not found`)                                                                       |
| `altered-opening`  | Three alterations of `open_tenant_channel`'s answer (the LSP's close script grown past the reserve the node states, the funding output's capacity, the fee rate), each refused as `opening_rejected` with nothing signed or funded |
| `outbound-payment` | A payment sent by the device stalls: its fulfil asks a third session on `Commitment@3`, which `nonceReuse: "allow"` refuses, so the payment stays in flight                                                                        |

The outbound scenario asserts the stall on purpose. Under `allow` a slot serves two sessions and never a third, and the
peer's fulfil of a payment the device sent asks for a third on the commitment slot the device's own round left at the local
number. On the devnet node 1's invoice is paid, the LSP holds the preimage, and the tenant's payment stays `Inflight` with
its TLC on the channel. The scenario turns green on a completed payment only once fiber's nonces are strict and `allow` is
gone. Each channel otherwise takes a single received payment, since a second one after a fulfilled one stalls the same
way ([policy.md](./policy.md), "The known cost").

Fiber keeps an opening the device refused until its external funding times out (five minutes by default), and refuses
another opening of the same tenant meanwhile ("tenant already has a different channel opening"). So each alteration runs
on a device of its own, and the clean opening that ends the scenario waits for the first one's abort.

The scenarios read the devnet's URLs, keys and operator token from fiber's `tests/bruno/environments/test.bru` and its
contracts from `tests/deploy/contracts`, both under `FIBER_CHECKOUT`. Fiber's devnet starts its LSP only under one of
its LSP suites' names, and its agent runs beside the scenarios with a tenant of its own:

```bash
# in <fiber-checkout>, with the wrapper installed as above
PATH="<sdk-checkout>/e2e/agent/devnet:$PATH" REMOVE_OLD_STATE=y ./tests/nodes/start.sh e2e/lsp-remote-signer

# in <sdk-checkout>, once tests/nodes/wait.sh returns
# one scenario: pnpm --dir e2e/agent build && FIBER_CHECKOUT=<fiber-checkout> node --test e2e/agent/dist/scenarios/<name>.scenario.js
FIBER_CHECKOUT=<fiber-checkout> pnpm --dir e2e/agent scenarios
```

They run in series on one devnet, in about seven minutes, five of them the refused opening's abort.

## Tests

`pnpm --dir e2e/agent test` compiles the agent and its specs and runs them with `node --test`: the config, the store, the
JSON-RPC calls, the contract's readers and the status, and the process over a fake node, including a real opening the
SDK accepts. The suites and the scenarios need fiber's devnet and run outside CI, which only typechecks the scenarios.
