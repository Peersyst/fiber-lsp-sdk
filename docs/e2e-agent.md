# The device agent for fiber's e2e suites

Fiber's hosted-LSP pull request ships its own device for its end-to-end suites: `tests/fiber-lsp-sdk-agent`, a Rust
process that registers a tenant, holds its keys and answers the node's signing requests, driven by the Bruno suites
through a small HTTP control port. `e2e/agent/` is the same device run by this SDK: a Node process that speaks that
control contract to the letter, so six of fiber's seven LSP suites (`e2e/lsp`, `e2e/lsp-remote-signer` and the four
`e2e/lsp-remote-signer-watchtower*`) run unchanged with the SDK signing. The seventh, `e2e/lsp-multi-asset`, does not run
on it (`POST /prepare-channel`, [below](#the-contract)), and one assertion of `e2e/lsp` fails
([below](#where-it-parts-from-fibers-agent)).

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

| File                  | What it does                                                                                                           |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `fiber-lsp-sdk-agent` | The wrapper, linked at that path: it runs `node e2e/agent/dist/src/main.js --nonce-cap-bypass` with the same arguments |
| `cargo`               | A shim first in `PATH`: it skips the build of the Rust agent and passes every other cargo call through                 |
| `install.sh`          | Links the wrapper into `target/debug/`, moving the Rust binary aside; `--restore` puts the Rust binary back            |

`install.sh` takes the `debug` profile alone: on the devnet the agent pins fiber's debug epoch (2 s,
`MILLI_SECONDS_PER_EPOCH` in a debug build) as the SDK's `millisecondsPerEpoch`, which a release build's nodes do not run.

## The contract

The flags and their environment variables are fiber's (`--rpc`, `--ws-rpc`, `--store`, `--operator-token`,
`--lsp-node-id`, `--status-file`, `--control-addr`); `--contracts-dir` and `--ckb-rpc` have no
environment variable, as in fiber's agent. `--ckb-rpc` is accepted and unused, since the SDK has no chain client, and so is
`--ws-rpc`, the endpoint of fiber's signing subscriptions, since the SDK polls. `--lsp-node-id` is required: it is the LSP's
node id the device trusts, `0x` optional, and the agent pins the facade's `lspPubkey` to it and signs its registration to
it, asking the node for nothing. Three flags are this agent's alone:

| Flag                                                          | What it does                                                                                                                                |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `--interval-ms` (`FIBER_LSP_SDK_AGENT_INTERVAL_MS`)           | The SDK's poll interval, 200 ms by default; at least 1, since it is a timer delay. Fiber's agent subscribes instead and has no interval     |
| `--nonce-cap-bypass` (`FIBER_LSP_SDK_AGENT_NONCE_CAP_BYPASS`) | Takes no value; the variable takes `true`, `false`, `1` or `0`. Off by default; the devnet wrapper sets it ([below](#the-nonce-cap-bypass)) |
| `--network` (`FIBER_LSP_SDK_AGENT_NETWORK`)                   | `devnet` (the default), with the contracts read from `--contracts-dir`, or `testnet`, the SDK's preset, which refuses `--contracts-dir`     |

`--once` is refused, the agent has no single-poll mode, and so is any other flag fiber's agent does not have. The control
port answers:

| Request                 | Answer                                                                                                                                                                      |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /status`           | The status file, or 503 before it exists                                                                                                                                    |
| `POST /open-channel`    | `{ result }` with the node's `OpenChannelWithExternalFundingResult`, once the SDK checked and pinned it; else 400                                                           |
| `POST /authorize`       | `{ result: { authorized: true } }` for `Invoice`, `Payment`, `Fulfillment`, `ReleasePreimage`, `Close` and `Watchtower`; else 400                                           |
| `POST /shutdown`        | `{ status: "restarting" }`, then the process exits 0 and `start.sh`'s loop restarts it on its store                                                                         |
| `POST /prepare-channel` | 404: fiber's `lsp-multi-asset` suite allocates a tenant's next channel there, and the SDK opens one channel at a time with no UDT, so that suite does not run on this agent |

Every failure of `/open-channel` and `/authorize` is a 400 with `{ error }`, as in fiber's agent; one that is not a
refusal of the request is also logged in full.

`Payment` and `Fulfillment` carry fiber's checks (`authorize_payment`, and `CommitmentState`'s `authorize` and `resolve`,
d8dd6d28 `fiber-lsp-sdk/src/signer.rs:622-665` and `commitment.rs:255-300`). A refusal's `error` is fiber's message alone,
quoted below, where fiber's agent answers it as `invalid signing content: commitment validation: <message>`:

- `Payment` approves an outgoing payment of an exact amount, the routing fee budget included. Its terms are refused
  `inbound` ("inbound authorization requires authorize_invoice and a matching preimage"), with an amount or a
  `min_tlc_expiry_delta_ms` of 0, or a `max_tlc_expiry_ms` not above `expires_at_ms` ("invalid payment amount or expiry
  bounds"), the same bounds `Invoice`'s terms take. The agent keeps the terms and records the SDK's open debit intent for
  the hash with the amount as its budget, which is what the SDK signs an offered TLC against; it refuses a hash of one of
  the device's hold invoices, one whose first 20 bytes another hold invoice's hash shares, or one the SDK already holds
  another intent under.
- `Fulfillment` names a payment and its preimage: refused when no `Payment` or `Invoice` of that channel authorized the
  hash ("unknown payment"), or when the preimage does not hash to it under that authorization's algorithm ("preimage does
  not match payment hash"). It records nothing.

`Invoice` and `Payment` both end in `CommitmentState::authorize`: the same terms again are a no-op, and other terms under
the hash, or a hash the other one authorized, are refused ("payment authorization cannot be replaced"). Fiber checks the
hash per channel signer, the agent across the device's channels: the SDK keeps one debit intent per payment hash, whichever
channel the TLC takes, so a hash holds one authorization on the device.

On start the agent serves the port, then initializes, retrying every second until the node answers: it builds the facade
with `nonceReuse: "allow"` and, unless its store holds a token, registers the tenant: `signTenantRegistration` over a
request id of 32 random bytes and the clock's time in milliseconds, then `lsp_register_tenant` with the operator token.
Each attempt draws its own request id, since the node refuses a request id it has seen for good. It checks the tenant id
and hands the token to the facade. The store keeps the master seed, the SDK's storage and `agent.json` (the token, the
channels opened with both close scripts, and the authorizations), so a restart makes no operator call and keeps the token.
`agent.json` is read field by field, so one of another shape, an earlier agent's included, is refused at start and its store
is wiped rather than migrated; the devnet runs start on a clean store.

Every SDK event is logged as one JSON line on stdout. The status file is rewritten from `channelEvidence` at
initialization, after an open or an authorization that succeeded, and on every SDK event.

## The nonce-cap bypass

Fiber's current nonce lifecycle asks the device for a third signing session on one slot when the peer fulfils a payment
the device sent, and `nonceReuse: "allow"` refuses it, since three signatures under one deterministic nonce solve for the
funding key ([policy.md](./policy.md), "The known cost"). Fiber's `e2e/lsp` suite sends that payment (steps 27b to 29).
With `--nonce-cap-bypass`, the agent hands the SDK its storage behind `NonceCapBypassStorage`, which reads every channel
policy record (`fiber-lsp-sdk:channel:<index>`) with each `nonceReuse` mark moved into `signedSessions`, so a slot that
served two sessions reads as one that served the second alone, and a third is served as a second. A repeat of that latest
session is answered as already signed, the same signature again, without the reuse warning it carries without the bypass;
a repeat of an earlier one reads as a new session. The storage keeps what the SDK writes; every other key reads as stored.

It is test-only: on any key that matters it gives the funding key away. It is off unless asked for, the wrapper in
`devnet/` sets it so fiber's suites run to the end, and it goes once fiber's nonces are strict. A scenario asks for it
per device (`ScenarioDevice.create(env, { nonceCapBypass: true })`), which only `served-third-session` and `cancel-and-force-close` do.

## Where it parts from fiber's agent

Fiber's agent drives fiber's own SDK, whose model differs from this one's in places; each difference is the SDK's
position, kept here rather than bent to the contract.

| Fiber's agent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | This agent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `channel_open_signer_material` is the next opening block, allocated before the open                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `{ "allocated_at_open": true }` until a channel is bound, then `null`: the SDK derives the block in `prepareChannelOpen`, at an index it allocates then, so the `external_channel_signer` the driver sends back is ignored                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `/open-channel` takes fiber's open params whole                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Only what `prepareChannelOpen` sends: the LSP as peer, a private channel, the shutdown script equal to the funding lock, fiber's default delay and fee rate (compared by value), no UDT and none of the other options fiber's params have; any of those is a 400, and a key fiber's params do not have is ignored, as serde does                                                                                                                                                                                                                                                                                                               |
| Subscribes to `channel_signing` and `watchtower_signing` over `--ws-rpc`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Polls through the SDK every `--interval-ms`, and leaves `--ws-rpc` unused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `Invoice` hands the SDK the terms and a preimage the driver chose; fiber's `authorize_invoice` refuses terms that are not `inbound` and a preimage that does not hash to `payment_hash`                                                                                                                                                                                                                                                                                                                                                                                            | The agent makes the same refusals, the terms' bounds included, and keeps the terms and the preimage: the SDK derives its own preimages and holds no other, and signs an incoming TLC under its balance rule whatever its hash                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `Payment` hands fiber's SDK the terms, which bound each TLC it signs under the hash: amount, acceptance deadline and expiry window                                                                                                                                                                                                                                                                                                                                                                                                                                                 | The agent makes the same refusals and records the SDK's debit intent with the amount as its budget, written to the SDK's storage in the policy's own record, since the facade records one only inside `transfer`, which sends the payment itself. The SDK checks an offered TLC against the budget alone, not the deadline or the expiry window                                                                                                                                                                                                                                                                                                |
| `Fulfillment` records the preimage, without which fiber's SDK signs no removal of the TLC as fulfilled                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | The agent makes the same refusals and records nothing: the SDK signs the removal under its balance rule, charging the debit intent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `ReleasePreimage` (fiber's `authorize_preimage_release` and `release_preimage`) requires: the channel bound; its funding cell live on chain with the approved output and data; the invoice known, inbound, not cancelled, and the preimage hashing to it under its algorithm; the latest local commitment with a complete signature, not revoked, holding the incoming TLC with that hash, the invoice's amount and its algorithm; and that TLC's expiry past now plus the safety margin (two thirds of the commitment delay). Then it calls `settle_invoice` or `create_preimage` | Ported: the channel bound, an `Invoice` with that hash on that channel (inbound, checked when it was given), and the preimage hashing to it under the invoice's algorithm; nothing cancels an invoice here. Not ported: the funding cell, since the SDK has no chain client, and the commitment and TLC checks, since the SDK's public evidence carries no TLC set. Then the agent calls the node itself                                                                                                                                                                                                                                       |
| `Close` sets the fee shares the SDK's close check takes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | The agent checks both scripts against the open's and records it; the SDK signs a close by its pins and its fee bound, with no per-close authorization                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `Watchtower` approves a destination and a fee cap per channel                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | One approval, the SDK's `watchtower` option. The agent changes it its own way, not through `setWatchtowerApproval`, which the SDK has: it retires the facade (closes its fetch, disconnects, waits until its last request settled) and builds another with the approval. The same channel's approval replaces the last; another channel's that differs in destination or fee cap is a 400. When the new facade cannot be built or the approval cannot be written, a facade over the previous state runs on and the request is a 400                                                                                                            |
| `revoked_commitments` carries each revoked commitment's `tx_hash`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `{ for_remote, version }` alone: the evidence keeps the revocation, not the hash of what it revoked                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `POST /prepare-channel` allocates the key of a tenant's next channel, for `lsp-multi-asset`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | 404: the SDK opens one channel at a time, with no UDT                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Never lists channels: under it, a tenant `lsp_evict_tenant` evicted stays cold until a payment or an operator reactivates it                                                                                                                                                                                                                                                                                                                                                                                                                                                       | While the agent's channel is open, the SDK's channel step calls `list_channels` every tick to see it close, and fiber serves a tenant's `list_channels` through `GetTenantRpcContext`, which reactivates the tenant (`supervisor.ensure`, d8dd6d28 `lsp/service.rs:506-517`); the signing-status poll reads the store without it (`:518-534`). So the tenant is running again within a tick of the eviction. `-evict` asserts only the eviction's response, but `e2e/lsp`'s `10-check-cold-lsp-status`, half a second after the eviction, reads `active_tenants` at 1 where it asserts 0: the one assertion of the six suites this agent fails |
| A control body over 1 MiB drops the connection unanswered and ends the control task; a closed control queue is a 503                                                                                                                                                                                                                                                                                                                                                                                                                                                               | A body over 1 MiB is a 400 and the port serves on; there is no queue to close. The `error` messages are this agent's and the SDK's own wording                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

## Scenarios

Fiber's suites drive the device through its control contract alone: they open, authorize and restart it.
`e2e/agent/scenarios/` holds nine scenarios of the SDK's own that the contract cannot express, `node:test` specs that
build the facade in process over the same nodes under `nonceReuse: "allow"`, as the agent runs, each with a tenant and
a channel of its own, and inject faults through the `fetch` it is given. They run on fiber's devnet or on testnet
([below](#running-it-on-testnet)):

| Scenario                 | What it asserts                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `late-signer`            | A device disconnected while node 1 pays its invoice: the node holds the request and the payment stays `Inflight`; once it connects, the request is signed with its deadline reported and still ahead, and the invoice is paid                                                                                                                                                                                                                                                                                                                                                                    |
| `restart-pending`        | The first submission of the payment's first signature lost before it reaches the node: a new facade over the same store serves the same request with the same bytes, with no third session                                                                                                                                                                                                                                                                                                                                                                                                       |
| `non-hosted-payer`       | Node 3 pays the SDK's invoice through node 1 and the LSP, routed by the invoice's trampoline hint                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `two-tenants`            | Two devices paid at once: each signs and polls only its own channel, and one tenant's token reading the other's channel is refused (`channel ... not found`)                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `altered-opening`        | Three alterations of `open_channel_with_external_funding`'s answer (the LSP's close script grown past the reserve the node states, the funding output's capacity, the fee rate), each refused as `opening_rejected` with nothing signed or funded, then a clean opening on the same device                                                                                                                                                                                                                                                                                                       |
| `outbound-payment`       | A payment sent by the device: its fulfil asks a third session on `Commitment@3`, which `nonceReuse: "allow"` refuses, fiber force-closes the channel from the tenant's side, and the payment stays `Inflight`                                                                                                                                                                                                                                                                                                                                                                                    |
| `served-third-session`   | The same payment under the nonce-cap bypass and the default five-second poll: the third session on `Commitment@3` served as a second, `PAYMENT_SENT`, the payment `Success` and node 1's invoice `Paid`, the channel still `ChannelReady` past the watchdog's latest close, then a payment received with the usual steps                                                                                                                                                                                                                                                                         |
| `backgrounded-round`     | A payment received, the device sent to the background as its `SendRevokeAndAck` lands: back inside fiber#1701's window it finishes the round, the payment received and the channel ready; back past it, it finds the channel force-closed `UNCOOPERATIVE_LOCAL` by fiber#1701, the payer's payment `Inflight` and the invoice `Open`, with no `PAYMENT_RECEIVED`                                                                                                                                                                                                                                 |
| `cancel-and-force-close` | An `Open` invoice cancelled ends `PAYMENT_CANCELLED` with the node's invoice `Cancelled`, and a second cancel is no error; a payer holding the string fails; a cancel from `PAYMENT_PENDING`, with the TLC held, fails the held TLC back and ends `PAYMENT_CANCELLED` with the channel's balances as they were; `forceCloseChannel` ends in `CHANNEL_CLOSED` with no signing request, the watchtower's spend refused as `policy_refusal` while no approval is given, and the approval given afterwards signs that pending spend with no new facade. The scenario runs under the nonce-cap bypass |

The outbound scenario asserts the refusal on purpose, and runs without the bypass. Under `allow` a slot serves two
sessions and never a third, and the peer's fulfil of a payment the device sent asks for a third on the commitment slot
the device's own round left at the local number. On the devnet node 1's invoice is paid by then, so the LSP holds the
preimage. The refused round leaves the channel's revocation nonce ledger unbalanced, and fiber force-closes a channel
whose ledger stays so past its peer response timeout (fiber#1701: 30 s, checked every 3 s in a debug build, d8dd6d28
`fiber/channel.rs:6787-6793`), so some 30 to 33 s after the refusal on the devnet: the scenario waits for the channel to
leave `ChannelReady` up to the watchdog's latest close plus 27 s ([below](#the-margins)), waits until the device reports
`CHANNEL_CLOSED`, which needs the commitment confirmed and never its settlement, and asserts the close is
`UNCOOPERATIVE_LOCAL` in the tenant's listing: only the tenant's side runs the check, the LSP's side having the tenant
for an internal peer. The sent TLC then settles on chain: the LSP's side holds the preimage, and fiber's watchtower
claims the TLC with it once a third of the commitment delay has passed (d8dd6d28 `watchtower/actor.rs:1626-1647`), past
the point the scenario mines or waits to, so the tenant's payment is `Inflight`, with no payment event. Under the bypass
the same payment completes (`served-third-session`); `outbound-payment` turns into a completed payment only once fiber's
nonces are strict and `allow` is gone. Each channel otherwise takes a single received payment, since a second one after
a fulfilled one asks the same third session ([policy.md](./policy.md), "The known cost").

`backgrounded-round` meets the same watchdog in the same gap with every session served, the device absent rather than
refusing, in a round the peer starts: the window opens when the device's `SendRevokeAndAck` lands, since fiber then
waits for its `commitment_signed`. The device disconnects from inside its event listener, so no tick runs after the
revocation, and reconnects inside the window or past it (21 s and 45 s on the devnet, 21 s and 102 s on testnet,
[below](#the-margins)). At the default poll `served-third-session` signs one step per channel per tick, and two back to
back where a hold invoice's release polls again at once, so each gap between two of the device's steps is about one
poll, well inside fiber's 30 s.

On the devnet every opening first mines until CKB's pool is empty. A force close leaves its settlement in the pool for a
while, and an opening funded then was aborted (`FUNDING_ABORTED`, node 2 logging `invalid cell status: "unknown"` while
signing the funding tx), so a scenario that follows `outbound-payment` would fail on the order alone. On testnet nothing
is mined and the shared pool never empties: every funding and close a scenario makes is already confirmed before its
next opening, since `ChannelReady` and `CHANNEL_CLOSED` both wait on the confirmation.

Node 1 funds every tenant opening, and the scenario signs its inputs itself: `e2e/agent/src/sighash-signer.ts` signs
each input whose live cell is the key's default lock (CKB's secp256k1-blake160 with sighash-all), one signature in the
first witness of the group, the way CKB's default lock checks it. For the transaction fiber hands out, fiber's
`sign_external_funding_tx` signs the same way, but it matches inputs by the lock's args alone and pads witnesses only up
to the group's first input, where this signer checks the whole lock and pads every input of the group; and it belongs to
the `dev` RPC module, which only a debug build serves (`rpc/mod.rs:476`), so both networks sign locally.

Fiber keeps an opening the device refused until its external funding times out (five minutes by default), but refuses
another one only under the same channel signer ("tenant already has a different channel opening for this signer"). The
SDK drops the pending opening it refuses, so the next one takes a fresh channel index and keys of its own, and the three
alterations and the clean opening run back to back on one device.

`FIBER_E2E_NETWORK` picks the network: unset or empty is `devnet`, `testnet` the other, and any other value is refused.
On the devnet the scenarios read the URLs, keys and operator token from fiber's `tests/bruno/environments/test.bru` and
the contracts from `tests/deploy/contracts`, both under `FIBER_CHECKOUT` (absolute, or relative to `e2e/agent`, where
`pnpm --dir` runs them), and refuse a set `FIBER_E2E_ENV_FILE`. Fiber's devnet starts its LSP only under one of its LSP
suites' names, and its agent runs beside the scenarios with a tenant of its own:

```bash
# in <fiber-checkout>, with the wrapper installed as above
PATH="<sdk-checkout>/e2e/agent/devnet:$PATH" REMOVE_OLD_STATE=y ./tests/nodes/start.sh e2e/lsp-remote-signer

# in <sdk-checkout>, once tests/nodes/wait.sh returns
# one scenario: pnpm --dir e2e/agent build && FIBER_CHECKOUT=<fiber-checkout> node --test e2e/agent/dist/scenarios/<name>.scenario.js
FIBER_CHECKOUT=<fiber-checkout> pnpm --dir e2e/agent scenarios
```

They run in series on one devnet; a run has taken some six and a half minutes.

## Running it on testnet

On testnet the scenarios run against an LSP and two plain nodes someone operates, under the SDK's `testnet` preset, and
read everything from the file `FIBER_E2E_ENV_FILE` names (absolute, or relative to `e2e/agent`), refusing a set
`FIBER_CHECKOUT`:

```bash
FIBER_E2E_NETWORK=testnet FIBER_E2E_ENV_FILE=<env-file> pnpm --dir e2e/agent scenarios
```

The file is `KEY=value` lines, with blank lines and whole-line `#` comments allowed (a `#` inside a value is refused),
no quotes, no spaces around `=` and no key set twice; a value may hold `=`, and keys the scenarios do not read are
ignored. It sets the keys the scenarios read from `test.bru` on the devnet, and keys of its own:

| Key                                                  | What it is                                                                             |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `CKB_RPC_URL`                                        | A CKB testnet RPC: the funding signer reads the live cells of the inputs it signs      |
| `NODE1_RPC_URL`, `NODE2_RPC_URL`, `NODE3_RPC_URL`    | Node 1 (the payer and funder), the LSP, node 3 (a payer the LSP does not host)         |
| `NODE1_ADDR`, `NODE2_ADDR`, `NODE3_ADDR`             | Their multiaddrs, for `connect_peer`                                                   |
| `NODE1_PUBKEY`, `NODE2_PUBKEY`, `NODE3_PUBKEY`       | Their node ids                                                                         |
| `LSP_OPERATOR_TOKEN`                                 | A biscuit with the LSP's operator rights                                               |
| `LSP_REMOTE_SIGNER_FUNDING_PRIVKEY`                  | The key of node 1's default funding lock, which funds the tenant channels              |
| `PEER_CHANNEL_RESPONSE_TIMEOUT_MS`                   | Fiber's `PEER_CHANNEL_RESPONSE_TIMEOUT`, 30000 in a debug and a release build          |
| `CHECK_CHANNELS_INTERVAL_MS`                         | Fiber's `CHECK_CHANNELS_INTERVAL`, 60000 in a release build                            |
| `TENANT_CHANNEL_SHANNONS`, `PUBLIC_CHANNEL_SHANNONS` | Node 1's side of a tenant channel and a public channel's funding, as positive integers |

The LSP runs a release build (a debug build counts an epoch as 2 s, which testnet does not), with `lsp` among its
services and a biscuit public key with the private key it issues tenant tokens with (`rpc.biscuit_public_key` and
`rpc.biscuit_private_key_path`); `rpc.ws_listening_addr` only serves fiber's own Rust agent, and nothing here uses it.
The funder needs no `dev` module. Testnet's reserve is 100 CKB a side, so 200 CKB a tenant channel covers it and the
payments; the public channels between node 1, node 3 and the LSP take 500 CKB.

The LSP, which builds every tenant funding tx, keeps the inputs it picked for one, node 1's and its own contribution,
out of every funding tx it builds next, in memory, until that opening aborts (five minutes after it went unsigned), or
for 13 blocks after the tx commits (fiber's `KEEP_BLOCK_PERIOD`, d8dd6d28 `ckb/funding/funding_tx.rs:38-40,101-111`),
about 2 minutes on testnet. `altered-opening` leaves three openings unsigned on purpose, so with node 1's or the LSP's
balance in one cell no tenant opening can be built for five minutes after it; what node 1 funds by itself, such as its
public channel, is not held. Both need their balance in many cells. Node 1's cells of some 270 CKB each fund one opening
and keep its change; the LSP's need about 175 CKB to fund one channel from a single input, its 110 CKB and change above
the 61 CKB a cell under its lock holds, and smaller ones are combined. The LSP puts into each tenant channel its
auto-accept amount (`--fiber-auto-accept-channel-ckb-funding-amount`), of which 100 CKB is the reserve: the scenarios
move 0.01 CKB toward the device, so 110 CKB suffices, and a run then costs the LSP about 1,100 CKB and node 1 about
2,000. Node 1's share of a force-closed tenant channel is lost: the device's settlement needs its signature, and
`ScenarioDevice.close()` wipes the device's store, so nothing ever signs it.

### The margins

The windows that depend on fiber#1701 come from the pair of fiber's timings, the latest close being the timeout plus
one check interval:

| Margin                                       | Formula                | Devnet (30 s, 3 s) | Testnet (30 s, 60 s) |
| -------------------------------------------- | ---------------------- | ------------------ | -------------------- |
| `backgrounded-round`, back inside the window | timeout less 9 s       | 21 s               | 21 s                 |
| `backgrounded-round`, back past it           | latest close plus 12 s | 45 s               | 102 s                |
| `served-third-session`, channel still ready  | latest close plus 3 s  | 36 s               | 93 s                 |
| `outbound-payment`, the force close's window | latest close plus 27 s | 60 s               | 117 s                |

An opening waits up to 5 minutes on the devnet and 10 on testnet, and a graph announcement 3 and 10.

A run on testnet has taken some 20 to 25 minutes, an opening some 60 to 100 s with its confirmations: both follow the
block times and the shared pool, not the scenarios. The asserted error messages read the same as on the devnet.

### Signing a funding by hand

The signer has a command of its own, for a funding the scenarios do not make (the agent's `/open-channel` hands back
`unsigned_funding_tx` for the driver to sign and submit):

```bash
CKB_SIGNER_PRIVATE_KEY="$(cat <key-file>)" CKB_RPC_URL=<ckb rpc> node e2e/agent/dist/src/sign-tx.js < unsigned.json > signed.json
```

Stdin is the transaction object alone, in CKB's JSON; stdout is the same transaction with the inputs under the key's
default lock signed. The key is read from the environment alone, never from the arguments a process listing shows. Any
failure exits 1 with `sign-tx: <reason>` on stderr: no input under the key's lock, a malformed transaction or witness, an
input whose cell is not live.

### The watchtower on testnet

The agent runs on testnet with `--network testnet`. The driver opens its channel through `/open-channel`, signs and
submits the funding, authorizes `Watchtower` with the destination and fee cap, and the LSP force-closes the channel with
its operator token. The commitment confirms within minutes; its outputs only become spendable a commitment delay later,
one epoch, some 4 hours, when fiber's watchtower asks the device to sign the settlement and the agent serves it through
the SDK's watchtower step.

On a 200 CKB channel the commitment delay ran out some 4 hours after the commitment confirmed, and the agent's
`watchtower_submissions` then listed the channel's `Settlement` request. The watchtower asked twice, and the agent signed
both: the first spend takes the commitment's output 0 and a fee cell into a new cell under the
commitment lock, the second takes that cell to the authorized destination. The commitment lock, with its 58-byte args,
accepted both spends, and the channel stayed `Closed` with `UNCOOPERATIVE_REMOTE` once the settlement confirmed.

## Tests

`pnpm --dir e2e/agent test` compiles the agent and its specs and runs them with `node --test`: the config, the store,
the JSON-RPC calls, the contract's readers, the status and the bypass, the scenarios' environment, CKB's transaction and
the sighash-all signer (against transactions committed on testnet), and the process over a fake node, including a real
opening the SDK accepts and a registration checked against the device's signatures. The suites need fiber's devnet and
the scenarios the devnet or testnet; both run outside CI, which only typechecks the scenarios.
