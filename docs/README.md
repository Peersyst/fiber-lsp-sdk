# Docs

Long-form documentation that does not belong in code comments. For commands and repository layout see the root
[README.md](../README.md); for agent guidance see [CLAUDE.md](../CLAUDE.md).

## Index

| Doc                                          | What it covers                                                                                                                                                                                                                                  |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [derivation.md](./derivation.md)             | The key derivation scheme end to end: what each channel key protects, the cryptographic primitives, the full derivation tree and normative table, inherited quirks, what the tests guarantee, design decisions, and the conventions still open. |
| [digest.md](./digest.md)                     | The no-blind-signing reconstruction: the four signed-message constructions, the receive-don't-refilter input model, the two key orderings, why fees enter the digest, network pinning, and the vector guarantees.                               |
| [persistence.md](./persistence.md)           | What the device persists: the storage keyspace, the per-channel policy record and why corruption throws, the per-key serialization the sign-once registry depends on and its limit, and what a restore cannot bring back.                       |
| [policy.md](./policy.md)                     | The signing gate: the five checks in order, the slot model and its three fiber-imposed consequences, why sign-once claims a session, why the claim precedes the signature, and the exposure-based balance rule.                                 |
| [protocol.md](./protocol.md)                 | The remote signing protocol v1 as proposed for the review: the encodings, the session frames, the sign request and its ten methods, the four operation objects field by field, and what a frame that does not decode is answered with.          |
| [session.md](./session.md)                   | The signer session client: the effects it is given, its states, the establishment and each way it fails, one request at a time, the heartbeat, the reconnect backoff, device-initiated requests, what a listener may do, and the flow tests.    |
| [signing.md](./signing.md)                   | The musig2 engine: fiber's role order, the deterministic nonces and the rule that makes them safe, what the engine leaves to policy, the dispatch that joins the two at one call site, the wallet identity, and the interop loop.               |
| [../interop/README.md](../interop/README.md) | The cross-implementation harness: how the vectors are generated, regenerated, and re-validated against a new fiber release, and the RPC forms it pins from fiber's own serde.                                                                   |

## Conventions

- Keep docs next to the truth of the code: when a documented behavior changes, update the doc in the same change.
- Cross-link rather than duplicate. A fact belongs in exactly one place.
