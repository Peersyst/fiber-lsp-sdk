# Docs

Long-form documentation that does not belong in code comments. For commands and repository layout see the root
[README.md](../README.md); for agent guidance see [CLAUDE.md](../CLAUDE.md).

## Index

| Doc                                          | What it covers                                                                                                                                                                                                                                  |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [derivation.md](./derivation.md)             | The key derivation scheme end to end: what each channel key protects, the cryptographic primitives, the full derivation tree and normative table, inherited quirks, what the tests guarantee, design decisions, and the conventions still open. |
| [persistence.md](./persistence.md)           | What the device persists: the storage keyspace, the per-channel policy record and why corruption throws, the per-key serialization the sign-once registry depends on and its limit, and the recovery model.                                     |
| [signing.md](./signing.md)                   | The musig2 engine: fiber's role order, the deterministic nonces and the sign-once rule that makes them safe, what the engine validates and what it leaves to policy, and the two halves of the interop loop.                                    |
| [../interop/README.md](../interop/README.md) | The cross-implementation harness: how the vectors are generated, regenerated, and re-validated against a new fiber release.                                                                                                                     |

## Conventions

- Keep docs next to the truth of the code: when a documented behavior changes, update the doc in the same change.
- Cross-link rather than duplicate. A fact belongs in exactly one place.
