# Docs

Long-form documentation that does not belong in code comments. For commands and repository layout see the root
[README.md](../README.md); for agent guidance see [CLAUDE.md](../CLAUDE.md).

## Index

| Doc                                          | What it covers                                                                                                                                                                                                                                  |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [derivation.md](./derivation.md)             | The key derivation scheme end to end: what each channel key protects, the cryptographic primitives, the full derivation tree and normative table, inherited quirks, what the tests guarantee, design decisions, and the conventions still open. |
| [../interop/README.md](../interop/README.md) | The cross-implementation harness: how the vectors are generated, regenerated, and re-validated against a new fiber release.                                                                                                                     |

## Conventions

- Keep docs next to the truth of the code: when a documented behavior changes, update the doc in the same change.
- Cross-link rather than duplicate. A fact belongs in exactly one place.
