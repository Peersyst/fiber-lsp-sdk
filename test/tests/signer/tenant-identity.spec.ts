import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { UINT64_MAX } from "../../../src/common";
import { blake2bHashWithSalt } from "../../../src/derivation";
import type { RegisterTenantParams } from "../../../src/rpc";
import type { TenantRegistryPayload } from "../../../src/signer";
import {
    TENANT_ID_DOMAIN,
    TENANT_REGISTRY_MAX_SIGNED_AT_AGE_MS,
    TENANT_REGISTRY_MAX_SIGNED_AT_FUTURE_SKEW_MS,
    TenantIdentity,
    buildTenantRegistryPayload,
    computeTenantId,
    computeTenantRegistryDigest,
    deriveTenantId,
    readTenantRegistration,
    verifyTenantRegistration,
} from "../../../src/signer";
import { loadInteropVectors } from "../../utils/interop-vectors";
import { refusalOf } from "../../utils/refusal";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const OTHER_MASTER_SEED = new Uint8Array(32).fill(0x25);
// `deriveWalletIdentityKey(MASTER_SEED)`, pinned in the device scheme's spec.
const WALLET_IDENTITY_KEY = "fe11dd3161e80f6e20a43106d2b0853ec87d613c87ab0c87f41584c31f091ed1";
const ROOT_SIGNER_PUBKEY = "038dd0502b955500a40aa41114374cdc96ed2c34e85e1473f23ae80cddb0afcb26";
const OTHER_ROOT_SIGNER_PUBKEY = "038abd41e20e2c0b61c0c2acfbbd2146d648f275165c3256d8116ee20c78c1f095";
// `pubkeyOf(0x11 * 32)`.
const LSP_NODE_ID = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
// `pubkeyOf(0x12 * 32)`.
const OTHER_LSP_NODE_ID = "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7";
const REQUEST_ID = "0303030303030303030303030303030303030303030303030303030303030303";
const SIGNED_AT_MS = 1_700_000_000_123n;
// "fiber-hosted-lsp-tenant-registry/v2".
const PROTOCOL = "66696265722d686f737465642d6c73702d74656e616e742d72656769737472792f7632";
// SIGNED_AT_MS as a big-endian u64.
const SIGNED_AT = "0000018bcfe5687b";
const PAYLOAD = PROTOCOL + LSP_NODE_ID + ROOT_SIGNER_PUBKEY + REQUEST_ID + SIGNED_AT;
// Fiber's, from its interop harness over the same registration.
const DIGEST = "0da1c848b192e6bb08bd55dda31cf01dccce57909313e305562557b1d7d3321f";
const SIGNATURE =
    "758bd70fedc06ea87fef9f2bddcfd86975978e6eb697c52dd31ac299cc117dbc" + "55a0bf5c2d8091307842cf205743415e42483539806935a43576358dba0c827d";

// Fiber's fixed vectors (`fiber-types/src/hosted_lsp.rs:188-200`): the RootSigner of the secret 42 repeated, the LSP of the
// secret 7 repeated, the request id 3 repeated, signed at 1_700_000_000_123.
const FIBER_ROOT_SIGNER_PUBKEY = "035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c";
const FIBER_LSP_NODE_ID = "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f";
const FIBER_CANONICAL_BYTES =
    "66696265722d686f737465642d6c73702d74656e616e742d72656769737472792f763202989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c576" +
    "25596e05f6f035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c0303030303030303030303030303030303030303030303030" +
    "3030303030303030000018bcfe5687b";
const FIBER_DIGEST = "0119b795a736bcbb4d6d9f255500d0584f8702133e6d61c04bfc0a42081e3375";
const FIBER_TENANT_ID = "5feabe8ac4480f8979ecbf3fb43618dd0d3472eb140235a35ee643d4346b862f";

type RegistrationRequest = Omit<TenantRegistryPayload, "rootSignerPubkey">;

function request(): RegistrationRequest {
    return { lspNodeId: hexToBytes(LSP_NODE_ID), requestId: hexToBytes(REQUEST_ID), signedAtMs: SIGNED_AT_MS };
}

function payload(): TenantRegistryPayload {
    return {
        lspNodeId: hexToBytes(LSP_NODE_ID),
        rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY),
        requestId: hexToBytes(REQUEST_ID),
        signedAtMs: SIGNED_AT_MS,
    };
}

function unchecked(value: unknown): RegistrationRequest {
    return value as RegistrationRequest;
}

// Whether the signature is the root signer's over the digest of the payload written out in hex.
function signsPayload(signature: Uint8Array, payloadHex: string): boolean {
    const digest = blake2bHashWithSalt(hexToBytes(payloadHex), new Uint8Array(0));
    return secp256k1.verify(signature, digest, hexToBytes(ROOT_SIGNER_PUBKEY), { prehash: false });
}

function typeErrorOf(step: () => unknown): string {
    return refusalOf(TypeError, step).message;
}

function rangeErrorOf(step: () => unknown): string {
    return refusalOf(RangeError, step).message;
}

describe("against fiber's fixed registry vectors", () => {
    const fiberPayload = (): TenantRegistryPayload => ({
        lspNodeId: hexToBytes(FIBER_LSP_NODE_ID),
        rootSignerPubkey: hexToBytes(FIBER_ROOT_SIGNER_PUBKEY),
        requestId: new Uint8Array(32).fill(3),
        signedAtMs: 1_700_000_000_123n,
    });

    it("takes its RootSigner and its LSP from fiber's secrets", () => {
        expect(bytesToHex(secp256k1.getPublicKey(new Uint8Array(32).fill(42), true))).toBe(FIBER_ROOT_SIGNER_PUBKEY);
        expect(bytesToHex(secp256k1.getPublicKey(new Uint8Array(32).fill(7), true))).toBe(FIBER_LSP_NODE_ID);
    });

    it("writes fiber's canonical bytes, 141 of them", () => {
        const bytes = buildTenantRegistryPayload(fiberPayload());
        expect(bytesToHex(bytes)).toBe(FIBER_CANONICAL_BYTES);
        expect(bytes).toHaveLength(141);
    });

    it("hashes them into fiber's digest", () => {
        expect(bytesToHex(computeTenantRegistryDigest(fiberPayload()))).toBe(FIBER_DIGEST);
    });

    it("derives fiber's tenant id from its RootSigner", () => {
        expect(bytesToHex(blake2bHashWithSalt(hexToBytes(FIBER_ROOT_SIGNER_PUBKEY), utf8ToBytes(TENANT_ID_DOMAIN)))).toBe(FIBER_TENANT_ID);
        expect(computeTenantId(hexToBytes(FIBER_ROOT_SIGNER_PUBKEY))).toBe(FIBER_TENANT_ID);
    });
});

describe("buildTenantRegistryPayload", () => {
    it("writes the protocol, the LSP's node id, the root signer, the request id and the signing time, in fiber's order", () => {
        expect(bytesToHex(buildTenantRegistryPayload(payload()))).toBe(PAYLOAD);
    });

    it.each([
        ["0", 0n, "0000000000000000"],
        ["u64's maximum", UINT64_MAX, "ffffffffffffffff"],
    ])("writes a signing time of %s as eight big-endian bytes", (_, signedAtMs, written) => {
        const bytes = bytesToHex(buildTenantRegistryPayload({ ...payload(), signedAtMs }));
        expect(bytes).toBe(PROTOCOL + LSP_NODE_ID + ROOT_SIGNER_PUBKEY + REQUEST_ID + written);
    });

    it("refuses a payload that is not an object", () => {
        expect(typeErrorOf(() => buildTenantRegistryPayload(null as unknown as TenantRegistryPayload))).toBe("payload must be an object");
    });

    // Only a direct call reaches these: `signRegistration` writes its own key.
    it.each([
        ["absent", undefined, "rootSignerPubkey must be a Uint8Array"],
        ["in hex", ROOT_SIGNER_PUBKEY, "rootSignerPubkey must be a Uint8Array"],
        ["of 32 bytes", hexToBytes(ROOT_SIGNER_PUBKEY).slice(0, 32), "rootSignerPubkey must be 33 bytes, got 32"],
        ["33 zero bytes, no point", new Uint8Array(33), "rootSignerPubkey must be a compressed point on secp256k1"],
    ])("refuses a root signer %s", (_, rootSignerPubkey, message) => {
        const refused = { ...payload(), rootSignerPubkey: rootSignerPubkey as Uint8Array };
        expect(typeErrorOf(() => buildTenantRegistryPayload(refused))).toBe(message);
    });

    it.each([
        ["absent", undefined, "lspNodeId must be a Uint8Array"],
        ["in hex", LSP_NODE_ID, "lspNodeId must be a Uint8Array"],
        ["of 32 bytes", hexToBytes(LSP_NODE_ID).slice(0, 32), "lspNodeId must be 33 bytes, got 32"],
        ["33 zero bytes, no point", new Uint8Array(33), "lspNodeId must be a compressed point on secp256k1"],
    ])("refuses an LSP node id %s", (_, lspNodeId, message) => {
        const refused = { ...payload(), lspNodeId: lspNodeId as Uint8Array };
        expect(typeErrorOf(() => buildTenantRegistryPayload(refused))).toBe(message);
    });

    it.each([
        ["absent", undefined, "requestId must be a Uint8Array"],
        ["in hex", REQUEST_ID, "requestId must be a Uint8Array"],
        ["of 31 bytes", new Uint8Array(31).fill(0x03), "requestId must be 32 bytes, got 31"],
        ["of 33 bytes", new Uint8Array(33).fill(0x03), "requestId must be 32 bytes, got 33"],
    ])("refuses a request id %s", (_, requestId, message) => {
        const refused = { ...payload(), requestId: requestId as Uint8Array };
        expect(typeErrorOf(() => buildTenantRegistryPayload(refused))).toBe(message);
    });

    it.each([
        ["absent", undefined, "undefined"],
        ["negative", -1n, "-1"],
        ["past u64's maximum", UINT64_MAX + 1n, "18446744073709551616"],
    ])("refuses a signing time %s", (_, signedAtMs, got) => {
        const refused = { ...payload(), signedAtMs: signedAtMs as bigint };
        expect(rangeErrorOf(() => buildTenantRegistryPayload(refused))).toBe(
            `signedAtMs must be a bigint between 0 and 18446744073709551615, got ${got}`,
        );
    });

    it("reads each member of the payload once: what it checks is what it writes", () => {
        const reads: string[] = [];
        const shifting = {
            get lspNodeId(): Uint8Array {
                reads.push("lspNodeId");
                return hexToBytes(reads.length > 4 ? OTHER_LSP_NODE_ID : LSP_NODE_ID);
            },
            get rootSignerPubkey(): Uint8Array {
                reads.push("rootSignerPubkey");
                return hexToBytes(reads.length > 4 ? OTHER_ROOT_SIGNER_PUBKEY : ROOT_SIGNER_PUBKEY);
            },
            get requestId(): Uint8Array {
                reads.push("requestId");
                return reads.length > 4 ? new Uint8Array(31) : hexToBytes(REQUEST_ID);
            },
            get signedAtMs(): bigint {
                reads.push("signedAtMs");
                return reads.length > 4 ? -1n : SIGNED_AT_MS;
            },
        };
        expect(bytesToHex(buildTenantRegistryPayload(shifting))).toBe(PAYLOAD);
        expect(reads).toEqual(["lspNodeId", "rootSignerPubkey", "requestId", "signedAtMs"]);
    });
});

describe("computeTenantRegistryDigest", () => {
    it("hashes the payload into fiber's digest", () => {
        expect(bytesToHex(computeTenantRegistryDigest(payload()))).toBe(DIGEST);
    });

    it("is fiber's salted hash of the payload with an empty salt", () => {
        expect(bytesToHex(blake2bHashWithSalt(hexToBytes(PAYLOAD), new Uint8Array(0)))).toBe(DIGEST);
    });
});

describe("TenantIdentity", () => {
    const identity = new TenantIdentity(MASTER_SEED);

    describe("identity", () => {
        it("exposes the compressed public key of the wallet identity key", () => {
            expect(bytesToHex(identity.publicKey)).toBe(ROOT_SIGNER_PUBKEY);
            expect(bytesToHex(identity.publicKey)).toBe(bytesToHex(secp256k1.getPublicKey(hexToBytes(WALLET_IDENTITY_KEY), true)));
        });

        it("derives the pinned tenant id", () => {
            expect(identity.tenantId).toBe("a42a2ad2f6b771aceed7f964eb25469a8cd292d7f430a918745d7a5a7822fd8f");
        });

        it("hands out a copy of the public key: writing to it changes neither the key nor what it signs", () => {
            const exposed = identity.publicKey;
            exposed.fill(0);
            expect(bytesToHex(identity.publicKey)).toBe(ROOT_SIGNER_PUBKEY);
            expect(bytesToHex(identity.signRegistration(request()).signature)).toBe(SIGNATURE);
        });
    });

    describe("signRegistration", () => {
        it("signs fiber's signature", () => {
            expect(bytesToHex(identity.signRegistration(request()).signature)).toBe(SIGNATURE);
        });

        it("signs the digest itself, low-S, under the root signer", () => {
            const signature = identity.signRegistration(request()).signature;
            expect(signature).toHaveLength(64);
            expect(secp256k1.verify(signature, hexToBytes(DIGEST), hexToBytes(ROOT_SIGNER_PUBKEY), { prehash: false })).toBe(true);
            expect(secp256k1.verify(signature, hexToBytes(DIGEST), hexToBytes(ROOT_SIGNER_PUBKEY), { prehash: true })).toBe(false);
            expect(secp256k1.Signature.fromBytes(signature).hasHighS()).toBe(false);
        });

        it("returns the params of the registration: its own key, the request id and the signing time", () => {
            const params = identity.signRegistration(request());
            expect(Object.keys(params).sort()).toEqual(["requestId", "rootSignerPubkey", "signature", "signedAtMs"]);
            expect(bytesToHex(params.rootSignerPubkey)).toBe(ROOT_SIGNER_PUBKEY);
            expect(bytesToHex(params.requestId)).toBe(REQUEST_ID);
            expect(params.signedAtMs).toBe(SIGNED_AT_MS);
        });

        it("returns copies: writing to the request afterwards changes none of the params", () => {
            const input = request();
            const params = identity.signRegistration(input);
            expect(params.requestId).not.toBe(input.requestId);
            input.requestId.fill(0);
            input.lspNodeId.fill(0);
            expect(bytesToHex(params.requestId)).toBe(REQUEST_ID);
            expect(bytesToHex(params.signature)).toBe(SIGNATURE);
        });

        it("returns its own key as a copy: writing to the params changes neither the key nor what it signs next", () => {
            identity.signRegistration(request()).rootSignerPubkey.fill(0);
            expect(bytesToHex(identity.publicKey)).toBe(ROOT_SIGNER_PUBKEY);
            expect(bytesToHex(identity.signRegistration(request()).signature)).toBe(SIGNATURE);
        });

        it("copies a request id the host passes as a Node buffer into a plain Uint8Array of its own", () => {
            const requestId = Buffer.from(REQUEST_ID, "hex");
            const params = identity.signRegistration({ ...request(), requestId });
            requestId.fill(0);
            expect(bytesToHex(params.requestId)).toBe(REQUEST_ID);
            expect(Object.getPrototypeOf(params.requestId)).toBe(Uint8Array.prototype);
            expect(bytesToHex(params.signature)).toBe(SIGNATURE);
        });

        it("hands back the request id it signed, read from its bytes once", () => {
            // Iterates other bytes than it holds: a copy taken through the iterator would differ from the bytes signed.
            class IteratingOtherBytes extends Uint8Array {
                override [Symbol.iterator](): ReturnType<Uint8Array[typeof Symbol.iterator]> {
                    return new Uint8Array(32).fill(0x09)[Symbol.iterator]();
                }
            }
            const params = identity.signRegistration({ ...request(), requestId: new IteratingOtherBytes(hexToBytes(REQUEST_ID)) });
            expect(bytesToHex(params.requestId)).toBe(REQUEST_ID);
            expect(bytesToHex(params.signature)).toBe(SIGNATURE);
        });

        it("reads each member of the request once: what it signs is what it hands back", () => {
            const reads: string[] = [];
            const shifting = {
                get lspNodeId(): Uint8Array {
                    reads.push("lspNodeId");
                    return hexToBytes(reads.length > 3 ? OTHER_LSP_NODE_ID : LSP_NODE_ID);
                },
                get requestId(): Uint8Array {
                    reads.push("requestId");
                    return new Uint8Array(32).fill(reads.length > 3 ? 0x09 : 0x03);
                },
                get signedAtMs(): bigint {
                    reads.push("signedAtMs");
                    return reads.length > 3 ? 0n : SIGNED_AT_MS;
                },
            };
            const params = identity.signRegistration(shifting);
            expect(reads).toEqual(["lspNodeId", "requestId", "signedAtMs"]);
            expect(bytesToHex(params.signature)).toBe(SIGNATURE);
            expect(bytesToHex(params.requestId)).toBe(REQUEST_ID);
            expect(params.signedAtMs).toBe(SIGNED_AT_MS);
        });

        it("signs under its own key whatever root signer the request carries, and hands its own key back", () => {
            const params = identity.signRegistration(unchecked({ ...request(), rootSignerPubkey: hexToBytes(OTHER_ROOT_SIGNER_PUBKEY) }));
            expect(bytesToHex(params.signature)).toBe(SIGNATURE);
            expect(bytesToHex(params.rootSignerPubkey)).toBe(ROOT_SIGNER_PUBKEY);
        });

        it("signs another request id with another signature, over the payload naming it", () => {
            const requestId = "09".repeat(32);
            const signature = identity.signRegistration({ ...request(), requestId: hexToBytes(requestId) }).signature;
            expect(bytesToHex(signature)).not.toBe(SIGNATURE);
            expect(signsPayload(signature, PROTOCOL + LSP_NODE_ID + ROOT_SIGNER_PUBKEY + requestId + SIGNED_AT)).toBe(true);
        });

        it("signs another signing time with another signature, over the payload naming it", () => {
            const signature = identity.signRegistration({ ...request(), signedAtMs: SIGNED_AT_MS + 1n }).signature;
            expect(bytesToHex(signature)).not.toBe(SIGNATURE);
            expect(signsPayload(signature, PROTOCOL + LSP_NODE_ID + ROOT_SIGNER_PUBKEY + REQUEST_ID + "0000018bcfe5687c")).toBe(true);
        });

        it("signs for another LSP with another signature, over the payload naming it", () => {
            const signature = identity.signRegistration({ ...request(), lspNodeId: hexToBytes(OTHER_LSP_NODE_ID) }).signature;
            expect(bytesToHex(signature)).not.toBe(SIGNATURE);
            expect(signsPayload(signature, PROTOCOL + OTHER_LSP_NODE_ID + ROOT_SIGNER_PUBKEY + REQUEST_ID + SIGNED_AT)).toBe(true);
        });

        it.each([
            ["0", 0n, "0000000000000000"],
            ["u64's maximum", UINT64_MAX, "ffffffffffffffff"],
        ])("signs a signing time of %s, the bounds of fiber's u64", (_, signedAtMs, written) => {
            const params = identity.signRegistration({ ...request(), signedAtMs });
            expect(params.signedAtMs).toBe(signedAtMs);
            expect(signsPayload(params.signature, PROTOCOL + LSP_NODE_ID + ROOT_SIGNER_PUBKEY + REQUEST_ID + written)).toBe(true);
        });

        describe("refusals", () => {
            it.each([
                ["null", null],
                ["undefined", undefined],
                ["an array", []],
                ["a string", "request"],
            ])("refuses a request that is %s", (_, value) => {
                expect(typeErrorOf(() => identity.signRegistration(unchecked(value)))).toBe("request must be an object");
            });

            it.each([
                ["absent", undefined, "lspNodeId must be a Uint8Array"],
                ["null", null, "lspNodeId must be a Uint8Array"],
                ["in hex", LSP_NODE_ID, "lspNodeId must be a Uint8Array"],
                ["of 32 bytes", hexToBytes(LSP_NODE_ID).slice(0, 32), "lspNodeId must be 33 bytes, got 32"],
                ["of 34 bytes", hexToBytes(`${LSP_NODE_ID}00`), "lspNodeId must be 33 bytes, got 34"],
                ["33 zero bytes, no point's prefix", new Uint8Array(33), "lspNodeId must be a compressed point on secp256k1"],
                [
                    "under an uncompressed prefix",
                    hexToBytes(`04${LSP_NODE_ID.slice(2)}`),
                    "lspNodeId must be a compressed point on secp256k1",
                ],
                ["an x past the field's prime", hexToBytes(`02${"ff".repeat(32)}`), "lspNodeId must be a compressed point on secp256k1"],
            ])("refuses an LSP node id %s", (_, lspNodeId, message) => {
                expect(typeErrorOf(() => identity.signRegistration(unchecked({ ...request(), lspNodeId })))).toBe(message);
            });

            it.each([
                ["absent", undefined, "requestId must be a Uint8Array"],
                ["null", null, "requestId must be a Uint8Array"],
                ["in hex", REQUEST_ID, "requestId must be a Uint8Array"],
                ["of 31 bytes", new Uint8Array(31).fill(0x03), "requestId must be 32 bytes, got 31"],
                ["of 33 bytes", new Uint8Array(33).fill(0x03), "requestId must be 32 bytes, got 33"],
            ])("refuses a request id %s", (_, requestId, message) => {
                expect(typeErrorOf(() => identity.signRegistration(unchecked({ ...request(), requestId })))).toBe(message);
            });

            it.each([
                ["absent", undefined, "undefined"],
                ["null", null, "null"],
                ["a number", 1_700_000_000_123, "1700000000123"],
                ["a number that is no integer", 1_700_000_000_123.5, "1700000000123.5"],
                ["a decimal string", "1700000000123", "1700000000123"],
                ["negative", -1n, "-1"],
                ["past u64's maximum", UINT64_MAX + 1n, "18446744073709551616"],
            ])("refuses a signing time %s", (_, signedAtMs, got) => {
                expect(rangeErrorOf(() => identity.signRegistration(unchecked({ ...request(), signedAtMs })))).toBe(
                    `signedAtMs must be a bigint between 0 and 18446744073709551615, got ${got}`,
                );
            });
        });
    });

    describe("determinism and restore", () => {
        it("gives the same tenant and the same signature from a copy of the seed", () => {
            const restored = new TenantIdentity(Uint8Array.from(MASTER_SEED));
            expect(restored.tenantId).toBe(identity.tenantId);
            expect(bytesToHex(restored.publicKey)).toBe(ROOT_SIGNER_PUBKEY);
            expect(bytesToHex(restored.signRegistration(request()).signature)).toBe(SIGNATURE);
        });

        it("gives another key and another tenant from another seed", () => {
            const other = new TenantIdentity(OTHER_MASTER_SEED);
            expect(bytesToHex(other.publicKey)).toBe(OTHER_ROOT_SIGNER_PUBKEY);
            expect(other.tenantId).toBe("2bfb3edbb410cad1ea91e27bb0eee705749de74cf8a029c4bd24e3a92934448b");
        });

        it("signs the same request under the other seed's own key", () => {
            const params = new TenantIdentity(OTHER_MASTER_SEED).signRegistration(request());
            expect(bytesToHex(params.rootSignerPubkey)).toBe(OTHER_ROOT_SIGNER_PUBKEY);
            const digest = blake2bHashWithSalt(
                hexToBytes(PROTOCOL + LSP_NODE_ID + OTHER_ROOT_SIGNER_PUBKEY + REQUEST_ID + SIGNED_AT),
                new Uint8Array(0),
            );
            expect(secp256k1.verify(params.signature, digest, hexToBytes(OTHER_ROOT_SIGNER_PUBKEY), { prehash: false })).toBe(true);
        });
    });

    describe("the secret", () => {
        it("is no own property of the identity, enumerable or not", () => {
            expect(Object.keys(identity)).toEqual([]);
            expect(Object.getOwnPropertyNames(identity)).toEqual([]);
            expect(Object.getOwnPropertySymbols(identity)).toEqual([]);
        });

        it("is in no serialization of the identity or of what it signs", () => {
            expect(JSON.stringify(identity)).toBe("{}");
            const params = identity.signRegistration(request());
            const forms = [
                JSON.stringify({ ...identity }),
                String(identity),
                identity.tenantId,
                bytesToHex(params.rootSignerPubkey),
                bytesToHex(params.requestId),
                params.signedAtMs.toString(16),
                bytesToHex(params.signature),
            ];
            for (const form of forms) expect(form).not.toContain(WALLET_IDENTITY_KEY);
        });
    });

    describe("seed guards", () => {
        it.each([
            ["31 bytes", new Uint8Array(31).fill(0x24), "masterSeed must be 32 bytes, got 31"],
            ["33 bytes", new Uint8Array(33).fill(0x24), "masterSeed must be 32 bytes, got 33"],
            ["hex instead of bytes", "24".repeat(32), "masterSeed must be a Uint8Array"],
            ["absent", undefined, "masterSeed must be a Uint8Array"],
            ["null", null, "masterSeed must be a Uint8Array"],
        ])("refuses a master seed that is %s", (_, value, message) => {
            expect(typeErrorOf(() => new TenantIdentity(value as Uint8Array))).toBe(message);
        });
    });
});

describe("deriveTenantId", () => {
    it("gives the tenant id of the identity built over the same seed", () => {
        expect(deriveTenantId(MASTER_SEED)).toBe(new TenantIdentity(MASTER_SEED).tenantId);
        expect(deriveTenantId(OTHER_MASTER_SEED)).toBe(new TenantIdentity(OTHER_MASTER_SEED).tenantId);
    });

    it("gives the pinned tenant ids, one per seed", () => {
        expect(deriveTenantId(MASTER_SEED)).toBe("a42a2ad2f6b771aceed7f964eb25469a8cd292d7f430a918745d7a5a7822fd8f");
        expect(deriveTenantId(OTHER_MASTER_SEED)).toBe("2bfb3edbb410cad1ea91e27bb0eee705749de74cf8a029c4bd24e3a92934448b");
    });

    it("gives fiber's tenant id for the vector's master seed", () => {
        const vectors = loadInteropVectors();
        expect(deriveTenantId(hexToBytes(vectors.sdk_scheme.master_seed))).toBe(vectors.tenant_registry.tenant_id);
    });

    it("leaves the seed it was given as it was", () => {
        const seed = MASTER_SEED.slice();
        deriveTenantId(seed);
        expect(seed).toEqual(MASTER_SEED);
    });

    it.each([
        ["31 bytes", new Uint8Array(31).fill(0x24), "masterSeed must be 32 bytes, got 31"],
        ["33 bytes", new Uint8Array(33).fill(0x24), "masterSeed must be 32 bytes, got 33"],
        ["hex instead of bytes", "24".repeat(32), "masterSeed must be a Uint8Array"],
        ["absent", undefined, "masterSeed must be a Uint8Array"],
        ["null", null, "masterSeed must be a Uint8Array"],
    ])("refuses a master seed that is %s", (_, value, message) => {
        expect(typeErrorOf(() => deriveTenantId(value as Uint8Array))).toBe(message);
    });
});

describe("against fiber's tenant registry vector", () => {
    const vectors = loadInteropVectors();
    const vector = vectors.tenant_registry;
    const identity = new TenantIdentity(hexToBytes(vectors.sdk_scheme.master_seed));
    const vectorRequest = (): RegistrationRequest => ({
        lspNodeId: hexToBytes(vector.lsp_node_id),
        requestId: hexToBytes(vector.request_id),
        signedAtMs: BigInt(vector.signed_at),
    });

    it("takes the root signer from the device scheme's wallet identity key", () => {
        expect(vector.root_signer_secret_from).toBe("sdk_scheme.wallet_identity_key");
        expect(vector.root_signer_pubkey).toBe(
            bytesToHex(secp256k1.getPublicKey(hexToBytes(vectors.sdk_scheme.wallet_identity_key), true)),
        );
        expect(vector.lsp_node_id).toBe(bytesToHex(secp256k1.getPublicKey(hexToBytes(vector.lsp_node_secret), true)));
    });

    it("derives fiber's root signer public key and tenant id from the master seed", () => {
        expect(bytesToHex(identity.publicKey)).toBe(vector.root_signer_pubkey);
        expect(identity.tenantId).toBe(vector.tenant_id);
    });

    it("builds fiber's canonical payload and digest", () => {
        const vectorPayload = { ...vectorRequest(), rootSignerPubkey: hexToBytes(vector.root_signer_pubkey) };
        expect(bytesToHex(buildTenantRegistryPayload(vectorPayload))).toBe(vector.payload);
        expect(bytesToHex(computeTenantRegistryDigest(vectorPayload))).toBe(vector.digest);
    });

    it("signs fiber's signature byte for byte", () => {
        const params = identity.signRegistration(vectorRequest());
        expect(bytesToHex(params.signature)).toBe(vector.signature);
        expect(bytesToHex(params.rootSignerPubkey)).toBe(vector.root_signer_pubkey);
        expect(bytesToHex(params.requestId)).toBe(vector.request_id);
        expect(params.signedAtMs).toBe(BigInt(vector.signed_at));
    });

    it("signs what fiber's verifier accepts: the digest itself under the root signer", () => {
        const signature = hexToBytes(vector.signature);
        expect(secp256k1.verify(signature, hexToBytes(vector.digest), hexToBytes(vector.root_signer_pubkey), { prehash: false })).toBe(
            true,
        );
    });
});

describe("computeTenantId", () => {
    const vectors = loadInteropVectors();
    const vector = vectors.tenant_registry;

    it("gives fiber's tenant id for the vector's root signer", () => {
        expect(computeTenantId(hexToBytes(vector.root_signer_pubkey))).toBe(vector.tenant_id);
    });

    it("gives the id of the identity, and of deriveTenantId, over the vector's seed", () => {
        const seed = hexToBytes(vectors.sdk_scheme.master_seed);
        const id = computeTenantId(hexToBytes(vector.root_signer_pubkey));
        expect(new TenantIdentity(seed).tenantId).toBe(id);
        expect(deriveTenantId(seed)).toBe(id);
    });

    it("gives the pinned tenant id of each seed's root signer", () => {
        expect(computeTenantId(hexToBytes(ROOT_SIGNER_PUBKEY))).toBe("a42a2ad2f6b771aceed7f964eb25469a8cd292d7f430a918745d7a5a7822fd8f");
        expect(computeTenantId(hexToBytes(OTHER_ROOT_SIGNER_PUBKEY))).toBe(
            "2bfb3edbb410cad1ea91e27bb0eee705749de74cf8a029c4bd24e3a92934448b",
        );
    });

    it("leaves the key as it was, and hashes the bytes it holds at each call", () => {
        const key = hexToBytes(ROOT_SIGNER_PUBKEY);
        const id = computeTenantId(key);
        expect(bytesToHex(key)).toBe(ROOT_SIGNER_PUBKEY);
        // The same x under the other parity: still a point, another key.
        key[0] = 0x02;
        const other = computeTenantId(key);
        expect(other).not.toBe(id);
        expect(other).toBe(bytesToHex(blake2bHashWithSalt(key, utf8ToBytes(TENANT_ID_DOMAIN))));
        expect(id).toBe("a42a2ad2f6b771aceed7f964eb25469a8cd292d7f430a918745d7a5a7822fd8f");
    });

    it.each([
        ["absent", undefined, "rootSignerPubkey must be a Uint8Array"],
        ["null", null, "rootSignerPubkey must be a Uint8Array"],
        ["in hex", ROOT_SIGNER_PUBKEY, "rootSignerPubkey must be a Uint8Array"],
        ["an array of bytes", Array.from(hexToBytes(ROOT_SIGNER_PUBKEY)), "rootSignerPubkey must be a Uint8Array"],
        ["of 32 bytes", hexToBytes(ROOT_SIGNER_PUBKEY).slice(0, 32), "rootSignerPubkey must be 33 bytes, got 32"],
        ["of 34 bytes", hexToBytes(`${ROOT_SIGNER_PUBKEY}00`), "rootSignerPubkey must be 33 bytes, got 34"],
        ["33 zero bytes, no point's prefix", new Uint8Array(33), "rootSignerPubkey must be a compressed point on secp256k1"],
        [
            "under an uncompressed prefix",
            hexToBytes(`04${ROOT_SIGNER_PUBKEY.slice(2)}`),
            "rootSignerPubkey must be a compressed point on secp256k1",
        ],
        ["an x past the field's prime", hexToBytes(`02${"ff".repeat(32)}`), "rootSignerPubkey must be a compressed point on secp256k1"],
    ])("refuses a root signer %s", (_, rootSignerPubkey, message) => {
        expect(typeErrorOf(() => computeTenantId(rootSignerPubkey as Uint8Array))).toBe(message);
    });
});

describe("the registration window", () => {
    it("is fiber's: five minutes behind, thirty seconds ahead", () => {
        expect(TENANT_REGISTRY_MAX_SIGNED_AT_AGE_MS).toBe(300000n);
        expect(TENANT_REGISTRY_MAX_SIGNED_AT_FUTURE_SKEW_MS).toBe(30000n);
    });
});

describe("readTenantRegistration", () => {
    it("hands back the four fields alone, the very values it read", () => {
        const given = {
            rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY),
            requestId: hexToBytes(REQUEST_ID),
            signedAtMs: SIGNED_AT_MS,
            signature: hexToBytes(SIGNATURE),
            tenantId: "a42a2ad2f6b771aceed7f964eb25469a8cd292d7f430a918745d7a5a7822fd8f",
        };
        const read = readTenantRegistration(given);
        expect(Object.keys(read)).toEqual(["rootSignerPubkey", "requestId", "signedAtMs", "signature"]);
        expect(read.rootSignerPubkey).toBe(given.rootSignerPubkey);
        expect(read.requestId).toBe(given.requestId);
        expect(read.signedAtMs).toBe(SIGNED_AT_MS);
        expect(read.signature).toBe(given.signature);
    });
});

describe("verifyTenantRegistration", () => {
    const vectors = loadInteropVectors();
    const vector = vectors.tenant_registry;
    // secp256k1's group order n.
    const ORDER = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    const ORDER_N = BigInt(`0x${ORDER}`);
    const R = vector.signature.slice(0, 64);
    const S = vector.signature.slice(64);

    const lspPubkey = (): Uint8Array => hexToBytes(vector.lsp_node_id);
    const registration = (): RegisterTenantParams => ({
        rootSignerPubkey: hexToBytes(vector.root_signer_pubkey),
        requestId: hexToBytes(vector.request_id),
        signedAtMs: BigInt(vector.signed_at),
        signature: hexToBytes(vector.signature),
    });
    const withSignature = (signature: string): RegisterTenantParams => ({ ...registration(), signature: hexToBytes(signature) });
    const scalar = (value: bigint): string => value.toString(16).padStart(64, "0");
    const isPoint = (bytes: Uint8Array): boolean => {
        try {
            secp256k1.Point.fromBytes(bytes);
            return true;
        } catch {
            return false;
        }
    };
    const flipped = (hex: string, index: number): Uint8Array => hexToBytes(hex).map((byte, at) => (at === index ? byte ^ 0x01 : byte));
    const indices = (length: number): number[] => Array.from({ length }, (_, index) => index);
    const unverified = (value: unknown): RegisterTenantParams => value as RegisterTenantParams;

    it("accepts the vector's registration under its LSP", () => {
        expect(verifyTenantRegistration(lspPubkey(), registration())).toBe(true);
    });

    it("accepts what an identity signs, for any LSP, under its own key", () => {
        const other = new TenantIdentity(OTHER_MASTER_SEED);
        const request = { lspNodeId: hexToBytes(OTHER_LSP_NODE_ID), requestId: hexToBytes(REQUEST_ID), signedAtMs: SIGNED_AT_MS };
        expect(verifyTenantRegistration(hexToBytes(OTHER_LSP_NODE_ID), other.signRegistration(request))).toBe(true);
    });

    it.each([
        ["0", 0n],
        ["u64's maximum", UINT64_MAX],
    ])("accepts a signing time of %s, the bounds of fiber's u64", (_, signedAtMs) => {
        const signed = new TenantIdentity(MASTER_SEED).signRegistration({ ...request(), signedAtMs });
        expect(verifyTenantRegistration(hexToBytes(LSP_NODE_ID), signed)).toBe(true);
    });

    it("accepts keys and bytes the host passes as Node buffers", () => {
        const buffered = {
            rootSignerPubkey: Buffer.from(vector.root_signer_pubkey, "hex"),
            requestId: Buffer.from(vector.request_id, "hex"),
            signedAtMs: BigInt(vector.signed_at),
            signature: Buffer.from(vector.signature, "hex"),
        };
        expect(verifyTenantRegistration(Buffer.from(vector.lsp_node_id, "hex"), buffered)).toBe(true);
    });

    it("accepts the facade's own output, which carries the tenant id beside the registration", () => {
        const output = {
            rootSignerPubkey: hexToBytes(vector.root_signer_pubkey),
            requestId: hexToBytes(vector.request_id),
            signedAtMs: BigInt(vector.signed_at),
            signature: hexToBytes(vector.signature),
            tenantId: vector.tenant_id,
        };
        expect(verifyTenantRegistration(lspPubkey(), output)).toBe(true);
    });

    it("leaves the key and the registration it was given as they were", () => {
        const lsp = lspPubkey();
        const given = registration();
        verifyTenantRegistration(lsp, given);
        expect(bytesToHex(lsp)).toBe(vector.lsp_node_id);
        expect(bytesToHex(given.rootSignerPubkey)).toBe(vector.root_signer_pubkey);
        expect(bytesToHex(given.requestId)).toBe(vector.request_id);
        expect(given.signedAtMs).toBe(BigInt(vector.signed_at));
        expect(bytesToHex(given.signature)).toBe(vector.signature);
    });

    describe("a signature that does not verify", () => {
        it("is the vector's signature under another LSP", () => {
            expect(verifyTenantRegistration(hexToBytes(OTHER_LSP_NODE_ID), registration())).toBe(false);
        });

        it("is the signature of another seed's identity over the same request", () => {
            const other = new TenantIdentity(OTHER_MASTER_SEED).signRegistration({
                lspNodeId: lspPubkey(),
                requestId: hexToBytes(vector.request_id),
                signedAtMs: BigInt(vector.signed_at),
            });
            expect(verifyTenantRegistration(lspPubkey(), { ...registration(), signature: other.signature })).toBe(false);
        });

        it("is the vector's signature claimed by another seed's root signer", () => {
            const claimed = { ...registration(), rootSignerPubkey: hexToBytes(OTHER_ROOT_SIGNER_PUBKEY) };
            expect(verifyTenantRegistration(lspPubkey(), claimed)).toBe(false);
        });

        it("is any byte of the request id altered", () => {
            const verified = indices(32).filter((index) =>
                verifyTenantRegistration(lspPubkey(), { ...registration(), requestId: flipped(vector.request_id, index) }),
            );
            expect(verified).toEqual([]);
        });

        it("is any of the eight bytes of the signing time altered", () => {
            const signedAtMs = BigInt(vector.signed_at);
            const verified = indices(8).filter((index) => {
                const altered = signedAtMs ^ (0xffn << BigInt(8 * (7 - index)));
                const written = buildTenantRegistryPayload({
                    lspNodeId: lspPubkey(),
                    rootSignerPubkey: hexToBytes(vector.root_signer_pubkey),
                    requestId: hexToBytes(vector.request_id),
                    signedAtMs: altered,
                }).slice(133);
                const differing = indices(8).filter((at) => written[at] !== hexToBytes(vector.payload.slice(266))[at]);
                expect(differing).toEqual([index]);
                return verifyTenantRegistration(lspPubkey(), { ...registration(), signedAtMs: altered });
            });
            expect(verified).toEqual([]);
        });

        it("is any byte of the signature altered", () => {
            const verified = indices(64).filter((index) =>
                verifyTenantRegistration(lspPubkey(), { ...registration(), signature: flipped(vector.signature, index) }),
            );
            expect(verified).toEqual([]);
        });

        it("is any byte of the LSP's key altered into another point; into no point, it is refused", () => {
            const outcomes = indices(33).map((index) => {
                const altered = flipped(vector.lsp_node_id, index);
                if (!isPoint(altered)) {
                    expect(typeErrorOf(() => verifyTenantRegistration(altered, registration()))).toBe(
                        "lspPubkey must be a compressed point on secp256k1",
                    );
                    return "refused";
                }
                return verifyTenantRegistration(altered, registration()) ? "verified" : "unverified";
            });
            expect(outcomes).not.toContain("verified");
            expect(outcomes).toContain("unverified");
            expect(outcomes).toContain("refused");
        });

        it("is any byte of the root signer altered into another point; into no point, it is refused", () => {
            const outcomes = indices(33).map((index) => {
                const altered = { ...registration(), rootSignerPubkey: flipped(vector.root_signer_pubkey, index) };
                if (!isPoint(altered.rootSignerPubkey)) {
                    expect(typeErrorOf(() => verifyTenantRegistration(lspPubkey(), altered))).toBe(
                        "registration.rootSignerPubkey must be a compressed point on secp256k1",
                    );
                    return "refused";
                }
                return verifyTenantRegistration(lspPubkey(), altered) ? "verified" : "unverified";
            });
            expect(outcomes).not.toContain("verified");
            expect(outcomes).toContain("unverified");
            expect(outcomes).toContain("refused");
        });

        it("is the high-S twin of the vector's signature, which libsecp256k1 does not normalize", () => {
            const highS = scalar(ORDER_N - BigInt(`0x${S}`));
            const digest = hexToBytes(vector.digest);
            const pubkey = hexToBytes(vector.root_signer_pubkey);
            expect(secp256k1.verify(hexToBytes(R + highS), digest, pubkey, { prehash: false, lowS: false, format: "compact" })).toBe(true);
            expect(verifyTenantRegistration(lspPubkey(), withSignature(R + highS))).toBe(false);
            expect(verifyTenantRegistration(lspPubkey(), withSignature(R + scalar(ORDER_N - BigInt(`0x${highS}`))))).toBe(true);
        });

        it.each([
            ["r of zero", () => "00".repeat(32) + S],
            ["s of zero", () => R + "00".repeat(32)],
            ["r of the group order", () => ORDER + S],
            ["s of the group order", () => R + ORDER],
            ["r and s all 0xff", () => "ff".repeat(64)],
        ])("is a signature with %s", (_, signature) => {
            expect(verifyTenantRegistration(lspPubkey(), withSignature(signature()))).toBe(false);
        });
    });

    describe("refusals", () => {
        it.each([
            ["absent", undefined, "lspPubkey must be a Uint8Array"],
            ["null", null, "lspPubkey must be a Uint8Array"],
            ["in hex", LSP_NODE_ID, "lspPubkey must be a Uint8Array"],
            ["of 32 bytes", hexToBytes(LSP_NODE_ID).slice(0, 32), "lspPubkey must be 33 bytes, got 32"],
            ["of 34 bytes", hexToBytes(`${LSP_NODE_ID}00`), "lspPubkey must be 33 bytes, got 34"],
            ["33 zero bytes, no point's prefix", new Uint8Array(33), "lspPubkey must be a compressed point on secp256k1"],
            ["under an uncompressed prefix", hexToBytes(`04${LSP_NODE_ID.slice(2)}`), "lspPubkey must be a compressed point on secp256k1"],
            ["an x past the field's prime", hexToBytes(`02${"ff".repeat(32)}`), "lspPubkey must be a compressed point on secp256k1"],
        ])("refuses an LSP key %s", (_, lsp, message) => {
            expect(typeErrorOf(() => verifyTenantRegistration(lsp as Uint8Array, registration()))).toBe(message);
        });

        it.each([
            ["null", null],
            ["undefined", undefined],
            ["an array", []],
            ["a string", "registration"],
        ])("refuses a registration that is %s", (_, value) => {
            expect(typeErrorOf(() => verifyTenantRegistration(lspPubkey(), unverified(value)))).toBe("registration must be an object");
        });

        it.each([
            ["absent", undefined, "registration.rootSignerPubkey must be a Uint8Array"],
            ["null", null, "registration.rootSignerPubkey must be a Uint8Array"],
            ["in hex", ROOT_SIGNER_PUBKEY, "registration.rootSignerPubkey must be a Uint8Array"],
            ["of 32 bytes", hexToBytes(ROOT_SIGNER_PUBKEY).slice(0, 32), "registration.rootSignerPubkey must be 33 bytes, got 32"],
            ["of 34 bytes", hexToBytes(`${ROOT_SIGNER_PUBKEY}00`), "registration.rootSignerPubkey must be 33 bytes, got 34"],
            [
                "33 zero bytes, no point's prefix",
                new Uint8Array(33),
                "registration.rootSignerPubkey must be a compressed point on secp256k1",
            ],
            [
                "under an uncompressed prefix",
                hexToBytes(`04${ROOT_SIGNER_PUBKEY.slice(2)}`),
                "registration.rootSignerPubkey must be a compressed point on secp256k1",
            ],
            [
                "an x past the field's prime",
                hexToBytes(`02${"ff".repeat(32)}`),
                "registration.rootSignerPubkey must be a compressed point on secp256k1",
            ],
        ])("refuses a root signer %s", (_, rootSignerPubkey, message) => {
            const refused = unverified({ ...registration(), rootSignerPubkey });
            expect(typeErrorOf(() => verifyTenantRegistration(lspPubkey(), refused))).toBe(message);
        });

        it.each([
            ["absent", undefined, "registration.requestId must be a Uint8Array"],
            ["null", null, "registration.requestId must be a Uint8Array"],
            ["in hex", REQUEST_ID, "registration.requestId must be a Uint8Array"],
            ["of 31 bytes", new Uint8Array(31).fill(0x03), "registration.requestId must be 32 bytes, got 31"],
            ["of 33 bytes", new Uint8Array(33).fill(0x03), "registration.requestId must be 32 bytes, got 33"],
        ])("refuses a request id %s", (_, requestId, message) => {
            const refused = unverified({ ...registration(), requestId });
            expect(typeErrorOf(() => verifyTenantRegistration(lspPubkey(), refused))).toBe(message);
        });

        it.each([
            ["absent", undefined, "undefined"],
            ["null", null, "null"],
            ["a number", 1_700_000_000_123, "1700000000123"],
            ["a number that is no integer", 1_700_000_000_123.5, "1700000000123.5"],
            ["a decimal string", "1700000000123", "1700000000123"],
            ["negative", -1n, "-1"],
            ["past u64's maximum", UINT64_MAX + 1n, "18446744073709551616"],
        ])("refuses a signing time %s", (_, signedAtMs, got) => {
            const refused = unverified({ ...registration(), signedAtMs });
            expect(rangeErrorOf(() => verifyTenantRegistration(lspPubkey(), refused))).toBe(
                `registration.signedAtMs must be a bigint between 0 and 18446744073709551615, got ${got}`,
            );
        });

        it.each([
            ["absent", undefined, "registration.signature must be a Uint8Array"],
            ["null", null, "registration.signature must be a Uint8Array"],
            ["in hex", SIGNATURE, "registration.signature must be a Uint8Array"],
            ["of 63 bytes", hexToBytes(SIGNATURE).slice(0, 63), "registration.signature must be 64 bytes, got 63"],
            ["of 65 bytes, a recoverable one", hexToBytes(`${SIGNATURE}01`), "registration.signature must be 64 bytes, got 65"],
        ])("refuses a signature %s", (_, signature, message) => {
            const refused = unverified({ ...registration(), signature });
            expect(typeErrorOf(() => verifyTenantRegistration(lspPubkey(), refused))).toBe(message);
        });
    });

    it("reads each member of the registration once: what it checks is what it verifies", () => {
        const reads: string[] = [];
        const shifting = {
            get rootSignerPubkey(): Uint8Array {
                reads.push("rootSignerPubkey");
                return hexToBytes(reads.length > 4 ? OTHER_ROOT_SIGNER_PUBKEY : vector.root_signer_pubkey);
            },
            get requestId(): Uint8Array {
                reads.push("requestId");
                return reads.length > 4 ? new Uint8Array(31) : hexToBytes(vector.request_id);
            },
            get signedAtMs(): bigint {
                reads.push("signedAtMs");
                return reads.length > 4 ? -1n : BigInt(vector.signed_at);
            },
            get signature(): Uint8Array {
                reads.push("signature");
                return reads.length > 4 ? new Uint8Array(63) : hexToBytes(vector.signature);
            },
        };
        expect(verifyTenantRegistration(lspPubkey(), shifting)).toBe(true);
        expect(reads).toEqual(["rootSignerPubkey", "requestId", "signedAtMs", "signature"]);
    });
});
