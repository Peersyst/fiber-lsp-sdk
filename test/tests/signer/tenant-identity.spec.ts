import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { blake2bHashWithSalt } from "../../../src/derivation";
import type { GetTenantRegistryNonceResult } from "../../../src/rpc";
import { TenantIdentity, buildTenantRegistryPayload, computeTenantRegistryDigest } from "../../../src/signer/tenant-identity";
import { loadInteropVectors } from "../../utils/interop-vectors";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const OTHER_MASTER_SEED = new Uint8Array(32).fill(0x25);
// `deriveWalletIdentityKey(MASTER_SEED)`, pinned in the device scheme's spec.
const WALLET_IDENTITY_KEY = "fe11dd3161e80f6e20a43106d2b0853ec87d613c87ab0c87f41584c31f091ed1";
const ROOT_SIGNER_PUBKEY = "038dd0502b955500a40aa41114374cdc96ed2c34e85e1473f23ae80cddb0afcb26";
const OTHER_ROOT_SIGNER_PUBKEY = "038abd41e20e2c0b61c0c2acfbbd2146d648f275165c3256d8116ee20c78c1f095";
// `pubkeyOf(0x11 * 32)`.
const LSP_NODE_ID = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const NONCE = "0707070707070707070707070707070707070707070707070707070707070707";
const PAYLOAD =
    "66696265722d686f737465642d6c73702d74656e616e742d72656769737472792f7631" +
    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa" +
    "038dd0502b955500a40aa41114374cdc96ed2c34e85e1473f23ae80cddb0afcb26" +
    "0707070707070707070707070707070707070707070707070707070707070707";
const DIGEST = "572fd8da15a8cc25888ce23d96ec6ea0cef517da56a2881a35f960265d7c37d1";
const SIGNATURE =
    "b4881aa3b40683eaae114c1a490fa4f49b2f439387e85f28f5549445204b2a38" + "6fad4947e36291d35a13afd9da564c52abce97ca40fd2832cc223307c415136f";

function challenge(): GetTenantRegistryNonceResult {
    return { lspNodeId: hexToBytes(LSP_NODE_ID), rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY), nonce: hexToBytes(NONCE) };
}

function unchecked(value: unknown): GetTenantRegistryNonceResult {
    return value as GetTenantRegistryNonceResult;
}

function typeErrorOf(step: () => unknown): string {
    try {
        step();
    } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        return (error as TypeError).message;
    }
    throw new Error("the step did not refuse");
}

describe("buildTenantRegistryPayload", () => {
    it("writes the protocol, the LSP's node id, the root signer and the nonce, in fiber's order", () => {
        expect(bytesToHex(buildTenantRegistryPayload(challenge()))).toBe(PAYLOAD);
    });

    // Only a direct call reaches this: `signRegistration` refuses a foreign key first.
    it("refuses a root signer that is not a point", () => {
        const notPoint = { lspNodeId: hexToBytes(LSP_NODE_ID), rootSignerPubkey: new Uint8Array(33), nonce: hexToBytes(NONCE) };
        expect(typeErrorOf(() => buildTenantRegistryPayload(notPoint))).toBe(
            "challenge.rootSignerPubkey must be a compressed point on secp256k1",
        );
    });

    it("refuses a challenge that is not an object", () => {
        expect(typeErrorOf(() => buildTenantRegistryPayload(unchecked(null)))).toBe("challenge must be an object");
    });
});

describe("computeTenantRegistryDigest", () => {
    it("hashes the payload into the pinned digest", () => {
        expect(bytesToHex(computeTenantRegistryDigest(challenge()))).toBe(DIGEST);
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
            expect(bytesToHex(identity.signRegistration(challenge()).signature)).toBe(SIGNATURE);
        });
    });

    describe("signRegistration", () => {
        it("signs the pinned signature", () => {
            expect(bytesToHex(identity.signRegistration(challenge()).signature)).toBe(SIGNATURE);
        });

        it("signs the digest itself, low-S, under the root signer", () => {
            const signature = identity.signRegistration(challenge()).signature;
            expect(signature).toHaveLength(64);
            expect(secp256k1.verify(signature, hexToBytes(DIGEST), hexToBytes(ROOT_SIGNER_PUBKEY), { prehash: false })).toBe(true);
            expect(secp256k1.verify(signature, hexToBytes(DIGEST), hexToBytes(ROOT_SIGNER_PUBKEY), { prehash: true })).toBe(false);
            expect(secp256k1.Signature.fromBytes(signature).hasHighS()).toBe(false);
        });

        it("returns the params of the registration, the root signer and the nonce as the challenge names them", () => {
            const params = identity.signRegistration(challenge());
            expect(Object.keys(params).sort()).toEqual(["nonce", "rootSignerPubkey", "signature"]);
            expect(bytesToHex(params.rootSignerPubkey)).toBe(ROOT_SIGNER_PUBKEY);
            expect(bytesToHex(params.nonce)).toBe(NONCE);
        });

        it("returns copies: writing to the challenge afterwards changes none of the params", () => {
            const input = challenge();
            const params = identity.signRegistration(input);
            input.rootSignerPubkey.fill(0);
            input.nonce.fill(0);
            expect(bytesToHex(params.rootSignerPubkey)).toBe(ROOT_SIGNER_PUBKEY);
            expect(bytesToHex(params.nonce)).toBe(NONCE);
        });

        it("returns its own key as a copy: writing to the params changes neither the key nor what it signs next", () => {
            identity.signRegistration(challenge()).rootSignerPubkey.fill(0);
            expect(bytesToHex(identity.publicKey)).toBe(ROOT_SIGNER_PUBKEY);
            expect(bytesToHex(identity.signRegistration(challenge()).signature)).toBe(SIGNATURE);
        });

        it("copies a nonce the host passes as a Node buffer into a plain Uint8Array of its own", () => {
            const nonce = Buffer.from(NONCE, "hex");
            const params = identity.signRegistration({ ...challenge(), nonce });
            nonce.fill(0);
            expect(bytesToHex(params.nonce)).toBe(NONCE);
            expect(Object.getPrototypeOf(params.nonce)).toBe(Uint8Array.prototype);
            expect(bytesToHex(params.signature)).toBe(SIGNATURE);
        });

        it("signs another nonce with another signature", () => {
            const signature = identity.signRegistration({ ...challenge(), nonce: new Uint8Array(32).fill(0x08) }).signature;
            expect(bytesToHex(signature)).toBe(
                "ad9f6660fd334ba631562b8fd2a163cb1e2e1dde9a91b34ac4e6e41244fe9594" +
                    "581547b313c159226ca27e36f9fff83e99881511cac0c311867fa472c0fc01cd",
            );
        });

        it("signs another LSP's nonce with another signature", () => {
            const lspNodeId = secp256k1.getPublicKey(new Uint8Array(32).fill(0x12), true);
            expect(bytesToHex(identity.signRegistration({ ...challenge(), lspNodeId }).signature)).not.toBe(SIGNATURE);
        });

        describe("refusals", () => {
            it.each([
                ["null", null],
                ["undefined", undefined],
                ["an array", []],
                ["a string", "challenge"],
            ])("refuses a challenge that is %s", (_, value) => {
                expect(typeErrorOf(() => identity.signRegistration(unchecked(value)))).toBe("challenge must be an object");
            });

            it("refuses a nonce issued to another root signer", () => {
                const foreign = { ...challenge(), rootSignerPubkey: hexToBytes(OTHER_ROOT_SIGNER_PUBKEY) };
                expect(typeErrorOf(() => identity.signRegistration(foreign))).toBe(
                    "challenge.rootSignerPubkey must be this identity's public key: the nonce was issued to another RootSigner",
                );
            });

            it("refuses the root signer's x coordinate under the other parity", () => {
                const flipped = hexToBytes(ROOT_SIGNER_PUBKEY);
                flipped[0] = 0x02;
                expect(typeErrorOf(() => identity.signRegistration({ ...challenge(), rootSignerPubkey: flipped }))).toBe(
                    "challenge.rootSignerPubkey must be this identity's public key: the nonce was issued to another RootSigner",
                );
            });

            it.each([
                [
                    "absent",
                    { lspNodeId: hexToBytes(LSP_NODE_ID), nonce: hexToBytes(NONCE) },
                    "challenge.rootSignerPubkey must be a Uint8Array",
                ],
                [
                    "hex instead of bytes",
                    { lspNodeId: hexToBytes(LSP_NODE_ID), rootSignerPubkey: ROOT_SIGNER_PUBKEY, nonce: hexToBytes(NONCE) },
                    "challenge.rootSignerPubkey must be a Uint8Array",
                ],
                [
                    "32 bytes",
                    {
                        lspNodeId: hexToBytes(LSP_NODE_ID),
                        rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY).slice(0, 32),
                        nonce: hexToBytes(NONCE),
                    },
                    "challenge.rootSignerPubkey must be 33 bytes, got 32",
                ],
                [
                    "34 bytes",
                    {
                        lspNodeId: hexToBytes(LSP_NODE_ID),
                        rootSignerPubkey: hexToBytes(`${ROOT_SIGNER_PUBKEY}00`),
                        nonce: hexToBytes(NONCE),
                    },
                    "challenge.rootSignerPubkey must be 33 bytes, got 34",
                ],
                [
                    "null",
                    { lspNodeId: hexToBytes(LSP_NODE_ID), rootSignerPubkey: null, nonce: hexToBytes(NONCE) },
                    "challenge.rootSignerPubkey must be a Uint8Array",
                ],
            ])("refuses a root signer %s", (_, value, message) => {
                expect(typeErrorOf(() => identity.signRegistration(unchecked(value)))).toBe(message);
            });

            it.each([
                [
                    "absent",
                    { rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY), nonce: hexToBytes(NONCE) },
                    "challenge.lspNodeId must be a Uint8Array",
                ],
                [
                    "hex instead of bytes",
                    { lspNodeId: LSP_NODE_ID, rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY), nonce: hexToBytes(NONCE) },
                    "challenge.lspNodeId must be a Uint8Array",
                ],
                [
                    "32 bytes",
                    {
                        lspNodeId: hexToBytes(LSP_NODE_ID).slice(0, 32),
                        rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY),
                        nonce: hexToBytes(NONCE),
                    },
                    "challenge.lspNodeId must be 33 bytes, got 32",
                ],
                [
                    "34 bytes",
                    {
                        lspNodeId: hexToBytes(`${LSP_NODE_ID}00`),
                        rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY),
                        nonce: hexToBytes(NONCE),
                    },
                    "challenge.lspNodeId must be 33 bytes, got 34",
                ],
                [
                    "33 zero bytes, no point's prefix",
                    { lspNodeId: new Uint8Array(33), rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY), nonce: hexToBytes(NONCE) },
                    "challenge.lspNodeId must be a compressed point on secp256k1",
                ],
                [
                    "an uncompressed prefix",
                    {
                        lspNodeId: hexToBytes(`04${LSP_NODE_ID.slice(2)}`),
                        rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY),
                        nonce: hexToBytes(NONCE),
                    },
                    "challenge.lspNodeId must be a compressed point on secp256k1",
                ],
                [
                    "an x past the field's prime",
                    {
                        lspNodeId: hexToBytes(`02${"ff".repeat(32)}`),
                        rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY),
                        nonce: hexToBytes(NONCE),
                    },
                    "challenge.lspNodeId must be a compressed point on secp256k1",
                ],
                [
                    "null",
                    { lspNodeId: null, rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY), nonce: hexToBytes(NONCE) },
                    "challenge.lspNodeId must be a Uint8Array",
                ],
            ])("refuses an LSP node id %s", (_, value, message) => {
                expect(typeErrorOf(() => identity.signRegistration(unchecked(value)))).toBe(message);
            });

            it.each([
                [
                    "absent",
                    { lspNodeId: hexToBytes(LSP_NODE_ID), rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY) },
                    "challenge.nonce must be a Uint8Array",
                ],
                [
                    "hex instead of bytes",
                    { lspNodeId: hexToBytes(LSP_NODE_ID), rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY), nonce: NONCE },
                    "challenge.nonce must be a Uint8Array",
                ],
                [
                    "31 bytes",
                    {
                        lspNodeId: hexToBytes(LSP_NODE_ID),
                        rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY),
                        nonce: new Uint8Array(31).fill(0x07),
                    },
                    "challenge.nonce must be 32 bytes, got 31",
                ],
                [
                    "33 bytes",
                    {
                        lspNodeId: hexToBytes(LSP_NODE_ID),
                        rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY),
                        nonce: new Uint8Array(33).fill(0x07),
                    },
                    "challenge.nonce must be 32 bytes, got 33",
                ],
                [
                    "null",
                    { lspNodeId: hexToBytes(LSP_NODE_ID), rootSignerPubkey: hexToBytes(ROOT_SIGNER_PUBKEY), nonce: null },
                    "challenge.nonce must be a Uint8Array",
                ],
            ])("refuses a nonce %s", (_, value, message) => {
                expect(typeErrorOf(() => identity.signRegistration(unchecked(value)))).toBe(message);
            });
        });
    });

    describe("determinism and restore", () => {
        it("gives the same tenant and the same signature from a copy of the seed", () => {
            const restored = new TenantIdentity(Uint8Array.from(MASTER_SEED));
            expect(restored.tenantId).toBe(identity.tenantId);
            expect(bytesToHex(restored.publicKey)).toBe(ROOT_SIGNER_PUBKEY);
            expect(bytesToHex(restored.signRegistration(challenge()).signature)).toBe(SIGNATURE);
        });

        it("gives another key and another tenant from another seed", () => {
            const other = new TenantIdentity(OTHER_MASTER_SEED);
            expect(bytesToHex(other.publicKey)).toBe(OTHER_ROOT_SIGNER_PUBKEY);
            expect(other.tenantId).toBe("2bfb3edbb410cad1ea91e27bb0eee705749de74cf8a029c4bd24e3a92934448b");
        });

        it("signs the other seed's own nonce with another signature", () => {
            const other = new TenantIdentity(OTHER_MASTER_SEED);
            const signature = other.signRegistration({ ...challenge(), rootSignerPubkey: hexToBytes(OTHER_ROOT_SIGNER_PUBKEY) }).signature;
            expect(bytesToHex(signature)).not.toBe(SIGNATURE);
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
            const params = identity.signRegistration(challenge());
            const forms = [
                JSON.stringify({ ...identity }),
                String(identity),
                identity.tenantId,
                ...Object.values(params).map((value) => bytesToHex(value)),
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

describe("against fiber's tenant registry vector", () => {
    const vectors = loadInteropVectors();
    const vector = vectors.tenant_registry;
    const identity = new TenantIdentity(hexToBytes(vectors.sdk_scheme.master_seed));
    const vectorChallenge = {
        lspNodeId: hexToBytes(vector.lsp_node_id),
        rootSignerPubkey: hexToBytes(vector.root_signer_pubkey),
        nonce: hexToBytes(vector.nonce),
    };

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
        expect(bytesToHex(buildTenantRegistryPayload(vectorChallenge))).toBe(vector.payload);
        expect(bytesToHex(computeTenantRegistryDigest(vectorChallenge))).toBe(vector.digest);
    });

    it("signs fiber's signature byte for byte", () => {
        const params = identity.signRegistration(vectorChallenge);
        expect(bytesToHex(params.signature)).toBe(vector.signature);
        expect(bytesToHex(params.rootSignerPubkey)).toBe(vector.root_signer_pubkey);
        expect(bytesToHex(params.nonce)).toBe(vector.nonce);
    });

    it("signs what fiber's verifier accepts: the digest itself under the root signer", () => {
        const signature = hexToBytes(vector.signature);
        expect(secp256k1.verify(signature, hexToBytes(vector.digest), hexToBytes(vector.root_signer_pubkey), { prehash: false })).toBe(
            true,
        );
    });
});
