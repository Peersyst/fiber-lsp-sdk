import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import type { Transaction } from "../../../src/common";
import type { FiberChannelKeys } from "../../../src/derivation";
import { MAX_COMMITMENT_NUMBER, deriveTlcKey, pubkeyOf } from "../../../src/derivation";
import type { WatchtowerKeyPurpose } from "../../../src/policy";
import type { WatchtowerSigningRequest } from "../../../src/protocol";
import { decodeWatchtowerSigningStatus } from "../../../src/protocol";
import { signOnchain } from "../../../src/signer";
import { signingDeviceKeys } from "../../utils/signing-channel";
import type { SigningWatchtowerSpendVector } from "../../utils/signing-vectors";
import { loadSigningVectors, watchtowerSpendOf, watchtowerStatusField } from "../../utils/signing-vectors";

const vectors = loadSigningVectors();
const KEYS = signingDeviceKeys(vectors);
const DEVICE_SPENDS = vectors.watchtower.views.flatMap((view) => view.spends);
const INBOUND_TLC = "peer's commitment: inbound TLC by preimage";

function requestOf(spend: SigningWatchtowerSpendVector): WatchtowerSigningRequest {
    const status = decodeWatchtowerSigningStatus(watchtowerStatusField(spend));
    if (status.kind !== "required") throw new Error(`${spend.name} decodes to no request`);
    return status;
}

// Under fiber's order: `r`, `s`, then the recovery id.
function recoveredKeyOf(signature: Uint8Array, message: Uint8Array): string {
    const recovered = concatBytes(signature.subarray(64), signature.subarray(0, 64));
    return bytesToHex(secp256k1.recoverPublicKey(recovered, message, { prehash: false }));
}

describe("signOnchain", () => {
    describe("fiber's spends", () => {
        it.each(DEVICE_SPENDS.map((spend) => [spend.name, spend] as const))("signs %s to fiber's bytes", (_, spend) => {
            const { purpose, transaction } = requestOf(spend);
            expect(`0x${bytesToHex(signOnchain(KEYS, purpose, transaction))}`).toBe(spend.signature);
        });

        it.each(DEVICE_SPENDS.map((spend) => [spend.name, spend] as const))(
            "signs %s under the key fiber names, over fiber's message",
            (_, spend) => {
                const { purpose, transaction } = requestOf(spend);
                const key = purpose.kind === "settlement" ? KEYS.tlcBaseKey : deriveTlcKey(KEYS, purpose.commitmentNumber);
                const recovered = recoveredKeyOf(signOnchain(KEYS, purpose, transaction), hexToBytes(spend.message.slice(2)));
                expect(`0x${recovered}`).toBe(spend.signer_pubkey);
                expect(recovered).toBe(bytesToHex(pubkeyOf(key)));
            },
        );

        it("signs the settlement under the TLC base key", () => {
            const spend = watchtowerSpendOf(vectors, "peer's commitment: settlement");
            const { purpose, transaction } = requestOf(spend);
            expect(purpose).toEqual({ kind: "settlement" });
            const signature = signOnchain(KEYS, purpose, transaction);
            expect(recoveredKeyOf(signature, hexToBytes(spend.message.slice(2)))).toBe(vectors.device.tlc_base_pubkey);
        });

        it("signs a TLC under the key of another commitment number when the purpose names it", () => {
            const spend = watchtowerSpendOf(vectors, INBOUND_TLC);
            const { transaction } = requestOf(spend);
            const signature = signOnchain(KEYS, { kind: "tlc", commitmentNumber: 5 }, transaction);
            expect(`0x${bytesToHex(signature)}`).not.toBe(spend.signature);
            expect(recoveredKeyOf(signature, hexToBytes(spend.message.slice(2)))).toBe(bytesToHex(pubkeyOf(deriveTlcKey(KEYS, 5))));
            expect(`0x${bytesToHex(pubkeyOf(deriveTlcKey(KEYS, 5)))}`).not.toBe(spend.signer_pubkey);
        });
    });

    // Pinned from an independent RFC 6979 signer: low-S, the recovery id last, over the message with the cell deps emptied.
    describe("a literal spend", () => {
        const LITERAL_KEYS: FiberChannelKeys = {
            fundingKey: new Uint8Array(32).fill(0x11),
            tlcBaseKey: new Uint8Array(32).fill(0x22),
            musig2BaseNonce: new Uint8Array(32).fill(0x33),
            commitmentSeed: new Uint8Array(32).fill(0x44),
        };
        const LITERAL_TX: Transaction = {
            version: 0,
            cellDeps: [{ outPoint: { txHash: new Uint8Array(32).fill(0xdd), index: 1 }, depType: "dep_group" }],
            headerDeps: [],
            inputs: [{ since: 0n, previousOutput: { txHash: new Uint8Array(32).fill(0xaa), index: 0 } }],
            outputs: [
                {
                    capacityShannons: 10_000_000_000n,
                    lock: { codeHash: new Uint8Array(32).fill(0xbb), hashType: "type", args: new Uint8Array(20).fill(0xcc) },
                    type: null,
                },
            ],
            outputsData: [new Uint8Array(0)],
            witnesses: [new Uint8Array(4).fill(0xee)],
        };
        const LITERAL_SIGNATURE =
            "4ffcf354800926cb35fd765fd3777b3247143cbfcd208583aea25490014eea78" +
            "42affea2790959bc83296ca6b433daf0a38db4cc7a3db3aba7e9f1756f0a5de5" +
            "00";
        const LITERAL_MESSAGE = hexToBytes("7183511c30ffbdd7c3c73507c71616b6eee7071354d7c104675c256019d2002e");

        it("signs it to the pinned bytes", () => {
            expect(bytesToHex(signOnchain(LITERAL_KEYS, { kind: "settlement" }, LITERAL_TX))).toBe(LITERAL_SIGNATURE);
        });

        it("signs it under the pinned key", () => {
            const signature = signOnchain(LITERAL_KEYS, { kind: "settlement" }, LITERAL_TX);
            expect(recoveredKeyOf(signature, LITERAL_MESSAGE)).toBe("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27");
        });

        it("hands each call bytes of its own", () => {
            const first = signOnchain(LITERAL_KEYS, { kind: "settlement" }, LITERAL_TX);
            first.fill(0);
            expect(bytesToHex(signOnchain(LITERAL_KEYS, { kind: "settlement" }, LITERAL_TX))).toBe(LITERAL_SIGNATURE);
        });
    });

    describe("the purpose", () => {
        const { transaction } = requestOf(watchtowerSpendOf(vectors, INBOUND_TLC));

        it.each([0, MAX_COMMITMENT_NUMBER])("signs under the TLC key of commitment number %i", (commitmentNumber) => {
            const spend = watchtowerSpendOf(vectors, INBOUND_TLC);
            const signature = signOnchain(KEYS, { kind: "tlc", commitmentNumber }, transaction);
            expect(recoveredKeyOf(signature, hexToBytes(spend.message.slice(2)))).toBe(
                bytesToHex(pubkeyOf(deriveTlcKey(KEYS, commitmentNumber))),
            );
        });

        it.each<[string, unknown]>([
            ["null", null],
            ["absent", undefined],
            ["a string", "settlement"],
            ["a list", [{ kind: "settlement" }]],
        ])("refuses a purpose that is %s", (_, purpose) => {
            expect(() => signOnchain(KEYS, purpose as WatchtowerKeyPurpose, transaction)).toThrow(
                new TypeError("purpose must be an object"),
            );
        });

        it.each<[string, unknown]>([
            ["absent", undefined],
            ["another key's", "funding"],
            ["of another case", "Settlement"],
        ])("refuses a kind that is %s", (_, kind) => {
            expect(() => signOnchain(KEYS, { kind } as unknown as WatchtowerKeyPurpose, transaction)).toThrow(
                new TypeError("purpose.kind must be settlement or tlc"),
            );
        });

        it.each<[string, unknown]>([
            ["absent", undefined],
            ["negative", -1],
            ["fractional", 5.5],
            ["above the chain's bound", MAX_COMMITMENT_NUMBER + 1],
            ["a string", "5"],
        ])("refuses a TLC's commitment number that is %s", (_, commitmentNumber) => {
            const purpose = { kind: "tlc", commitmentNumber } as unknown as WatchtowerKeyPurpose;
            expect(() => signOnchain(KEYS, purpose, transaction)).toThrow(
                new RangeError(
                    `purpose.commitmentNumber must be an integer between 0 and ${MAX_COMMITMENT_NUMBER}, got ${commitmentNumber}`,
                ),
            );
        });
    });

    it("refuses a transaction it cannot serialize", () => {
        const { transaction } = requestOf(watchtowerSpendOf(vectors, INBOUND_TLC));
        expect(() => signOnchain(KEYS, { kind: "settlement" }, { ...transaction, version: -1 })).toThrow(
            new RangeError("transaction.version must be an integer between 0 and 4294967295, got -1"),
        );
    });
});
