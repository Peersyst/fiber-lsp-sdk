import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { MAX_COMMITMENT_NUMBER, deriveChannelKeys, deriveChannelSeed, pubkeyOf } from "../../../src/derivation";
import { getChannelCommitmentPoint, getPublicNonce } from "../../../src/signer/musig2-engine";
import { buildChannelOpenMaterial, buildNextMaterial } from "../../../src/signer/signer-material";
import { signingDeviceKeys } from "../../utils/signing-channel";
import { loadSigningVectors } from "../../utils/signing-vectors";

const vectors = loadSigningVectors();
const KEYS = signingDeviceKeys(vectors);
const SECRETS = [KEYS.fundingKey, KEYS.tlcBaseKey, KEYS.musig2BaseNonce, KEYS.commitmentSeed].map(bytesToHex);

function hexFields(material: object): string[] {
    return Object.values(material).flatMap((value) => (value instanceof Uint8Array ? [bytesToHex(value)] : []));
}

describe("buildChannelOpenMaterial", () => {
    const material = buildChannelOpenMaterial(KEYS);

    it("carries the base public keys the vectors name for the device", () => {
        expect(bytesToHex(material.fundingPubkey)).toBe(vectors.device.funding_pubkey);
        expect(bytesToHex(material.tlcBaseKey)).toBe(vectors.device.tlc_base_pubkey);
    });

    // Fiber installs the block at those numbers, so a nonce published at another one is a nonce the node never uses.
    it("carries the points of numbers 1 and 2 and the nonces of Commitment@0, Commitment@1 and Revocation@2", () => {
        expect(bytesToHex(material.firstCommitmentPoint)).toBe(bytesToHex(getChannelCommitmentPoint(KEYS, 1)));
        expect(bytesToHex(material.secondCommitmentPoint)).toBe(bytesToHex(getChannelCommitmentPoint(KEYS, 2)));
        expect(bytesToHex(material.commitmentNonce)).toBe(bytesToHex(getPublicNonce(KEYS, 0, "COMMITMENT")));
        expect(bytesToHex(material.nextCommitmentNonce)).toBe(bytesToHex(getPublicNonce(KEYS, 1, "COMMITMENT")));
        expect(bytesToHex(material.revocationNonce)).toBe(bytesToHex(getPublicNonce(KEYS, 2, "REVOKE")));
    });

    it("carries no announcement nonce: every channel of the device is private", () => {
        expect(material.channelAnnouncementNonce).toBeNull();
    });

    it("carries seven distinct values, none of them a secret", () => {
        const values = hexFields(material);
        expect(values).toHaveLength(7);
        expect(new Set(values).size).toBe(7);
        for (const value of values) for (const secret of SECRETS) expect(value).not.toContain(secret);
    });

    it("is the channel's own: another index opens with other material", () => {
        const other = deriveChannelKeys(deriveChannelSeed(hexToBytes(vectors.device.master_seed), vectors.device.channel_index + 1));
        expect(bytesToHex(buildChannelOpenMaterial(other).commitmentNonce)).not.toBe(bytesToHex(material.commitmentNonce));
        expect(bytesToHex(buildChannelOpenMaterial(other).fundingPubkey)).toBe(bytesToHex(pubkeyOf(other.fundingKey)));
    });
});

describe("buildNextMaterial", () => {
    // Fiber's expected `next_material` of each request, at the slot's number plus one.
    it.each(vectors.cases.filter((kase) => kase.expected.next_material !== null).map((kase) => [kase.name, kase] as const))(
        "builds the material fiber expects after %s",
        (_, kase) => {
            const status = kase.result.status as { content: { slot: { commitment_number: string } } };
            const material = buildNextMaterial(KEYS, Number(status.content.slot.commitment_number) + 1);
            expect({
                next_commitment_point: bytesToHex(material.nextCommitmentPoint),
                next_commitment_nonce: bytesToHex(material.nextCommitmentNonce),
                next_revocation_nonce: bytesToHex(material.nextRevocationNonce),
            }).toEqual(kase.expected.next_material);
        },
    );

    it("is the point and the two nonces of the number given", () => {
        const material = buildNextMaterial(KEYS, 7);
        expect(bytesToHex(material.nextCommitmentPoint)).toBe(bytesToHex(getChannelCommitmentPoint(KEYS, 7)));
        expect(bytesToHex(material.nextCommitmentNonce)).toBe(bytesToHex(getPublicNonce(KEYS, 7, "COMMITMENT")));
        expect(bytesToHex(material.nextRevocationNonce)).toBe(bytesToHex(getPublicNonce(KEYS, 7, "REVOKE")));
    });

    it("carries three distinct values, none of them a secret", () => {
        const values = hexFields(buildNextMaterial(KEYS, 7));
        expect(new Set(values).size).toBe(3);
        for (const value of values) for (const secret of SECRETS) expect(value).not.toContain(secret);
    });

    it("builds the material of the last derivable number and refuses the one past it", () => {
        expect(buildNextMaterial(KEYS, MAX_COMMITMENT_NUMBER).nextCommitmentNonce).toHaveLength(66);
        expect(() => buildNextMaterial(KEYS, MAX_COMMITMENT_NUMBER + 1)).toThrow(RangeError);
    });
});
