import { hexToBytes } from "@noble/hashes/utils.js";
import type { ChannelPolicyRecord } from "../../../src/policy";
import { CHANNEL_ALIAS_KEY_PREFIX, CHANNEL_RECORD_KEY_PREFIX, PolicyEngine, SignerStore } from "../../../src/policy";
import { SdkError, readSdkChannelEvidence } from "../../../src/sdk";
import { AsyncInMemorySignerStorage, InMemorySignerStorage } from "../../mocks/policy";
import { rejection } from "../../utils/rejection";

const CHANNEL_ID = `0x${"1f".repeat(32)}`;
// The name the open handshake moves the channel to.
const RENAMED_ID = `0x${"3c".repeat(32)}`;
const UNKNOWN_ID = `0x${"5a".repeat(32)}`;
const CHANNEL_INDEX = 3;
const CLOSE_SCRIPT = {
    codeHash: hexToBytes("9bb5d1e0c9f7c6b2a4d3e8f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1"),
    hashType: "type",
    args: hexToBytes("4f2b8e6d1c3a5b7d9f0e2c4a6b8d0f1e3c5a7b9d"),
} as const;

type Harness = { storage: InMemorySignerStorage; store: SignerStore };

async function registered(): Promise<Harness> {
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    await new PolicyEngine(store).registerChannel(CHANNEL_ID, CHANNEL_INDEX, "10000000000", CLOSE_SCRIPT);
    return { storage, store };
}

async function recordOf(h: Harness): Promise<ChannelPolicyRecord> {
    const record = await h.store.getChannelRecord(CHANNEL_INDEX);
    if (record === null) throw new Error("the channel holds no record");
    return record;
}

async function withEvidence(h: Harness): Promise<void> {
    await h.store.updateChannelRecord(CHANNEL_INDEX, (current) => {
        if (current === null) throw new Error("the channel holds no record");
        return {
            ...current,
            revocations: [
                { version: 1, forRemote: true, signature: "a1".repeat(64) },
                { version: 2, forRemote: true, signature: "a2".repeat(64) },
            ],
            commitmentHashes: {
                local: { commitmentNumber: 3, txHash: "c3".repeat(32) },
                remote: { commitmentNumber: 2, txHash: "d2".repeat(32) },
            },
            watchtowerSpends: [
                {
                    requestId: "e1".repeat(32),
                    purpose: { kind: "tlc", commitmentNumber: 3 },
                    view: "local",
                    commitmentNumber: 3,
                    tlcEntry: "ab".repeat(85),
                    txHash: "f1".repeat(32),
                    remainder: null,
                    signature: "51".repeat(65),
                    applied: true,
                },
                {
                    requestId: "e2".repeat(32),
                    purpose: { kind: "settlement" },
                    view: "remote",
                    commitmentNumber: 2,
                    tlcEntry: null,
                    txHash: "f2".repeat(32),
                    remainder: null,
                    signature: null,
                    applied: false,
                },
                {
                    requestId: "e3".repeat(32),
                    purpose: { kind: "settlement" },
                    view: "local",
                    commitmentNumber: 3,
                    tlcEntry: null,
                    txHash: "f3".repeat(32),
                    remainder: null,
                    signature: "53".repeat(65),
                    applied: false,
                },
            ],
        };
    });
}

const EVIDENCE = {
    revocations: [
        { version: 1, forRemote: true, signature: `0x${"a1".repeat(64)}` },
        { version: 2, forRemote: true, signature: `0x${"a2".repeat(64)}` },
    ],
    commitments: {
        local: { commitmentNumber: 3, txHash: `0x${"c3".repeat(32)}` },
        remote: { commitmentNumber: 2, txHash: `0x${"d2".repeat(32)}` },
    },
    watchtowerSignatures: [
        {
            requestId: `0x${"e1".repeat(32)}`,
            purpose: { kind: "tlc", commitmentNumber: 3 },
            signature: `0x${"51".repeat(65)}`,
            applied: true,
        },
        { requestId: `0x${"e3".repeat(32)}`, purpose: { kind: "settlement" }, signature: `0x${"53".repeat(65)}`, applied: false },
    ],
};

describe("readSdkChannelEvidence", () => {
    it("reads a channel that has signed nothing as empty", async () => {
        const h = await registered();
        expect(await readSdkChannelEvidence(h.store, CHANNEL_ID)).toStrictEqual({
            revocations: [],
            commitments: { local: null, remote: null },
            watchtowerSignatures: [],
        });
    });

    it("writes every hash and signature as 0x-prefixed hex, keeping the revocations' order and the claims' order", async () => {
        const h = await registered();
        await withEvidence(h);
        expect(await readSdkChannelEvidence(h.store, CHANNEL_ID)).toStrictEqual(EVIDENCE);
    });

    it("leaves out a spend the device claimed and never signed, and reads no watchtower signature before the first claim", async () => {
        const h = await registered();
        await withEvidence(h);
        await h.store.updateChannelRecord(CHANNEL_INDEX, (current) => {
            if (current === null) throw new Error("the channel holds no record");
            return { ...current, watchtowerSpends: current.watchtowerSpends?.filter((spend) => spend.signature === null) };
        });
        expect((await readSdkChannelEvidence(h.store, CHANNEL_ID)).watchtowerSignatures).toEqual([]);
        await h.store.updateChannelRecord(CHANNEL_INDEX, (current) => {
            if (current === null) throw new Error("the channel holds no record");
            const unclaimed = { ...current };
            delete unclaimed.watchtowerSpends;
            return unclaimed;
        });
        expect((await recordOf(h)).watchtowerSpends).toBeUndefined();
        expect((await readSdkChannelEvidence(h.store, CHANNEL_ID)).watchtowerSignatures).toEqual([]);
    });

    it("reads one view's commitment while the other has none", async () => {
        const h = await registered();
        await h.store.updateChannelRecord(CHANNEL_INDEX, (current) => {
            if (current === null) throw new Error("the channel holds no record");
            return { ...current, commitmentHashes: { remote: { commitmentNumber: 1, txHash: "d1".repeat(32) } } };
        });
        expect((await readSdkChannelEvidence(h.store, CHANNEL_ID)).commitments).toStrictEqual({
            local: null,
            remote: { commitmentNumber: 1, txHash: `0x${"d1".repeat(32)}` },
        });
    });

    it("reads the channel under the name the open handshake gave it and under the one it had before", async () => {
        const h = await registered();
        await withEvidence(h);
        await h.store.claimChannelAlias(RENAMED_ID, CHANNEL_INDEX);
        expect(await readSdkChannelEvidence(h.store, RENAMED_ID)).toStrictEqual(EVIDENCE);
        expect(await readSdkChannelEvidence(h.store, CHANNEL_ID)).toStrictEqual(EVIDENCE);
    });

    it("hands out copies: writing to the evidence changes neither the record nor the next read", async () => {
        const h = await registered();
        await withEvidence(h);
        const before = await recordOf(h);
        const evidence = await readSdkChannelEvidence(h.store, CHANNEL_ID);
        const [revocation] = evidence.revocations;
        const [tlcSpend] = evidence.watchtowerSignatures;
        if (revocation === undefined || tlcSpend?.purpose.kind !== "tlc" || evidence.commitments.local === null) {
            throw new Error("the evidence is not the one written");
        }
        revocation.version = 9;
        evidence.revocations.push({ version: 10, forRemote: false, signature: "0x00" });
        evidence.commitments.local.commitmentNumber = 9;
        evidence.commitments.remote = null;
        tlcSpend.purpose.commitmentNumber = 9;
        tlcSpend.applied = false;
        evidence.watchtowerSignatures.length = 0;
        expect(await recordOf(h)).toEqual(before);
        expect(await readSdkChannelEvidence(h.store, CHANNEL_ID)).toStrictEqual(EVIDENCE);
    });

    it("writes nothing", async () => {
        const h = await registered();
        await withEvidence(h);
        h.storage.ops.length = 0;
        await readSdkChannelEvidence(h.store, CHANNEL_ID);
        expect(h.storage.ops.filter((op) => op.startsWith("set "))).toEqual([]);
    });

    it("refuses a channel this device never registered as unknown_channel", async () => {
        const h = await registered();
        const error = await rejection(readSdkChannelEvidence(h.store, UNKNOWN_ID));
        expect(error).toBeInstanceOf(SdkError);
        expect(error).toMatchObject({ code: "unknown_channel", message: `channel ${UNKNOWN_ID} is not registered on this device` });
    });

    it("refuses a name that resolves to an index holding no record, which only a broken store leaves", async () => {
        const h = await registered();
        await h.store.claimChannelAlias(UNKNOWN_ID, 7);
        await expect(readSdkChannelEvidence(h.store, UNKNOWN_ID)).rejects.toEqual(
            new TypeError(`channel ${UNKNOWN_ID} resolves to channel index 7, which holds no record`),
        );
    });

    it.each([
        [
            "a record it cannot read",
            `${CHANNEL_RECORD_KEY_PREFIX}${CHANNEL_INDEX}`,
            `${CHANNEL_RECORD_KEY_PREFIX}${CHANNEL_INDEX} is not valid JSON`,
        ],
        [
            "a name it cannot read",
            `${CHANNEL_ALIAS_KEY_PREFIX}${CHANNEL_ID}`,
            `${CHANNEL_ALIAS_KEY_PREFIX}${CHANNEL_ID} is not a channel index`,
        ],
    ])("lets the store's error through as it is on %s", async (_, key, message) => {
        const h = await registered();
        h.storage.map.set(key, "garbage");
        await expect(readSdkChannelEvidence(h.store, CHANNEL_ID)).rejects.toEqual(new TypeError(`stored value at ${message}`));
    });

    it("lets a storage that throws through as it is", async () => {
        const h = await registered();
        const failure = new Error("storage unavailable");
        jest.spyOn(h.storage, "get").mockImplementation(() => {
            throw failure;
        });
        await expect(readSdkChannelEvidence(h.store, CHANNEL_ID)).rejects.toBe(failure);
    });

    it("lets an async storage that rejects through as it is", async () => {
        const storage = new AsyncInMemorySignerStorage();
        const store = new SignerStore(storage);
        await new PolicyEngine(store).registerChannel(CHANNEL_ID, CHANNEL_INDEX, "10000000000", CLOSE_SCRIPT);
        const failure = new Error("storage unavailable");
        jest.spyOn(storage, "get").mockRejectedValue(failure);
        await expect(readSdkChannelEvidence(store, CHANNEL_ID)).rejects.toBe(failure);
    });

    it.each([
        ["undefined", undefined],
        ["null", null],
        ["empty", ""],
        ["bare hex", "1f".repeat(32)],
        ["upper-case hex", `0x${"1F".repeat(32)}`],
        ["31 bytes", `0x${"1f".repeat(31)}`],
        ["33 bytes", `0x${"1f".repeat(33)}`],
        ["odd-length hex", `0x${"1f".repeat(32)}0`],
    ])("refuses a channel id that is %s, reading nothing", async (_, channelId) => {
        const h = await registered();
        h.storage.ops.length = 0;
        await expect(readSdkChannelEvidence(h.store, channelId as string)).rejects.toEqual(
            new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
        );
        expect(h.storage.ops).toEqual([]);
    });
});
