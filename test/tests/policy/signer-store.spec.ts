import type { ChannelPolicyRecord, IAsyncSignerStorage, ISignerStorage } from "../../../src/policy/index.js";
import { SignerStore } from "../../../src/policy/index.js";
import { AsyncMemorySignerStorage, MemorySignerStorage } from "../../utils/memory-storage.js";

const CHANNEL_ID = "0x1f".padEnd(66, "a");
const CHANNEL_KEY = `fiber-lsp-sdk:channel:${CHANNEL_ID}`;
const PAYMENT_HASH = "11".repeat(32);
const PREIMAGE_KEY = `fiber-lsp-sdk:preimage:${PAYMENT_HASH}`;
const PREIMAGE = "22".repeat(32);

function record(overrides: Partial<ChannelPolicyRecord> = {}): ChannelPolicyRecord {
    return {
        version: 1,
        channelIndex: 3,
        lastSignedCommitmentNumbers: { COMMITMENT: 5, REVOKE: 4 },
        signedDigests: { "COMMITMENT:5": "ab".repeat(32) },
        lastStateVersion: 7,
        localBalanceShannons: "5000000000",
        pendingDebitsShannons: ["100"],
        ...overrides,
    };
}

function requireRecord(current: ChannelPolicyRecord | null): ChannelPolicyRecord {
    if (current === null) throw new Error("unknown channel");
    return current;
}

function bumpStateVersion(current: ChannelPolicyRecord | null): ChannelPolicyRecord {
    const existing = requireRecord(current);
    return { ...existing, lastStateVersion: existing.lastStateVersion + 1 };
}

describe("channel records", () => {
    it("round-trips a record through a synchronous storage", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        await store.setChannelRecord(CHANNEL_ID, record());
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toEqual(record());
    });

    it("round-trips a record through an asynchronous storage", async () => {
        const store = new SignerStore(new AsyncMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_ID, record());
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toEqual(record());
    });

    it("returns null for a channel that was never written", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toBeNull();
    });

    // An untyped host may return undefined instead of null.
    it("reads a storage returning undefined as a missing record", async () => {
        const storage = { get: () => undefined, set: () => undefined } as unknown as ISignerStorage;
        const store = new SignerStore(storage);
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toBeNull();
    });

    it("namespaces the record key", async () => {
        const storage = new MemorySignerStorage();
        await new SignerStore(storage).setChannelRecord(CHANNEL_ID, record());
        expect([...storage.map.keys()]).toEqual([CHANNEL_KEY]);
    });

    it("keeps two channels in separate records", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        await store.setChannelRecord("channel-a", record({ channelIndex: 0 }));
        await store.setChannelRecord("channel-b", record({ channelIndex: 1 }));
        await expect(store.getChannelRecord("channel-a")).resolves.toMatchObject({ channelIndex: 0 });
        await expect(store.getChannelRecord("channel-b")).resolves.toMatchObject({ channelIndex: 1 });
    });

    it.each([
        ["get", (store: SignerStore) => store.getChannelRecord("")] as const,
        ["set", (store: SignerStore) => store.setChannelRecord("", record())] as const,
    ])("rejects an empty channelId on %s", async (_, call) => {
        const store = new SignerStore(new MemorySignerStorage());
        await expect(call(store)).rejects.toThrow(new TypeError("channelId must be a non-empty string"));
    });

    it("refuses to write a record with the wrong shape", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        const corrupt = record({ localBalanceShannons: "-1" });
        await expect(store.setChannelRecord(CHANNEL_ID, corrupt)).rejects.toThrow(
            new TypeError("record is not a valid channel policy record"),
        );
    });

    // Corruption must never read as absence: it would re-open sign-once slots.
    it("throws on a stored value that is not valid JSON", async () => {
        const storage = new MemorySignerStorage();
        storage.map.set(CHANNEL_KEY, "{not json");
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_ID)).rejects.toThrow(
            new TypeError(`stored value at ${CHANNEL_KEY} is not valid JSON`),
        );
    });

    it("throws on a stored record with the wrong shape", async () => {
        const storage = new MemorySignerStorage();
        storage.map.set(CHANNEL_KEY, JSON.stringify(record({ channelIndex: -1 })));
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_ID)).rejects.toThrow(
            new TypeError(`stored value at ${CHANNEL_KEY} is not a channel policy record`),
        );
    });

    it("throws on a stored record from a future format version", async () => {
        const storage = new MemorySignerStorage();
        storage.map.set(CHANNEL_KEY, JSON.stringify({ ...record(), version: 2 }));
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_ID)).rejects.toThrow(TypeError);
    });

    it("tolerates unknown extra fields in a stored record", async () => {
        const storage = new MemorySignerStorage();
        storage.map.set(CHANNEL_KEY, JSON.stringify({ ...record(), futureField: true }));
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_ID)).resolves.toMatchObject(record());
    });

    // Hand-written v1 payload: must parse forever. Never update it to pass; a failure means the format needs a new version.
    it("reads a v1 record written by any past version of the SDK", async () => {
        const v1Json =
            '{"pendingDebitsShannons":["250000000"],"localBalanceShannons":"123456789","lastStateVersion":42,' +
            '"signedDigests":{"REVOKE:9":"' +
            "cd".repeat(32) +
            '","COMMITMENT:10":"' +
            "ef".repeat(32) +
            '"},"lastSignedCommitmentNumbers":{"REVOKE":9,"COMMITMENT":10},"channelIndex":2,"version":1}';
        const storage = new MemorySignerStorage();
        storage.map.set(CHANNEL_KEY, v1Json);
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_ID)).resolves.toEqual({
            version: 1,
            channelIndex: 2,
            lastSignedCommitmentNumbers: { COMMITMENT: 10, REVOKE: 9 },
            signedDigests: { "COMMITMENT:10": "ef".repeat(32), "REVOKE:9": "cd".repeat(32) },
            lastStateVersion: 42,
            localBalanceShannons: "123456789",
            pendingDebitsShannons: ["250000000"],
        });
    });

    it("round-trips a record at every boundary at once", async () => {
        const boundary = record({
            channelIndex: Number.MAX_SAFE_INTEGER,
            lastSignedCommitmentNumbers: { COMMITMENT: 2 ** 48 - 1, REVOKE: 2 ** 48 - 1, CLOSE: 0, ANNOUNCEMENT: 0 },
            signedDigests: {
                [`COMMITMENT:${2 ** 48 - 1}`]: "ff".repeat(32),
                "REVOKE:0": "00".repeat(32),
                "CLOSE:0": "0f".repeat(32),
                "ANNOUNCEMENT:0": "f0".repeat(32),
            },
            lastStateVersion: Number.MAX_SAFE_INTEGER,
            localBalanceShannons: "340282366920938463463374607431768211455",
            pendingDebitsShannons: ["0", "340282366920938463463374607431768211455"],
        });
        const store = new SignerStore(new MemorySignerStorage());
        await store.setChannelRecord(CHANNEL_ID, boundary);
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toEqual(boundary);
    });

    it("writes nothing when the record is refused", async () => {
        const storage = new MemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_ID, record());
        await expect(store.setChannelRecord(CHANNEL_ID, record({ localBalanceShannons: "-1" }))).rejects.toThrow(TypeError);
        expect(storage.map.get(CHANNEL_KEY)).toBe(JSON.stringify(record()));
    });

    it("never writes on a read", async () => {
        const writtenKeys: string[] = [];
        const storage: ISignerStorage = {
            get: () => null,
            set: (key) => {
                writtenKeys.push(key);
            },
        };
        await new SignerStore(storage).getChannelRecord(CHANNEL_ID);
        expect(writtenKeys).toEqual([]);
    });

    it("propagates a synchronous storage failure", async () => {
        const storage: ISignerStorage = {
            get: () => {
                throw new Error("storage unavailable");
            },
            set: () => {
                throw new Error("storage unavailable");
            },
        };
        const store = new SignerStore(storage);
        await expect(store.getChannelRecord(CHANNEL_ID)).rejects.toThrow(new Error("storage unavailable"));
        await expect(store.setChannelRecord(CHANNEL_ID, record())).rejects.toThrow(new Error("storage unavailable"));
    });

    it("propagates an asynchronous storage failure", async () => {
        const storage: IAsyncSignerStorage = {
            get: () => Promise.reject(new Error("storage unavailable")),
            set: () => Promise.reject(new Error("storage unavailable")),
        };
        const store = new SignerStore(storage);
        await expect(store.getChannelRecord(CHANNEL_ID)).rejects.toThrow(new Error("storage unavailable"));
        await expect(store.setChannelRecord(CHANNEL_ID, record())).rejects.toThrow(new Error("storage unavailable"));
    });

    it("treats an empty stored string as corruption, not absence", async () => {
        const storage = new MemorySignerStorage();
        storage.map.set(CHANNEL_KEY, "");
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_ID)).rejects.toThrow(
            new TypeError(`stored value at ${CHANNEL_KEY} is not valid JSON`),
        );
    });
});

describe("updateChannelRecord", () => {
    it("reads, updates and writes in one step", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        await store.setChannelRecord(CHANNEL_ID, record({ lastStateVersion: 7 }));
        await expect(store.updateChannelRecord(CHANNEL_ID, bumpStateVersion)).resolves.toEqual(record({ lastStateVersion: 8 }));
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toEqual(record({ lastStateVersion: 8 }));
    });

    it("passes null to the updater for a channel that was never registered", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        const seen: (ChannelPolicyRecord | null)[] = [];
        await store.updateChannelRecord(CHANNEL_ID, (current) => {
            seen.push(current);
            return record();
        });
        expect(seen).toEqual([null]);
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toEqual(record());
    });

    it("writes nothing when the updater refuses", async () => {
        const storage = new MemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_ID, record());
        storage.ops.length = 0;
        await expect(
            store.updateChannelRecord(CHANNEL_ID, () => {
                throw new Error("policy refusal");
            }),
        ).rejects.toThrow(new Error("policy refusal"));
        expect(storage.ops).toEqual([`get ${CHANNEL_KEY}`]);
        expect(storage.map.get(CHANNEL_KEY)).toBe(JSON.stringify(record()));
    });

    it("writes nothing when the updater returns a record with the wrong shape", async () => {
        const storage = new MemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_ID, record());
        storage.ops.length = 0;
        await expect(
            store.updateChannelRecord(CHANNEL_ID, (current) => ({ ...requireRecord(current), localBalanceShannons: "-1" })),
        ).rejects.toThrow(new TypeError("updated record is not a valid channel policy record"));
        expect(storage.ops).toEqual([`get ${CHANNEL_KEY}`]);
        expect(storage.map.get(CHANNEL_KEY)).toBe(JSON.stringify(record()));
    });

    it("refuses to update over a corrupt stored record", async () => {
        const storage = new MemorySignerStorage();
        storage.map.set(CHANNEL_KEY, "{not json");
        await expect(new SignerStore(storage).updateChannelRecord(CHANNEL_ID, () => record())).rejects.toThrow(
            new TypeError(`stored value at ${CHANNEL_KEY} is not valid JSON`),
        );
        expect(storage.map.get(CHANNEL_KEY)).toBe("{not json");
    });

    it("rejects an empty channelId before touching the storage", async () => {
        const storage = new MemorySignerStorage();
        await expect(new SignerStore(storage).updateChannelRecord("", () => record())).rejects.toThrow(
            new TypeError("channelId must be a non-empty string"),
        );
        expect(storage.ops).toEqual([]);
    });

    it("propagates a storage failure", async () => {
        const storage: IAsyncSignerStorage = {
            get: () => Promise.reject(new Error("storage unavailable")),
            set: () => Promise.resolve(),
        };
        await expect(new SignerStore(storage).updateChannelRecord(CHANNEL_ID, () => record())).rejects.toThrow(
            new Error("storage unavailable"),
        );
    });
});

describe("concurrency", () => {
    it("serializes concurrent updates on one channel instead of losing one", async () => {
        const storage = new AsyncMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_ID, record({ lastStateVersion: 0 }));
        storage.ops.length = 0;

        await Promise.all([
            store.updateChannelRecord(CHANNEL_ID, bumpStateVersion),
            store.updateChannelRecord(CHANNEL_ID, bumpStateVersion),
        ]);

        expect(storage.ops).toEqual([`get ${CHANNEL_KEY}`, `set ${CHANNEL_KEY}`, `get ${CHANNEL_KEY}`, `set ${CHANNEL_KEY}`]);
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toMatchObject({ lastStateVersion: 2 });
    });

    it("lets only one of two concurrent claims take a sign-once slot", async () => {
        const store = new SignerStore(new AsyncMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_ID, record({ lastSignedCommitmentNumbers: {}, signedDigests: {} }));
        const claim = (digest: string): Promise<ChannelPolicyRecord> =>
            store.updateChannelRecord(CHANNEL_ID, (current) => {
                const existing = requireRecord(current);
                const taken = existing.signedDigests["COMMITMENT:6"];
                if (taken !== undefined && taken !== digest) throw new Error("slot already signed");
                return { ...existing, signedDigests: { ...existing.signedDigests, "COMMITMENT:6": digest } };
            });

        const outcomes = await Promise.allSettled([claim("aa".repeat(32)), claim("bb".repeat(32))]);

        expect(outcomes.map((outcome) => outcome.status)).toEqual(["fulfilled", "rejected"]);
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toMatchObject({
            signedDigests: { "COMMITMENT:6": "aa".repeat(32) },
        });
    });

    it("serializes an operation that arrives while an earlier one is still queued", async () => {
        const storage = new AsyncMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_ID, record({ lastStateVersion: 0 }));
        storage.ops.length = 0;

        const first = store.updateChannelRecord(CHANNEL_ID, bumpStateVersion);
        const second = store.updateChannelRecord(CHANNEL_ID, bumpStateVersion);
        // Enqueued the instant the first settles, while the second is still in flight.
        const third = first.then(() => store.updateChannelRecord(CHANNEL_ID, bumpStateVersion));
        await Promise.all([first, second, third]);

        expect(storage.ops).toEqual([
            `get ${CHANNEL_KEY}`,
            `set ${CHANNEL_KEY}`,
            `get ${CHANNEL_KEY}`,
            `set ${CHANNEL_KEY}`,
            `get ${CHANNEL_KEY}`,
            `set ${CHANNEL_KEY}`,
        ]);
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toMatchObject({ lastStateVersion: 3 });
    });

    it("does not serialize two channels against each other", async () => {
        const storage = new AsyncMemorySignerStorage();
        const store = new SignerStore(storage);

        await Promise.all([
            store.updateChannelRecord("channel-a", () => record({ channelIndex: 0 })),
            store.updateChannelRecord("channel-b", () => record({ channelIndex: 1 })),
        ]);

        expect(storage.ops).toEqual([
            "get fiber-lsp-sdk:channel:channel-a",
            "get fiber-lsp-sdk:channel:channel-b",
            "set fiber-lsp-sdk:channel:channel-a",
            "set fiber-lsp-sdk:channel:channel-b",
        ]);
    });

    it("keeps a bare write from landing inside an update", async () => {
        const storage = new AsyncMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_ID, record({ lastStateVersion: 1 }));
        storage.ops.length = 0;
        const seen: (ChannelPolicyRecord | null)[] = [];

        const update = store.updateChannelRecord(CHANNEL_ID, (current) => {
            seen.push(current);
            return bumpStateVersion(current);
        });
        const write = store.setChannelRecord(CHANNEL_ID, record({ lastStateVersion: 9 }));
        await Promise.all([update, write]);

        expect(seen).toEqual([record({ lastStateVersion: 1 })]);
        expect(storage.ops).toEqual([`get ${CHANNEL_KEY}`, `set ${CHANNEL_KEY}`, `set ${CHANNEL_KEY}`]);
        await expect(store.getChannelRecord(CHANNEL_ID)).resolves.toMatchObject({ lastStateVersion: 9 });
    });

    it("serves a read issued behind a pending update the updated record", async () => {
        const store = new SignerStore(new AsyncMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_ID, record({ lastStateVersion: 1 }));

        const update = store.updateChannelRecord(CHANNEL_ID, bumpStateVersion);
        const read = store.getChannelRecord(CHANNEL_ID);

        await expect(update).resolves.toMatchObject({ lastStateVersion: 2 });
        await expect(read).resolves.toMatchObject({ lastStateVersion: 2 });
    });

    it("keeps the key usable after an updater refuses", async () => {
        const store = new SignerStore(new AsyncMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_ID, record({ lastStateVersion: 1 }));

        const refused = store.updateChannelRecord(CHANNEL_ID, () => {
            throw new Error("policy refusal");
        });
        const next = store.updateChannelRecord(CHANNEL_ID, bumpStateVersion);

        await expect(refused).rejects.toThrow(new Error("policy refusal"));
        await expect(next).resolves.toMatchObject({ lastStateVersion: 2 });
    });

    it("keeps the key usable after a storage failure", async () => {
        let failNextRead = true;
        const storage: IAsyncSignerStorage = {
            get: async () => {
                if (failNextRead) {
                    failNextRead = false;
                    throw new Error("storage unavailable");
                }
                return JSON.stringify(record({ lastStateVersion: 1 }));
            },
            set: () => Promise.resolve(),
        };
        const store = new SignerStore(storage);

        const failed = store.updateChannelRecord(CHANNEL_ID, bumpStateVersion);
        const next = store.updateChannelRecord(CHANNEL_ID, bumpStateVersion);

        await expect(failed).rejects.toThrow(new Error("storage unavailable"));
        await expect(next).resolves.toMatchObject({ lastStateVersion: 2 });
    });

    it("applies writes on one payment hash in call order, even when the first one is slower", async () => {
        const applied: string[] = [];
        const storage: IAsyncSignerStorage = {
            get: () => Promise.resolve(null),
            set: async (_key, value) => {
                for (let tick = 0; tick < (value === PREIMAGE ? 6 : 1); tick++) await Promise.resolve();
                applied.push(value);
            },
        };
        const store = new SignerStore(storage);

        await Promise.all([
            store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE),
            store.setHoldInvoicePreimage(PAYMENT_HASH, "33".repeat(32)),
        ]);

        expect(applied).toEqual([PREIMAGE, "33".repeat(32)]);
    });

    it("drops a key's lane once nothing is queued behind it", async () => {
        const store = new SignerStore(new AsyncMemorySignerStorage());
        const lanes = (store as unknown as { lanes: Map<string, unknown> }).lanes;

        await Promise.all([
            store.updateChannelRecord(CHANNEL_ID, () => record()),
            store.updateChannelRecord("other-channel", () => record()),
            store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE),
            store.getChannelRecord(CHANNEL_ID),
        ]);
        expect(lanes.size).toBe(0);

        await expect(
            store.updateChannelRecord(CHANNEL_ID, () => {
                throw new Error("policy refusal");
            }),
        ).rejects.toThrow(new Error("policy refusal"));
        expect(lanes.size).toBe(0);
    });

    it("holds one lane per key while operations are queued on it", async () => {
        const store = new SignerStore(new AsyncMemorySignerStorage());
        const lanes = (store as unknown as { lanes: Map<string, unknown> }).lanes;

        const pending = [
            store.updateChannelRecord(CHANNEL_ID, () => record()),
            store.updateChannelRecord(CHANNEL_ID, () => record()),
            store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE),
        ];
        expect([...lanes.keys()].sort()).toEqual([CHANNEL_KEY, PREIMAGE_KEY].sort());

        await Promise.all(pending);
        expect(lanes.size).toBe(0);
    });
});

describe("hold-invoice preimages", () => {
    it("round-trips a preimage through a synchronous storage", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        await store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE);
        await expect(store.getHoldInvoicePreimage(PAYMENT_HASH)).resolves.toBe(PREIMAGE);
    });

    it("round-trips a preimage through an asynchronous storage", async () => {
        const store = new SignerStore(new AsyncMemorySignerStorage());
        await store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE);
        await expect(store.getHoldInvoicePreimage(PAYMENT_HASH)).resolves.toBe(PREIMAGE);
    });

    it("returns null when no preimage is stored", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        await expect(store.getHoldInvoicePreimage(PAYMENT_HASH)).resolves.toBeNull();
    });

    it("namespaces the preimage key by payment hash", async () => {
        const storage = new MemorySignerStorage();
        await new SignerStore(storage).setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE);
        expect([...storage.map.keys()]).toEqual([PREIMAGE_KEY]);
    });

    it.each([
        ["an uppercase hash", "11".repeat(31) + "AB"],
        ["a 0x-prefixed hash", "0x" + "11".repeat(31)],
        ["a short hash", "11".repeat(31)],
        ["a long hash", "11".repeat(33)],
        ["an empty hash", ""],
        ["a non-hex hash", "zz".repeat(32)],
    ])("rejects %s", async (_, badHash) => {
        const store = new SignerStore(new MemorySignerStorage());
        await expect(store.getHoldInvoicePreimage(badHash)).rejects.toThrow(
            new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
        );
        await expect(store.setHoldInvoicePreimage(badHash, PREIMAGE)).rejects.toThrow(
            new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
        );
    });

    it("rejects an invalid preimage on write", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        await expect(store.setHoldInvoicePreimage(PAYMENT_HASH, "33".repeat(16))).rejects.toThrow(
            new TypeError("preimageHex must be 32 bytes of lowercase hex"),
        );
    });

    it("does not echo the rejected preimage in the error", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        const bogus = "AB".repeat(32);
        const error = await store.setHoldInvoicePreimage(PAYMENT_HASH, bogus).catch((cause: unknown) => cause);
        expect(error).toBeInstanceOf(TypeError);
        expect((error as TypeError).message).not.toContain(bogus);
    });

    it("throws on a stored value that is not a preimage", async () => {
        const storage = new MemorySignerStorage();
        storage.map.set(PREIMAGE_KEY, "not-a-preimage");
        await expect(new SignerStore(storage).getHoldInvoicePreimage(PAYMENT_HASH)).rejects.toThrow(
            new TypeError(`stored value at ${PREIMAGE_KEY} is not a preimage`),
        );
    });

    it("overwrites a previously stored preimage", async () => {
        const store = new SignerStore(new MemorySignerStorage());
        await store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE);
        await store.setHoldInvoicePreimage(PAYMENT_HASH, "33".repeat(32));
        await expect(store.getHoldInvoicePreimage(PAYMENT_HASH)).resolves.toBe("33".repeat(32));
    });

    it("treats an empty stored string as corruption, not absence", async () => {
        const storage = new MemorySignerStorage();
        storage.map.set(PREIMAGE_KEY, "");
        await expect(new SignerStore(storage).getHoldInvoicePreimage(PAYMENT_HASH)).rejects.toThrow(
            new TypeError(`stored value at ${PREIMAGE_KEY} is not a preimage`),
        );
    });

    it("keeps preimages and channel records in disjoint keyspaces", async () => {
        const storage = new MemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(PAYMENT_HASH, record());
        await store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE);
        expect([...storage.map.keys()].sort()).toEqual([`fiber-lsp-sdk:channel:${PAYMENT_HASH}`, PREIMAGE_KEY].sort());
        await expect(store.getHoldInvoicePreimage(PAYMENT_HASH)).resolves.toBe(PREIMAGE);
    });
});
