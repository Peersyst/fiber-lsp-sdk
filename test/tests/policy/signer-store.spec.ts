import { AsyncInMemorySignerStorage, InMemorySignerStorage } from "../../mocks/policy";
import type { ChannelPolicyRecord, IAsyncSignerStorage, ISignerStorage } from "../../../src/policy";
import { CHANNEL_INDEX_PROBE_LIMIT, CHANNEL_RECORD_KEY_PREFIX, CHANNEL_WATERMARK_KEY_PREFIX, SignerStore } from "../../../src/policy";

const CHANNEL_ID = "0x1f".padEnd(66, "a");
const CHANNEL_INDEX = 3;
const CHANNEL_KEY = `fiber-lsp-sdk:channel:${CHANNEL_INDEX}`;
const ALIAS_KEY = `fiber-lsp-sdk:alias:${CHANNEL_ID}`;
const PAYMENT_HASH = "11".repeat(32);
const PREIMAGE_KEY = `fiber-lsp-sdk:preimage:${PAYMENT_HASH}`;
const PREIMAGE = "22".repeat(32);
const WATERMARK_KEY = `fiber-lsp-sdk:watermark:${CHANNEL_INDEX}`;
const NEXT_INDEX_KEY = "fiber-lsp-sdk:next-channel-index";

function record(overrides: Partial<ChannelPolicyRecord> = {}): ChannelPolicyRecord {
    return {
        version: 1,
        channelId: CHANNEL_ID,
        lastSignedCommitmentNumbers: { COMMITMENT: 5, REVOKE: 4 },
        signedSessions: { "COMMITMENT:5": "ab".repeat(32) },
        lastStateVersion: 7,
        localExposureShannons: "5000000000",
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

describe("channel aliases", () => {
    it("round-trips an alias through a synchronous storage", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        await expect(store.resolveChannelIndex(CHANNEL_ID)).resolves.toBe(CHANNEL_INDEX);
    });

    it("round-trips an alias through an asynchronous storage", async () => {
        const store = new SignerStore(new AsyncInMemorySignerStorage());
        await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        await expect(store.resolveChannelIndex(CHANNEL_ID)).resolves.toBe(CHANNEL_INDEX);
    });

    it("returns null for a name that was never registered", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await expect(store.resolveChannelIndex(CHANNEL_ID)).resolves.toBeNull();
    });

    it("namespaces the alias key, apart from the record it points at", async () => {
        const storage = new InMemorySignerStorage();
        await new SignerStore(storage).claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        expect([...storage.map.entries()]).toEqual([[ALIAS_KEY, String(CHANNEL_INDEX)]]);
    });

    // The whole point of the alias: fiber renames a channel when the handshake fixes its id.
    it("resolves two names to one index", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await store.claimChannelAlias("temporary-id", CHANNEL_INDEX);
        await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        await expect(store.resolveChannelIndex("temporary-id")).resolves.toBe(CHANNEL_INDEX);
        await expect(store.resolveChannelIndex(CHANNEL_ID)).resolves.toBe(CHANNEL_INDEX);
    });

    it("round-trips the highest index a channel seed derives from", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await store.claimChannelAlias(CHANNEL_ID, Number.MAX_SAFE_INTEGER);
        await expect(store.resolveChannelIndex(CHANNEL_ID)).resolves.toBe(Number.MAX_SAFE_INTEGER);
    });

    it("writes nothing when a name is claimed again for the index it already holds", async () => {
        const storage = new InMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        storage.ops.length = 0;
        await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
    });

    // A name that moved would leave the first record orphaned under the second one's slots.
    it("refuses to move a name to another index", async () => {
        const storage = new InMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        await expect(store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX + 1)).rejects.toThrow(
            new TypeError(`the name at ${ALIAS_KEY} already resolves to channel index ${CHANNEL_INDEX}`),
        );
        expect(storage.map.get(ALIAS_KEY)).toBe(String(CHANNEL_INDEX));
    });

    it("settles a race between two indexes for one name", async () => {
        const storage = new AsyncInMemorySignerStorage();
        const store = new SignerStore(storage);

        const outcomes = await Promise.allSettled([store.claimChannelAlias(CHANNEL_ID, 1), store.claimChannelAlias(CHANNEL_ID, 2)]);

        expect(outcomes.map((outcome) => outcome.status)).toEqual(["fulfilled", "rejected"]);
        expect(storage.map.get(ALIAS_KEY)).toBe("1");
    });

    it("throws on a claim over a corrupt alias", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(ALIAS_KEY, "three");
        await expect(new SignerStore(storage).claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX)).rejects.toThrow(
            new TypeError(`stored value at ${ALIAS_KEY} is not a channel index`),
        );
    });

    it.each([
        ["resolve", (store: SignerStore) => store.resolveChannelIndex("")] as const,
        ["set", (store: SignerStore) => store.claimChannelAlias("", CHANNEL_INDEX)] as const,
    ])("rejects an empty channelId on %s", async (_, call) => {
        const store = new SignerStore(new InMemorySignerStorage());
        await expect(call(store)).rejects.toThrow(new TypeError("channelId must be a non-empty string"));
    });

    it.each([
        ["a negative index", -1],
        ["a fractional index", 1.5],
        ["an index above the safe range", Number.MAX_SAFE_INTEGER + 2],
    ])("rejects %s", async (_, channelIndex) => {
        const store = new SignerStore(new InMemorySignerStorage());
        await expect(store.claimChannelAlias(CHANNEL_ID, channelIndex)).rejects.toThrow(RangeError);
    });

    // Corruption must never read as absence: the channel would re-register with empty sign-once slots.
    it.each([
        ["a non-numeric value", "three"],
        ["a value with leading zeros", "03"],
        ["a negative value", "-1"],
        ["a fractional value", "3.5"],
        ["a value above the safe range", "9007199254740993"],
        ["an empty value", ""],
    ])("throws on a stored alias holding %s", async (_, stored) => {
        const storage = new InMemorySignerStorage();
        storage.map.set(ALIAS_KEY, stored);
        await expect(new SignerStore(storage).resolveChannelIndex(CHANNEL_ID)).rejects.toThrow(
            new TypeError(`stored value at ${ALIAS_KEY} is not a channel index`),
        );
    });

    it("never writes on a resolve", async () => {
        const writtenKeys: string[] = [];
        const storage: ISignerStorage = {
            get: () => null,
            set: (key) => {
                writtenKeys.push(key);
            },
        };
        await new SignerStore(storage).resolveChannelIndex(CHANNEL_ID);
        expect(writtenKeys).toEqual([]);
    });

    it("propagates a storage failure", async () => {
        const storage: IAsyncSignerStorage = {
            get: () => Promise.reject(new Error("storage unavailable")),
            set: () => Promise.reject(new Error("storage unavailable")),
        };
        const store = new SignerStore(storage);
        await expect(store.resolveChannelIndex(CHANNEL_ID)).rejects.toThrow(new Error("storage unavailable"));
        await expect(store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX)).rejects.toThrow(new Error("storage unavailable"));
    });
});

describe("channel records", () => {
    it("round-trips a record through a synchronous storage", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_INDEX, record());
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual(record());
    });

    it("round-trips a record through an asynchronous storage", async () => {
        const store = new SignerStore(new AsyncInMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_INDEX, record());
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual(record());
    });

    it("returns null for an index that was never written", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toBeNull();
    });

    // An untyped host may return undefined instead of null.
    it("reads a storage returning undefined as a missing record", async () => {
        const storage = { get: () => undefined, set: () => undefined } as unknown as ISignerStorage;
        const store = new SignerStore(storage);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toBeNull();
    });

    it("namespaces the record key", async () => {
        const storage = new InMemorySignerStorage();
        await new SignerStore(storage).setChannelRecord(CHANNEL_INDEX, record());
        expect([...storage.map.keys()]).toEqual([CHANNEL_KEY]);
    });

    it("keeps two channels in separate records", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await store.setChannelRecord(0, record({ channelId: "channel-a" }));
        await store.setChannelRecord(1, record({ channelId: "channel-b" }));
        await expect(store.getChannelRecord(0)).resolves.toMatchObject({ channelId: "channel-a" });
        await expect(store.getChannelRecord(1)).resolves.toMatchObject({ channelId: "channel-b" });
    });

    it.each([
        ["get", (store: SignerStore) => store.getChannelRecord(-1)] as const,
        ["set", (store: SignerStore) => store.setChannelRecord(-1, record())] as const,
        ["update", (store: SignerStore) => store.updateChannelRecord(-1, () => record())] as const,
    ])("rejects a negative channel index on %s", async (_, call) => {
        const store = new SignerStore(new InMemorySignerStorage());
        await expect(call(store)).rejects.toThrow(RangeError);
    });

    it("refuses to write a record with the wrong shape", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const corrupt = record({ localExposureShannons: "-1" });
        await expect(store.setChannelRecord(CHANNEL_INDEX, corrupt)).rejects.toThrow(
            new TypeError("record is not a valid channel policy record"),
        );
    });

    // Corruption must never read as absence: it would re-open sign-once slots.
    it("throws on a stored value that is not valid JSON", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(CHANNEL_KEY, "{not json");
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_INDEX)).rejects.toThrow(
            new TypeError(`stored value at ${CHANNEL_KEY} is not valid JSON`),
        );
    });

    it("throws on a stored record with the wrong shape", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(CHANNEL_KEY, JSON.stringify(record({ channelId: "" })));
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_INDEX)).rejects.toThrow(
            new TypeError(`stored value at ${CHANNEL_KEY} is not a channel policy record`),
        );
    });

    it("throws on a stored record from a future format version", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(CHANNEL_KEY, JSON.stringify({ ...record(), version: 2 }));
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_INDEX)).rejects.toThrow(TypeError);
    });

    it("tolerates unknown extra fields in a stored record", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(CHANNEL_KEY, JSON.stringify({ ...record(), futureField: true }));
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject(record());
    });

    // Hand-written v1 payload: must parse forever. Never update it to pass; a failure means the format needs a new version.
    // It was rewritten twice while the version was still unpublished, and no device had written a record either time: the
    // rename of two fields, and the move of the record key from the channel id to the channel index. There is no third.
    it("reads a v1 record written by any past version of the SDK", async () => {
        const v1Json =
            '{"pendingDebitsShannons":["250000000"],"localExposureShannons":"123456789","lastStateVersion":42,' +
            '"signedSessions":{"REVOKE:9":"' +
            "cd".repeat(32) +
            '","COMMITMENT:10":"' +
            "ef".repeat(32) +
            '"},"lastSignedCommitmentNumbers":{"REVOKE":9,"COMMITMENT":10},"channelId":"' +
            CHANNEL_ID +
            '","version":1}';
        const storage = new InMemorySignerStorage();
        storage.map.set(CHANNEL_KEY, v1Json);
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_INDEX)).resolves.toEqual({
            version: 1,
            channelId: CHANNEL_ID,
            lastSignedCommitmentNumbers: { COMMITMENT: 10, REVOKE: 9 },
            signedSessions: { "COMMITMENT:10": "ef".repeat(32), "REVOKE:9": "cd".repeat(32) },
            lastStateVersion: 42,
            localExposureShannons: "123456789",
            pendingDebitsShannons: ["250000000"],
        });
    });

    it("round-trips a record at every boundary at once", async () => {
        const boundary = record({
            lastSignedCommitmentNumbers: { COMMITMENT: 2 ** 48 - 1, REVOKE: 2 ** 48 - 1, CLOSE: 0, ANNOUNCEMENT: 0 },
            signedSessions: {
                [`COMMITMENT:${2 ** 48 - 1}`]: "ff".repeat(32),
                "REVOKE:0": "00".repeat(32),
                "CLOSE:0": "0f".repeat(32),
                "ANNOUNCEMENT:0": "f0".repeat(32),
            },
            lastStateVersion: Number.MAX_SAFE_INTEGER,
            localExposureShannons: "340282366920938463463374607431768211455",
            pendingDebitsShannons: ["0", "340282366920938463463374607431768211455"],
        });
        const store = new SignerStore(new InMemorySignerStorage());
        await store.setChannelRecord(Number.MAX_SAFE_INTEGER, boundary);
        await expect(store.getChannelRecord(Number.MAX_SAFE_INTEGER)).resolves.toEqual(boundary);
    });

    it("writes nothing when the record is refused", async () => {
        const storage = new InMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_INDEX, record());
        await expect(store.setChannelRecord(CHANNEL_INDEX, record({ localExposureShannons: "-1" }))).rejects.toThrow(TypeError);
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
        await new SignerStore(storage).getChannelRecord(CHANNEL_INDEX);
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
        await expect(store.getChannelRecord(CHANNEL_INDEX)).rejects.toThrow(new Error("storage unavailable"));
        await expect(store.setChannelRecord(CHANNEL_INDEX, record())).rejects.toThrow(new Error("storage unavailable"));
    });

    it("propagates an asynchronous storage failure", async () => {
        const storage: IAsyncSignerStorage = {
            get: () => Promise.reject(new Error("storage unavailable")),
            set: () => Promise.reject(new Error("storage unavailable")),
        };
        const store = new SignerStore(storage);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).rejects.toThrow(new Error("storage unavailable"));
        await expect(store.setChannelRecord(CHANNEL_INDEX, record())).rejects.toThrow(new Error("storage unavailable"));
    });

    it("treats an empty stored string as corruption, not absence", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(CHANNEL_KEY, "");
        await expect(new SignerStore(storage).getChannelRecord(CHANNEL_INDEX)).rejects.toThrow(
            new TypeError(`stored value at ${CHANNEL_KEY} is not valid JSON`),
        );
    });
});

describe("updateChannelRecord", () => {
    it("reads, updates and writes in one step", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_INDEX, record({ lastStateVersion: 7 }));
        await expect(store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion)).resolves.toEqual(record({ lastStateVersion: 8 }));
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual(record({ lastStateVersion: 8 }));
    });

    it("passes null to the updater for an index that was never registered", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const seen: (ChannelPolicyRecord | null)[] = [];
        await store.updateChannelRecord(CHANNEL_INDEX, (current) => {
            seen.push(current);
            return record();
        });
        expect(seen).toEqual([null]);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual(record());
    });

    it("writes nothing when the updater hands back the record it was given", async () => {
        const storage = new InMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_INDEX, record());
        storage.ops.length = 0;

        await expect(store.updateChannelRecord(CHANNEL_INDEX, (current) => requireRecord(current))).resolves.toEqual(record());

        expect(storage.ops).toEqual([`get ${CHANNEL_KEY}`]);
    });

    it("writes nothing when the updater refuses", async () => {
        const storage = new InMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_INDEX, record());
        storage.ops.length = 0;
        await expect(
            store.updateChannelRecord(CHANNEL_INDEX, () => {
                throw new Error("policy refusal");
            }),
        ).rejects.toThrow(new Error("policy refusal"));
        expect(storage.ops).toEqual([`get ${CHANNEL_KEY}`]);
        expect(storage.map.get(CHANNEL_KEY)).toBe(JSON.stringify(record()));
    });

    it("writes nothing when the updater returns a record with the wrong shape", async () => {
        const storage = new InMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_INDEX, record());
        storage.ops.length = 0;
        await expect(
            store.updateChannelRecord(CHANNEL_INDEX, (current) => ({ ...requireRecord(current), localExposureShannons: "-1" })),
        ).rejects.toThrow(new TypeError("updated record is not a valid channel policy record"));
        expect(storage.ops).toEqual([`get ${CHANNEL_KEY}`]);
        expect(storage.map.get(CHANNEL_KEY)).toBe(JSON.stringify(record()));
    });

    it("refuses to update over a corrupt stored record", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(CHANNEL_KEY, "{not json");
        await expect(new SignerStore(storage).updateChannelRecord(CHANNEL_INDEX, () => record())).rejects.toThrow(
            new TypeError(`stored value at ${CHANNEL_KEY} is not valid JSON`),
        );
        expect(storage.map.get(CHANNEL_KEY)).toBe("{not json");
    });

    it("rejects a fractional channel index before touching the storage", async () => {
        const storage = new InMemorySignerStorage();
        await expect(new SignerStore(storage).updateChannelRecord(1.5, () => record())).rejects.toThrow(RangeError);
        expect(storage.ops).toEqual([]);
    });

    it("propagates a storage failure", async () => {
        const storage: IAsyncSignerStorage = {
            get: () => Promise.reject(new Error("storage unavailable")),
            set: () => Promise.resolve(),
        };
        await expect(new SignerStore(storage).updateChannelRecord(CHANNEL_INDEX, () => record())).rejects.toThrow(
            new Error("storage unavailable"),
        );
    });
});

describe("concurrency", () => {
    it("serializes concurrent updates on one channel instead of losing one", async () => {
        const storage = new AsyncInMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_INDEX, record({ lastStateVersion: 0 }));
        storage.ops.length = 0;

        await Promise.all([
            store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion),
            store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion),
        ]);

        expect(storage.ops).toEqual([`get ${CHANNEL_KEY}`, `set ${CHANNEL_KEY}`, `get ${CHANNEL_KEY}`, `set ${CHANNEL_KEY}`]);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ lastStateVersion: 2 });
    });

    it("lets only one of two concurrent claims take a sign-once slot", async () => {
        const store = new SignerStore(new AsyncInMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_INDEX, record({ lastSignedCommitmentNumbers: {}, signedSessions: {} }));
        const claim = (commitment: string): Promise<ChannelPolicyRecord> =>
            store.updateChannelRecord(CHANNEL_INDEX, (current) => {
                const existing = requireRecord(current);
                const taken = existing.signedSessions["COMMITMENT:6"];
                if (taken !== undefined && taken !== commitment) throw new Error("slot already signed");
                return { ...existing, signedSessions: { ...existing.signedSessions, "COMMITMENT:6": commitment } };
            });

        const outcomes = await Promise.allSettled([claim("aa".repeat(32)), claim("bb".repeat(32))]);

        expect(outcomes.map((outcome) => outcome.status)).toEqual(["fulfilled", "rejected"]);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            signedSessions: { "COMMITMENT:6": "aa".repeat(32) },
        });
    });

    it("serializes an operation that arrives while an earlier one is still queued", async () => {
        const storage = new AsyncInMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_INDEX, record({ lastStateVersion: 0 }));
        storage.ops.length = 0;

        const first = store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion);
        const second = store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion);
        // Enqueued the instant the first settles, while the second is still in flight.
        const third = first.then(() => store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion));
        await Promise.all([first, second, third]);

        expect(storage.ops).toEqual([
            `get ${CHANNEL_KEY}`,
            `set ${CHANNEL_KEY}`,
            `get ${CHANNEL_KEY}`,
            `set ${CHANNEL_KEY}`,
            `get ${CHANNEL_KEY}`,
            `set ${CHANNEL_KEY}`,
        ]);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ lastStateVersion: 3 });
    });

    it("does not serialize two channels against each other", async () => {
        const storage = new AsyncInMemorySignerStorage();
        const store = new SignerStore(storage);

        await Promise.all([
            store.updateChannelRecord(0, () => record({ channelId: "channel-a" })),
            store.updateChannelRecord(1, () => record({ channelId: "channel-b" })),
        ]);

        expect(storage.ops).toEqual([
            "get fiber-lsp-sdk:channel:0",
            "get fiber-lsp-sdk:channel:1",
            "set fiber-lsp-sdk:channel:0",
            "set fiber-lsp-sdk:channel:1",
        ]);
    });

    it("keeps a bare write from landing inside an update", async () => {
        const storage = new AsyncInMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_INDEX, record({ lastStateVersion: 1 }));
        storage.ops.length = 0;
        const seen: (ChannelPolicyRecord | null)[] = [];

        const update = store.updateChannelRecord(CHANNEL_INDEX, (current) => {
            seen.push(current);
            return bumpStateVersion(current);
        });
        const write = store.setChannelRecord(CHANNEL_INDEX, record({ lastStateVersion: 9 }));
        await Promise.all([update, write]);

        expect(seen).toEqual([record({ lastStateVersion: 1 })]);
        expect(storage.ops).toEqual([`get ${CHANNEL_KEY}`, `set ${CHANNEL_KEY}`, `set ${CHANNEL_KEY}`]);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ lastStateVersion: 9 });
    });

    it("serves a read issued behind a pending update the updated record", async () => {
        const store = new SignerStore(new AsyncInMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_INDEX, record({ lastStateVersion: 1 }));

        const update = store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion);
        const read = store.getChannelRecord(CHANNEL_INDEX);

        await expect(update).resolves.toMatchObject({ lastStateVersion: 2 });
        await expect(read).resolves.toMatchObject({ lastStateVersion: 2 });
    });

    it("keeps the key usable after an updater refuses", async () => {
        const store = new SignerStore(new AsyncInMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_INDEX, record({ lastStateVersion: 1 }));

        const refused = store.updateChannelRecord(CHANNEL_INDEX, () => {
            throw new Error("policy refusal");
        });
        const next = store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion);

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

        const failed = store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion);
        const next = store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion);

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
        const store = new SignerStore(new AsyncInMemorySignerStorage());
        const lanes = (store as unknown as { lanes: Map<string, unknown> }).lanes;

        await Promise.all([
            store.updateChannelRecord(CHANNEL_INDEX, () => record()),
            store.updateChannelRecord(4, () => record({ channelId: "other-channel" })),
            store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX),
            store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE),
            store.getChannelRecord(CHANNEL_INDEX),
        ]);
        expect(lanes.size).toBe(0);

        await expect(
            store.updateChannelRecord(CHANNEL_INDEX, () => {
                throw new Error("policy refusal");
            }),
        ).rejects.toThrow(new Error("policy refusal"));
        expect(lanes.size).toBe(0);
    });

    it("holds one lane per key while operations are queued on it", async () => {
        const store = new SignerStore(new AsyncInMemorySignerStorage());
        const lanes = (store as unknown as { lanes: Map<string, unknown> }).lanes;

        const pending = [
            store.updateChannelRecord(CHANNEL_INDEX, () => record()),
            store.updateChannelRecord(CHANNEL_INDEX, () => record()),
            store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX),
            store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE),
        ];
        expect([...lanes.keys()].sort()).toEqual([ALIAS_KEY, CHANNEL_KEY, PREIMAGE_KEY].sort());

        await Promise.all(pending);
        expect(lanes.size).toBe(0);
    });
});

describe("hold-invoice preimages", () => {
    it("round-trips a preimage through a synchronous storage", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE);
        await expect(store.getHoldInvoicePreimage(PAYMENT_HASH)).resolves.toBe(PREIMAGE);
    });

    it("round-trips a preimage through an asynchronous storage", async () => {
        const store = new SignerStore(new AsyncInMemorySignerStorage());
        await store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE);
        await expect(store.getHoldInvoicePreimage(PAYMENT_HASH)).resolves.toBe(PREIMAGE);
    });

    it("returns null when no preimage is stored", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await expect(store.getHoldInvoicePreimage(PAYMENT_HASH)).resolves.toBeNull();
    });

    it("namespaces the preimage key by payment hash", async () => {
        const storage = new InMemorySignerStorage();
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
        const store = new SignerStore(new InMemorySignerStorage());
        await expect(store.getHoldInvoicePreimage(badHash)).rejects.toThrow(
            new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
        );
        await expect(store.setHoldInvoicePreimage(badHash, PREIMAGE)).rejects.toThrow(
            new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
        );
    });

    it("rejects an invalid preimage on write", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await expect(store.setHoldInvoicePreimage(PAYMENT_HASH, "33".repeat(16))).rejects.toThrow(
            new TypeError("preimageHex must be 32 bytes of lowercase hex"),
        );
    });

    it("does not echo the rejected preimage in the error", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const bogus = "AB".repeat(32);
        const error = await store.setHoldInvoicePreimage(PAYMENT_HASH, bogus).catch((cause: unknown) => cause);
        expect(error).toBeInstanceOf(TypeError);
        expect((error as TypeError).message).not.toContain(bogus);
    });

    it("throws on a stored value that is not a preimage", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(PREIMAGE_KEY, "not-a-preimage");
        await expect(new SignerStore(storage).getHoldInvoicePreimage(PAYMENT_HASH)).rejects.toThrow(
            new TypeError(`stored value at ${PREIMAGE_KEY} is not a preimage`),
        );
    });

    it("overwrites a previously stored preimage", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE);
        await store.setHoldInvoicePreimage(PAYMENT_HASH, "33".repeat(32));
        await expect(store.getHoldInvoicePreimage(PAYMENT_HASH)).resolves.toBe("33".repeat(32));
    });

    it("treats an empty stored string as corruption, not absence", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(PREIMAGE_KEY, "");
        await expect(new SignerStore(storage).getHoldInvoicePreimage(PAYMENT_HASH)).rejects.toThrow(
            new TypeError(`stored value at ${PREIMAGE_KEY} is not a preimage`),
        );
    });

    it("keeps the three keyspaces disjoint", async () => {
        const storage = new InMemorySignerStorage();
        const store = new SignerStore(storage);
        await store.setChannelRecord(CHANNEL_INDEX, record());
        await store.claimChannelAlias(PAYMENT_HASH, CHANNEL_INDEX);
        await store.setHoldInvoicePreimage(PAYMENT_HASH, PREIMAGE);
        expect([...storage.map.keys()].sort()).toEqual([CHANNEL_KEY, `fiber-lsp-sdk:alias:${PAYMENT_HASH}`, PREIMAGE_KEY].sort());
        await expect(store.getHoldInvoicePreimage(PAYMENT_HASH)).resolves.toBe(PREIMAGE);
    });
});

describe("channel watermarks", () => {
    it("writes the watermark before the record it projects from", async () => {
        const ops: string[] = [];
        const storage = new InMemorySignerStorage(ops);
        const recoveryStorage = new InMemorySignerStorage(ops);
        await new SignerStore(storage, recoveryStorage).setChannelRecord(CHANNEL_INDEX, record());
        expect(ops.filter((op) => op.startsWith("set"))).toEqual([`set ${WATERMARK_KEY}`, `set ${CHANNEL_KEY}`]);
    });

    it("prunes the registry to the top slot of each context", async () => {
        const recoveryStorage = new InMemorySignerStorage();
        const store = new SignerStore(new InMemorySignerStorage(), recoveryStorage);
        await store.setChannelRecord(
            CHANNEL_INDEX,
            record({
                lastSignedCommitmentNumbers: { COMMITMENT: 5, REVOKE: 4 },
                signedSessions: { "COMMITMENT:2": "aa".repeat(32), "COMMITMENT:5": "bb".repeat(32), "REVOKE:4": "cc".repeat(32) },
            }),
        );
        await expect(store.getChannelWatermark(CHANNEL_INDEX)).resolves.toEqual({
            version: 1,
            lastSignedCommitmentNumbers: { COMMITMENT: 5, REVOKE: 4 },
            signedSessions: { "COMMITMENT:5": "bb".repeat(32), "REVOKE:4": "cc".repeat(32) },
            lastStateVersion: 7,
            localExposureShannons: "5000000000",
        });
    });

    it("drops the debit intents and the channel name, which a restore takes from elsewhere", async () => {
        const recoveryStorage = new InMemorySignerStorage();
        const store = new SignerStore(new InMemorySignerStorage(), recoveryStorage);
        await store.setChannelRecord(CHANNEL_INDEX, record({ pendingDebitsShannons: ["100", "200"] }));
        const stored = JSON.parse(recoveryStorage.map.get(WATERMARK_KEY) ?? "null") as Record<string, unknown>;
        expect(Object.keys(stored).sort()).toEqual(
            ["version", "lastSignedCommitmentNumbers", "signedSessions", "lastStateVersion", "localExposureShannons"].sort(),
        );
    });

    it("does not touch the recovery storage when the projection does not move", async () => {
        const recoveryStorage = new InMemorySignerStorage();
        const store = new SignerStore(new InMemorySignerStorage(), recoveryStorage);
        await store.setChannelRecord(CHANNEL_INDEX, record());
        await store.updateChannelRecord(CHANNEL_INDEX, (current) => ({ ...requireRecord(current), pendingDebitsShannons: ["7"] }));
        expect(recoveryStorage.ops.filter((op) => op.startsWith("set"))).toEqual([`set ${WATERMARK_KEY}`]);
    });

    it("writes it again once the projection moves", async () => {
        const recoveryStorage = new InMemorySignerStorage();
        const store = new SignerStore(new InMemorySignerStorage(), recoveryStorage);
        await store.setChannelRecord(CHANNEL_INDEX, record());
        await store.updateChannelRecord(CHANNEL_INDEX, bumpStateVersion);
        expect(recoveryStorage.ops.filter((op) => op.startsWith("set"))).toEqual([`set ${WATERMARK_KEY}`, `set ${WATERMARK_KEY}`]);
    });

    it("keeps the watermark out of the storage the host may lose", async () => {
        const storage = new InMemorySignerStorage();
        await new SignerStore(storage, new InMemorySignerStorage()).setChannelRecord(CHANNEL_INDEX, record());
        expect([...storage.map.keys()]).toEqual([CHANNEL_KEY]);
    });

    it("reports no watermark when the host injected no recovery storage", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await store.setChannelRecord(CHANNEL_INDEX, record());
        await expect(store.getChannelWatermark(CHANNEL_INDEX)).resolves.toBeNull();
    });

    it("reads a watermark written by an earlier install", async () => {
        const recoveryStorage = new InMemorySignerStorage();
        recoveryStorage.map.set(
            WATERMARK_KEY,
            JSON.stringify({
                version: 1,
                lastSignedCommitmentNumbers: { COMMITMENT: 9 },
                signedSessions: { "COMMITMENT:9": "dd".repeat(32) },
                lastStateVersion: 2,
                localExposureShannons: "62000000000",
            }),
        );
        const store = new SignerStore(new InMemorySignerStorage(), recoveryStorage);
        await expect(store.getChannelWatermark(CHANNEL_INDEX)).resolves.toEqual({
            version: 1,
            lastSignedCommitmentNumbers: { COMMITMENT: 9 },
            signedSessions: { "COMMITMENT:9": "dd".repeat(32) },
            lastStateVersion: 2,
            localExposureShannons: "62000000000",
        });
    });

    it.each([
        ["not valid JSON", "{", `stored value at ${WATERMARK_KEY} is not valid JSON`],
        ["a version from the future", '{"version":2}', `stored value at ${WATERMARK_KEY} is not a channel watermark`],
        [
            "a counter above the chain",
            '{"version":1,"lastSignedCommitmentNumbers":{"COMMITMENT":281474976710656},"signedSessions":{},"lastStateVersion":0,"localExposureShannons":"1"}',
            `stored value at ${WATERMARK_KEY} is not a channel watermark`,
        ],
        ["not an object at all", '"a watermark"', `stored value at ${WATERMARK_KEY} is not a channel watermark`],
        [
            "a state version that is not one",
            '{"version":1,"lastSignedCommitmentNumbers":{},"signedSessions":{},"lastStateVersion":-1,"localExposureShannons":"1"}',
            `stored value at ${WATERMARK_KEY} is not a channel watermark`,
        ],
        [
            "an exposure that is not decimal shannons",
            '{"version":1,"lastSignedCommitmentNumbers":{},"signedSessions":{},"lastStateVersion":0,"localExposureShannons":"0x1"}',
            `stored value at ${WATERMARK_KEY} is not a channel watermark`,
        ],
        [
            "a commitment that is not a digest",
            '{"version":1,"lastSignedCommitmentNumbers":{},"signedSessions":{"COMMITMENT:1":"ab"},"lastStateVersion":0,"localExposureShannons":"1"}',
            `stored value at ${WATERMARK_KEY} is not a channel watermark`,
        ],
    ])("throws on a watermark that is %s", async (_case, stored, message) => {
        const recoveryStorage = new InMemorySignerStorage();
        recoveryStorage.map.set(WATERMARK_KEY, stored);
        const store = new SignerStore(new InMemorySignerStorage(), recoveryStorage);
        await expect(store.getChannelWatermark(CHANNEL_INDEX)).rejects.toThrow(new TypeError(message));
    });
});

describe("the channel index allocator", () => {
    it("starts at zero and hands out indexes in sequence", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await expect(store.getNextChannelIndex()).resolves.toBe(0);
        await expect(store.allocateChannelIndex()).resolves.toBe(0);
        await expect(store.allocateChannelIndex()).resolves.toBe(1);
        await expect(store.getNextChannelIndex()).resolves.toBe(2);
    });

    it("spends an index before handing it out", async () => {
        const storage = new InMemorySignerStorage();
        await new SignerStore(storage).allocateChannelIndex();
        expect(storage.map.get(NEXT_INDEX_KEY)).toBe("1");
    });

    it("mirrors the counter into the recovery storage", async () => {
        const recoveryStorage = new InMemorySignerStorage();
        await new SignerStore(new InMemorySignerStorage(), recoveryStorage).allocateChannelIndex();
        expect(recoveryStorage.map.get(NEXT_INDEX_KEY)).toBe("1");
    });

    it("continues from the recovery storage once the main one is lost", async () => {
        const recoveryStorage = new InMemorySignerStorage();
        const store = new SignerStore(new InMemorySignerStorage(), recoveryStorage);
        await store.allocateChannelIndex();
        await store.allocateChannelIndex();
        const restored = new SignerStore(new InMemorySignerStorage(), recoveryStorage);
        await expect(restored.allocateChannelIndex()).resolves.toBe(2);
    });

    it("raises the counter to an index, and never lowers it", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await store.raiseNextChannelIndex(4);
        await expect(store.getNextChannelIndex()).resolves.toBe(5);
        await store.raiseNextChannelIndex(1);
        await expect(store.getNextChannelIndex()).resolves.toBe(5);
    });

    it("steps over an index that still holds a record", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(CHANNEL_RECORD_KEY_PREFIX + "0", JSON.stringify(record()));
        await expect(new SignerStore(storage).allocateChannelIndex()).resolves.toBe(1);
    });

    it("steps over an index whose watermark outlived its record", async () => {
        const recoveryStorage = new InMemorySignerStorage();
        recoveryStorage.map.set(
            CHANNEL_WATERMARK_KEY_PREFIX + "0",
            JSON.stringify({
                version: 1,
                lastSignedCommitmentNumbers: { COMMITMENT: 1 },
                signedSessions: {},
                lastStateVersion: 0,
                localExposureShannons: "1",
            }),
        );
        const store = new SignerStore(new InMemorySignerStorage(), recoveryStorage);
        await expect(store.allocateChannelIndex()).resolves.toBe(1);
    });

    it("gives two concurrent allocations different indexes", async () => {
        const store = new SignerStore(new AsyncInMemorySignerStorage());
        const [first, second] = await Promise.all([store.allocateChannelIndex(), store.allocateChannelIndex()]);
        expect([first, second].sort()).toEqual([0, 1]);
    });

    it("refuses to allocate once the probes run out", async () => {
        const storage = new InMemorySignerStorage();
        for (let channelIndex = 0; channelIndex <= CHANNEL_INDEX_PROBE_LIMIT; channelIndex++) {
            storage.map.set(CHANNEL_RECORD_KEY_PREFIX + channelIndex, JSON.stringify(record()));
        }
        await expect(new SignerStore(storage).allocateChannelIndex()).rejects.toThrow(
            `channel indexes 0 to ${CHANNEL_INDEX_PROBE_LIMIT} are all in use`,
        );
    });
});
