import type { CellDep, Script } from "../../../src/common";
import { SignerStore } from "../../../src/policy";
import { PENDING_OPENING_RECORD_KEY, PendingOpeningStore } from "../../../src/sdk";
import { AsyncInMemorySignerStorage, InMemorySignerStorage } from "../../mocks/policy";
import { rejection } from "../../utils/rejection";
import { withField } from "../../utils/with-field";

const KEY = "fiber-lsp-sdk:opening";
const INDEX = 1_790_812_800;
const OTHER_INDEX = 1_790_812_801;
const FUNDED = "10000000000";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const OTHER_CHANNEL_ID = `0x${"2e".repeat(32)}`;
const LOCK: Script = { codeHash: new Uint8Array(32).fill(0x9b), hashType: "type", args: new Uint8Array(20).fill(0x11) };
// The molecule table of LOCK: total size, three offsets, the code hash, the hash type byte, then the args' length and bytes.
const LOCK_HEX = `49000000100000003000000031000000${"9b".repeat(32)}0114000000${"11".repeat(20)}`;
const STORED = { version: 1, opening: { channelIndex: INDEX, fundedShannons: FUNDED, userLock: LOCK_HEX, channelId: null } };
const STORED_WITH_ID = { version: 1, opening: { channelIndex: INDEX, fundedShannons: FUNDED, userLock: LOCK_HEX, channelId: CHANNEL_ID } };
const CLEARED = { version: 1, opening: null };
const CELL_DEPS: CellDep[] = [
    { outPoint: { txHash: new Uint8Array(32).fill(0xd8), index: 0 }, depType: "dep_group" },
    { outPoint: { txHash: new Uint8Array(32).fill(0x25), index: 2 }, depType: "code" },
];
const CELL_DEPS_STORED = [
    { txHash: "d8".repeat(32), index: 0, depType: "dep_group" },
    { txHash: "25".repeat(32), index: 2, depType: "code" },
];
const STORED_WITH_DEPS = {
    version: 1,
    opening: { channelIndex: INDEX, fundedShannons: FUNDED, userLock: LOCK_HEX, userLockCellDeps: CELL_DEPS_STORED, channelId: CHANNEL_ID },
};
const CORRUPT = `stored value at ${KEY} is not a pending opening record`;

function harness(stored?: unknown, storage: InMemorySignerStorage | AsyncInMemorySignerStorage = new InMemorySignerStorage()) {
    if (stored !== undefined) storage.map.set(KEY, JSON.stringify(stored));
    return { openings: new PendingOpeningStore(new SignerStore(storage)), storage };
}

function storedOf(h: { storage: InMemorySignerStorage | AsyncInMemorySignerStorage }): unknown {
    const raw = h.storage.map.get(KEY);
    return raw === undefined ? undefined : JSON.parse(raw);
}

function writes(h: { storage: InMemorySignerStorage | AsyncInMemorySignerStorage }): string[] {
    return h.storage.ops.filter((op) => op.startsWith("set "));
}

describe("PendingOpeningStore", () => {
    it("pins the key", () => {
        expect(PENDING_OPENING_RECORD_KEY).toBe(KEY);
    });

    describe("read", () => {
        it("reads null when nothing was ever written, writing nothing", async () => {
            const h = harness();
            await expect(h.openings.read()).resolves.toBeNull();
            expect(h.storage.ops).toEqual([`get ${KEY}`]);
        });

        it("reads null once the opening was cleared", async () => {
            await expect(harness(CLEARED).openings.read()).resolves.toBeNull();
        });

        it("reads what a previous instance wrote", async () => {
            const storage = new InMemorySignerStorage();
            await harness(undefined, storage).openings.write(INDEX, FUNDED, LOCK);
            await expect(harness(undefined, storage).openings.read()).resolves.toStrictEqual(STORED.opening);
        });

        it("reads a channel id once one is set", async () => {
            await expect(harness(STORED_WITH_ID).openings.read()).resolves.toStrictEqual(STORED_WITH_ID.opening);
        });

        it.each<[string, string, unknown]>([
            ["the largest channel index", "opening.channelIndex", Number.MAX_SAFE_INTEGER],
            ["channel index 0", "opening.channelIndex", 0],
            ["a zero amount", "opening.fundedShannons", "0"],
            ["the largest u128 amount", "opening.fundedShannons", "340282366920938463463374607431768211455"],
            ["a lock with no args", "opening.userLock", `35000000100000003000000031000000${"9b".repeat(32)}0000000000`],
        ])("reads %s", async (_, path, value) => {
            const stored = withField(STORED, path, value);
            await expect(harness(stored).openings.read()).resolves.toStrictEqual(stored.opening);
        });

        it("tolerates unknown extra fields", async () => {
            await expect(harness({ ...STORED, extra: 1 }).openings.read()).resolves.toStrictEqual(STORED.opening);
        });
    });

    describe("a corrupt record", () => {
        it.each<[string, string, unknown]>([
            ["an absent version", "version", undefined],
            ["another version", "version", 2],
            ["the version as a string", "version", "1"],
            ["an absent opening", "opening", undefined],
            ["an opening that is not an object", "opening", "pending"],
            ["an opening that is an array", "opening", []],
            ["an absent channel index", "opening.channelIndex", undefined],
            ["a negative channel index", "opening.channelIndex", -1],
            ["a fractional channel index", "opening.channelIndex", 1.5],
            ["a channel index past the largest safe integer", "opening.channelIndex", Number.MAX_SAFE_INTEGER + 1],
            ["a channel index as a string", "opening.channelIndex", String(INDEX)],
            ["an absent amount", "opening.fundedShannons", undefined],
            ["an amount as a number", "opening.fundedShannons", 10000000000],
            ["an amount with a leading zero", "opening.fundedShannons", "010000000000"],
            ["an amount in hex", "opening.fundedShannons", "0x2540be400"],
            ["an amount past u128", "opening.fundedShannons", "340282366920938463463374607431768211456"],
            ["an absent lock", "opening.userLock", undefined],
            ["an empty lock", "opening.userLock", ""],
            ["a lock in uppercase hex", "opening.userLock", LOCK_HEX.toUpperCase()],
            ["a lock with the 0x prefix", "opening.userLock", `0x${LOCK_HEX}`],
            ["a lock of an odd length", "opening.userLock", LOCK_HEX.slice(0, -1)],
            ["a lock missing its last byte", "opening.userLock", LOCK_HEX.slice(0, -2)],
            [
                "a lock with a hash type CKB does not define",
                "opening.userLock",
                LOCK_HEX.replace(`${"9b".repeat(32)}01`, `${"9b".repeat(32)}03`),
            ],
            ["a lock as an object", "opening.userLock", { codeHash: "9b".repeat(32), hashType: "type", args: "11".repeat(20) }],
            ["an absent channel id", "opening.channelId", undefined],
            ["a channel id without the 0x prefix", "opening.channelId", "1f".repeat(32)],
            ["a channel id in uppercase hex", "opening.channelId", `0x${"1F".repeat(32)}`],
            ["a channel id one byte short", "opening.channelId", `0x${"1f".repeat(31)}`],
            ["a channel id one byte long", "opening.channelId", `0x${"1f".repeat(33)}`],
        ])("refuses %s on a read", async (_, path, value) => {
            const h = harness(withField(STORED_WITH_ID, path, value));
            await expect(h.openings.read()).rejects.toThrow(new TypeError(CORRUPT));
        });

        it.each<[string, string, unknown]>([
            ["null cell deps", "opening.userLockCellDeps", null],
            ["cell deps that are not a list", "opening.userLockCellDeps", CELL_DEPS_STORED[0]],
            ["a cell dep that is not an object", "opening.userLockCellDeps[1]", "25".repeat(32)],
            ["a null cell dep", "opening.userLockCellDeps[1]", null],
            ["a cell dep without its tx hash", "opening.userLockCellDeps[1].txHash", undefined],
            ["a tx hash with the 0x prefix", "opening.userLockCellDeps[1].txHash", `0x${"25".repeat(32)}`],
            ["a tx hash in uppercase hex", "opening.userLockCellDeps[1].txHash", "2A".repeat(32)],
            ["a tx hash one byte short", "opening.userLockCellDeps[1].txHash", "25".repeat(31)],
            ["a tx hash as bytes", "opening.userLockCellDeps[1].txHash", Array(32).fill(0x25)],
            ["a cell dep without its index", "opening.userLockCellDeps[1].index", undefined],
            ["a negative index", "opening.userLockCellDeps[1].index", -1],
            ["a fractional index", "opening.userLockCellDeps[1].index", 1.5],
            ["an index past a u32", "opening.userLockCellDeps[1].index", 2 ** 32],
            ["an index as a string", "opening.userLockCellDeps[1].index", "2"],
            ["a cell dep without its dep type", "opening.userLockCellDeps[1].depType", undefined],
            ["a dep type CKB does not define", "opening.userLockCellDeps[1].depType", "depGroup"],
        ])("refuses %s on a read", async (_, path, value) => {
            const h = harness(withField(STORED_WITH_DEPS, path, value));
            await expect(h.openings.read()).rejects.toThrow(new TypeError(CORRUPT));
        });

        it("reads cell deps at the bounds of their index", async () => {
            const stored = withField(
                withField(STORED_WITH_DEPS, "opening.userLockCellDeps[0].index", 2 ** 32 - 1),
                "opening.userLockCellDeps[1].index",
                0,
            );
            await expect(harness(stored).openings.read()).resolves.toStrictEqual(stored.opening);
        });

        it("refuses a record that is not JSON", async () => {
            const storage = new InMemorySignerStorage();
            storage.map.set(KEY, "{");
            await expect(harness(undefined, storage).openings.read()).rejects.toThrow(
                new TypeError(`stored value at ${KEY} is not valid JSON`),
            );
        });

        // Every operation checks its arguments before it updates, so only the format itself can be handed a corrupt record.
        it("hands the store a format that refuses to write a record it would refuse on a read", async () => {
            const store = new SignerStore(new InMemorySignerStorage());
            const update = jest.spyOn(store, "updateRecord");
            await new PendingOpeningStore(store).write(INDEX, FUNDED, LOCK);
            const format = update.mock.calls[0]?.[1];
            expect(() => format?.assert("updated record", withField(STORED, "opening.channelIndex", -1))).toThrow(
                new TypeError("updated record is not a valid pending opening record"),
            );
            expect(() => format?.assert("updated record", STORED)).not.toThrow();
        });

        it.each<[string, (openings: PendingOpeningStore) => Promise<unknown>]>([
            ["a match", (openings) => openings.readMatching(FUNDED, LOCK)],
            ["a write", (openings) => openings.write(INDEX, FUNDED, LOCK)],
            ["a channel id", (openings) => openings.setChannelId(INDEX, CHANNEL_ID)],
            ["a clear", (openings) => openings.clear(CHANNEL_ID)],
            ["a clear by index", (openings) => openings.clearIndex(INDEX)],
        ])("refuses it on %s, writing nothing", async (_, operation) => {
            const h = harness(withField(STORED, "opening.channelIndex", -1));
            await expect(operation(h.openings)).rejects.toThrow(new TypeError(CORRUPT));
            expect(writes(h)).toEqual([]);
        });
    });

    describe("write", () => {
        it("persists the opening as JSON, with the lock as molecule hex and no channel yet, and returns it", async () => {
            const h = harness();
            await expect(h.openings.write(INDEX, FUNDED, LOCK)).resolves.toStrictEqual(STORED.opening);
            expect(h.storage.map.get(KEY)).toBe(
                `{"version":1,"opening":{"channelIndex":${INDEX},"fundedShannons":"${FUNDED}","userLock":"${LOCK_HEX}","channelId":null}}`,
            );
            expect([...h.storage.map.keys()]).toEqual([KEY]);
        });

        it("persists the cell deps of the lock in their record form, and returns them unheld by the store", async () => {
            const h = harness();
            const opening = await h.openings.write(INDEX, FUNDED, LOCK, CELL_DEPS);
            expect(opening).toStrictEqual({ ...STORED_WITH_DEPS.opening, channelId: null });
            expect(h.storage.map.get(KEY)).toBe(
                `{"version":1,"opening":{"channelIndex":${INDEX},"fundedShannons":"${FUNDED}","userLock":"${LOCK_HEX}",` +
                    `"userLockCellDeps":[{"txHash":"${"d8".repeat(32)}","index":0,"depType":"dep_group"},` +
                    `{"txHash":"${"25".repeat(32)}","index":2,"depType":"code"}],"channelId":null}}`,
            );
            const returned = opening.userLockCellDeps?.[0];
            if (returned === undefined) throw new Error("no cell dep returned");
            returned.index = 9;
            await expect(h.openings.read()).resolves.toStrictEqual({ ...STORED_WITH_DEPS.opening, channelId: null });
        });

        it("records an empty list of cell deps as given, the caller deciding what it means", async () => {
            const h = harness();
            const recorded = { ...STORED.opening, userLockCellDeps: [] };
            await expect(h.openings.write(INDEX, FUNDED, LOCK, [])).resolves.toStrictEqual(recorded);
            expect(storedOf(h)).toStrictEqual({ version: 1, opening: recorded });
            await expect(h.openings.read()).resolves.toStrictEqual(recorded);
        });

        it("replaces another opening, its channel id included", async () => {
            const h = harness(STORED_WITH_ID);
            await h.openings.write(OTHER_INDEX, "20000000000", { ...LOCK, hashType: "data1" });
            expect(storedOf(h)).toStrictEqual({
                version: 1,
                opening: {
                    channelIndex: OTHER_INDEX,
                    fundedShannons: "20000000000",
                    userLock: LOCK_HEX.replace(`${"9b".repeat(32)}01`, `${"9b".repeat(32)}02`),
                    channelId: null,
                },
            });
        });

        it("writes over a cleared opening", async () => {
            const h = harness(CLEARED);
            await h.openings.write(INDEX, FUNDED, LOCK);
            expect(storedOf(h)).toStrictEqual(STORED);
        });

        it("writes before it resolves, with an asynchronous storage too", async () => {
            const h = harness(undefined, new AsyncInMemorySignerStorage());
            await h.openings.write(INDEX, FUNDED, LOCK);
            expect(storedOf(h)).toStrictEqual(STORED);
        });

        it("returns an opening the store does not hold: writing to it changes nothing stored", async () => {
            const h = harness();
            const opening = await h.openings.write(INDEX, FUNDED, LOCK);
            opening.channelId = CHANNEL_ID;
            await expect(h.openings.read()).resolves.toStrictEqual(STORED.opening);
        });

        it.each<[string, number, string, unknown, Error]>([
            [
                "a negative index",
                -1,
                FUNDED,
                LOCK,
                new RangeError(`channelIndex must be an integer between 0 and ${Number.MAX_SAFE_INTEGER}, got -1`),
            ],
            [
                "a fractional index",
                1.5,
                FUNDED,
                LOCK,
                new RangeError(`channelIndex must be an integer between 0 and ${Number.MAX_SAFE_INTEGER}, got 1.5`),
            ],
            [
                "an index past the largest safe integer",
                Number.MAX_SAFE_INTEGER + 1,
                FUNDED,
                LOCK,
                new RangeError(
                    `channelIndex must be an integer between 0 and ${Number.MAX_SAFE_INTEGER}, got ${Number.MAX_SAFE_INTEGER + 1}`,
                ),
            ],
            [
                "an amount that is not decimal shannons",
                INDEX,
                "1e10",
                LOCK,
                new TypeError("fundedShannons must be an amount in decimal shannons"),
            ],
            [
                "a lock without args",
                INDEX,
                FUNDED,
                { codeHash: LOCK.codeHash, hashType: "type" },
                new TypeError("userLock.args must be a Uint8Array"),
            ],
            [
                "a lock with a short code hash",
                INDEX,
                FUNDED,
                { ...LOCK, codeHash: new Uint8Array(31) },
                new TypeError("userLock.codeHash must be 32 bytes, got 31"),
            ],
        ])("refuses %s, writing nothing", async (_, index, funded, lock, error) => {
            const h = harness();
            await expect(h.openings.write(index, funded, lock as Script)).rejects.toThrow(error);
            expect(h.storage.ops).toEqual([]);
        });

        it.each<[string, unknown, Error]>([
            ["cell deps that are not a list", CELL_DEPS[0], new TypeError("userLockCellDeps must be an array")],
            ["null cell deps", null, new TypeError("userLockCellDeps must be an array")],
            ["a cell dep that is not an object", [CELL_DEPS[0], "dep"], new TypeError("userLockCellDeps[1] must be an object")],
            ["a cell dep without an out point", [{ depType: "code" }], new TypeError("userLockCellDeps[0].outPoint must be an object")],
            [
                "a cell dep with a short tx hash",
                [{ outPoint: { txHash: new Uint8Array(31), index: 0 }, depType: "code" }],
                new TypeError("userLockCellDeps[0].outPoint.txHash must be 32 bytes, got 31"),
            ],
            [
                "a cell dep with a negative index",
                [{ outPoint: { txHash: new Uint8Array(32), index: -1 }, depType: "code" }],
                new RangeError("userLockCellDeps[0].outPoint.index must be an integer between 0 and 4294967295, got -1"),
            ],
            [
                "a cell dep with an unknown dep type",
                [{ outPoint: { txHash: new Uint8Array(32), index: 0 }, depType: "depGroup" }],
                new TypeError("userLockCellDeps[0].depType must be one of code, dep_group"),
            ],
        ])("refuses %s, writing nothing", async (_, deps, error) => {
            const h = harness();
            const thrown = await rejection(h.openings.write(INDEX, FUNDED, LOCK, deps as CellDep[]));
            expect(thrown).toEqual(error);
            expect(thrown).toBeInstanceOf(error.constructor);
            expect(h.storage.ops).toEqual([]);
        });

        it("takes the largest safe integer as the index", async () => {
            const h = harness();
            await h.openings.write(Number.MAX_SAFE_INTEGER, FUNDED, LOCK);
            expect(storedOf(h)).toStrictEqual(withField(STORED, "opening.channelIndex", Number.MAX_SAFE_INTEGER));
        });
    });

    describe("readMatching", () => {
        it("reads the opening asked with the same amount and lock", async () => {
            const h = harness(STORED_WITH_ID);
            const lock: Script = { codeHash: new Uint8Array(32).fill(0x9b), hashType: "type", args: new Uint8Array(20).fill(0x11) };
            await expect(h.openings.readMatching(FUNDED, lock)).resolves.toStrictEqual(STORED_WITH_ID.opening);
            expect(writes(h)).toEqual([]);
        });

        it.each<[string, string, Script]>([
            ["another amount", "10000000001", LOCK],
            ["another code hash", FUNDED, { ...LOCK, codeHash: new Uint8Array(32).fill(0x9c) }],
            ["another hash type", FUNDED, { ...LOCK, hashType: "data" }],
            ["other args", FUNDED, { ...LOCK, args: new Uint8Array(20).fill(0x12) }],
            ["args one byte shorter", FUNDED, { ...LOCK, args: new Uint8Array(19).fill(0x11) }],
        ])("reads null for %s", async (_, funded, lock) => {
            await expect(harness(STORED).openings.readMatching(funded, lock)).resolves.toBeNull();
        });

        it("reads the opening asked with the same cell deps, none with none and an empty list with an empty list", async () => {
            const deps: CellDep[] = [
                { outPoint: { txHash: new Uint8Array(32).fill(0xd8), index: 0 }, depType: "dep_group" },
                { outPoint: { txHash: new Uint8Array(32).fill(0x25), index: 2 }, depType: "code" },
            ];
            await expect(harness(STORED_WITH_DEPS).openings.readMatching(FUNDED, LOCK, deps)).resolves.toStrictEqual(
                STORED_WITH_DEPS.opening,
            );
            await expect(harness(STORED).openings.readMatching(FUNDED, LOCK, undefined)).resolves.toStrictEqual(STORED.opening);
            const withEmpty = withField(STORED, "opening.userLockCellDeps", []);
            await expect(harness(withEmpty).openings.readMatching(FUNDED, LOCK, [])).resolves.toStrictEqual(withEmpty.opening);
        });

        it.each<[string, unknown, CellDep[] | undefined]>([
            ["no cell deps when the opening named some", STORED_WITH_DEPS, undefined],
            ["an empty list when the opening named some", STORED_WITH_DEPS, []],
            ["an empty list when the opening named none", STORED, []],
            ["none when the opening named an empty list", withField(STORED, "opening.userLockCellDeps", []), undefined],
            ["cell deps when the opening named none", STORED, CELL_DEPS],
            ["one cell dep fewer", STORED_WITH_DEPS, CELL_DEPS.slice(0, 1)],
            ["one cell dep more", STORED_WITH_DEPS, [...CELL_DEPS, CELL_DEPS[0] as CellDep]],
            ["the cell deps in another order", STORED_WITH_DEPS, [...CELL_DEPS].reverse()],
            [
                "another tx hash",
                STORED_WITH_DEPS,
                [CELL_DEPS[0] as CellDep, { outPoint: { txHash: new Uint8Array(32).fill(0x26), index: 2 }, depType: "code" }],
            ],
            [
                "another index",
                STORED_WITH_DEPS,
                [CELL_DEPS[0] as CellDep, { outPoint: { txHash: new Uint8Array(32).fill(0x25), index: 3 }, depType: "code" }],
            ],
            [
                "another dep type",
                STORED_WITH_DEPS,
                [CELL_DEPS[0] as CellDep, { outPoint: { txHash: new Uint8Array(32).fill(0x25), index: 2 }, depType: "dep_group" }],
            ],
        ])("reads null for %s", async (_, stored, deps) => {
            await expect(harness(stored).openings.readMatching(FUNDED, LOCK, deps)).resolves.toBeNull();
        });

        it("refuses cell deps that are not ones, reading nothing", async () => {
            const h = harness(STORED_WITH_DEPS);
            const error = await rejection(h.openings.readMatching(FUNDED, LOCK, [{ depType: "code" }] as unknown as CellDep[]));
            expect(error).toEqual(new TypeError("userLockCellDeps[0].outPoint must be an object"));
            expect(h.storage.ops).toEqual([]);
        });

        it("reads null when nothing is pending", async () => {
            await expect(harness().openings.readMatching(FUNDED, LOCK)).resolves.toBeNull();
            await expect(harness(CLEARED).openings.readMatching(FUNDED, LOCK)).resolves.toBeNull();
        });

        it("refuses a lock that is not a script, reading nothing", async () => {
            const h = harness(STORED);
            const error = await rejection(h.openings.readMatching(FUNDED, { ...LOCK, hashType: "data3" } as unknown as Script));
            expect(error).toEqual(new TypeError("userLock.hashType must be one of data, type, data1, data2"));
            expect(h.storage.ops).toEqual([]);
        });
    });

    describe("setChannelId", () => {
        it("names the channel of the opening under the index", async () => {
            const h = harness(STORED);
            await expect(h.openings.setChannelId(INDEX, CHANNEL_ID)).resolves.toBeUndefined();
            expect(storedOf(h)).toStrictEqual(STORED_WITH_ID);
        });

        it("renames the channel of the opening under the index", async () => {
            const h = harness(STORED_WITH_ID);
            await expect(h.openings.setChannelId(INDEX, OTHER_CHANNEL_ID)).resolves.toBeUndefined();
            expect(storedOf(h)).toStrictEqual(withField(STORED_WITH_ID, "opening.channelId", OTHER_CHANNEL_ID));
        });

        it("writes nothing when the opening already names the channel", async () => {
            const h = harness(STORED_WITH_ID);
            await expect(h.openings.setChannelId(INDEX, CHANNEL_ID)).resolves.toBeUndefined();
            expect(writes(h)).toEqual([]);
        });

        it("leaves an opening under another index alone", async () => {
            const h = harness(STORED);
            await expect(h.openings.setChannelId(OTHER_INDEX, CHANNEL_ID)).resolves.toBeUndefined();
            expect(writes(h)).toEqual([]);
            expect(storedOf(h)).toStrictEqual(STORED);
        });

        it("leaves an opening under another index alone, even one that names the same channel", async () => {
            const h = harness(STORED_WITH_ID);
            await expect(h.openings.setChannelId(OTHER_INDEX, CHANNEL_ID)).resolves.toBeUndefined();
            expect(writes(h)).toEqual([]);
        });

        it.each<[string, unknown]>([
            ["nothing was ever written", undefined],
            ["the opening was cleared", CLEARED],
        ])("does nothing when %s", async (_, stored) => {
            const h = harness(stored);
            await expect(h.openings.setChannelId(INDEX, CHANNEL_ID)).resolves.toBeUndefined();
            expect(writes(h)).toEqual([]);
        });

        it.each<[string, number, string, Error]>([
            [
                "a negative index",
                -1,
                CHANNEL_ID,
                new RangeError(`channelIndex must be an integer between 0 and ${Number.MAX_SAFE_INTEGER}, got -1`),
            ],
            [
                "a channel id without the 0x prefix",
                INDEX,
                "1f".repeat(32),
                new TypeError("channel id must be 32 bytes of 0x-prefixed lowercase hex"),
            ],
            [
                "a channel id one byte short",
                INDEX,
                `0x${"1f".repeat(31)}`,
                new TypeError("channel id must be 32 bytes of 0x-prefixed lowercase hex"),
            ],
        ])("refuses %s, reading nothing", async (_, index, channelId, error) => {
            const h = harness(STORED);
            await expect(h.openings.setChannelId(index, channelId)).rejects.toThrow(error);
            expect(h.storage.ops).toEqual([]);
        });
    });

    describe("clear", () => {
        it("drops the opening that names the channel", async () => {
            const h = harness(STORED_WITH_ID);
            await expect(h.openings.clear(CHANNEL_ID)).resolves.toBeUndefined();
            expect(h.storage.map.get(KEY)).toBe('{"version":1,"opening":null}');
            await expect(h.openings.read()).resolves.toBeNull();
        });

        it.each<[string, unknown]>([
            ["names another channel", STORED_WITH_ID],
            ["names no channel yet", STORED],
        ])("leaves an opening that %s alone", async (_, stored) => {
            const h = harness(stored);
            await expect(h.openings.clear(OTHER_CHANNEL_ID)).resolves.toBeUndefined();
            expect(writes(h)).toEqual([]);
            expect(storedOf(h)).toStrictEqual(stored);
        });

        it.each<[string, unknown]>([
            ["nothing was ever written", undefined],
            ["the opening was cleared", CLEARED],
        ])("does nothing when %s", async (_, stored) => {
            const h = harness(stored);
            await expect(h.openings.clear(CHANNEL_ID)).resolves.toBeUndefined();
            expect(writes(h)).toEqual([]);
        });

        it.each<[string, unknown]>([
            ["no channel id", undefined],
            ["a channel id without the 0x prefix", "1f".repeat(32)],
        ])("refuses %s, reading nothing", async (_, channelId) => {
            const h = harness(STORED_WITH_ID);
            await expect(h.openings.clear(channelId as string)).rejects.toThrow(
                new TypeError("channel id must be 32 bytes of 0x-prefixed lowercase hex"),
            );
            expect(h.storage.ops).toEqual([]);
        });
    });

    describe("clearIndex", () => {
        it.each<[string, unknown]>([
            ["one with no channel yet", STORED],
            ["one that names a channel", STORED_WITH_ID],
        ])("drops the opening under the index, %s", async (_, stored) => {
            const h = harness(stored);
            await expect(h.openings.clearIndex(INDEX)).resolves.toBeUndefined();
            expect(storedOf(h)).toStrictEqual(CLEARED);
        });

        it.each<[string, unknown]>([
            ["one with no channel yet", STORED],
            ["one that names a channel", STORED_WITH_ID],
        ])("leaves an opening under another index alone, %s", async (_, stored) => {
            const h = harness(stored);
            await expect(h.openings.clearIndex(OTHER_INDEX)).resolves.toBeUndefined();
            expect(writes(h)).toEqual([]);
            expect(storedOf(h)).toStrictEqual(stored);
        });

        it.each<[string, unknown]>([
            ["nothing was ever written", undefined],
            ["the opening was cleared", CLEARED],
        ])("does nothing when %s", async (_, stored) => {
            const h = harness(stored);
            await expect(h.openings.clearIndex(INDEX)).resolves.toBeUndefined();
            expect(writes(h)).toEqual([]);
        });

        it.each<[string, unknown, string]>([
            ["no index", undefined, "undefined"],
            ["a negative index", -1, "-1"],
            ["a fractional index", 1.5, "1.5"],
            ["an index past the largest safe integer", Number.MAX_SAFE_INTEGER + 1, String(Number.MAX_SAFE_INTEGER + 1)],
        ])("refuses %s, reading nothing", async (_, index, shown) => {
            const h = harness(STORED);
            await expect(h.openings.clearIndex(index as number)).rejects.toThrow(
                new RangeError(`channelIndex must be an integer between 0 and ${Number.MAX_SAFE_INTEGER}, got ${shown}`),
            );
            expect(h.storage.ops).toEqual([]);
        });
    });
});
