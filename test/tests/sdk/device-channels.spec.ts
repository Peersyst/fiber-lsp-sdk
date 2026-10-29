import { SignerStore } from "../../../src/policy";
import { DEVICE_CHANNELS_RECORD_KEY, DeviceChannelList, assertDeviceChannelsRecord } from "../../../src/sdk";
import { InMemorySignerStorage } from "../../mocks/policy";
import { rejection } from "../../utils/rejection";
import { storedAt, writes } from "../../utils/stored-records";

const KEY = "fiber-lsp-sdk:device-channels";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const OTHER_CHANNEL_ID = `0x${"2e".repeat(32)}`;
const THIRD_CHANNEL_ID = `0x${"3d".repeat(32)}`;
const STORED = { version: 1, channelIds: [CHANNEL_ID, OTHER_CHANNEL_ID] };
const CORRUPT = `stored value at ${KEY} is not a device channels record`;

function harness(stored?: unknown): { channels: DeviceChannelList; storage: InMemorySignerStorage } {
    const storage = new InMemorySignerStorage();
    if (stored !== undefined) storage.map.set(KEY, JSON.stringify(stored));
    return { channels: new DeviceChannelList(new SignerStore(storage)), storage };
}

describe("DeviceChannelList", () => {
    it("pins the key", () => {
        expect(DEVICE_CHANNELS_RECORD_KEY).toBe(KEY);
    });

    describe("read", () => {
        it("reads no channel when nothing was ever written, writing nothing", async () => {
            const h = harness();
            await expect(h.channels.read()).resolves.toEqual([]);
            expect(h.storage.ops).toEqual([`get ${KEY}`]);
        });

        it("reads the ids in the order they were added", async () => {
            await expect(harness(STORED).channels.read()).resolves.toEqual([CHANNEL_ID, OTHER_CHANNEL_ID]);
        });

        it("reads an empty list", async () => {
            await expect(harness({ version: 1, channelIds: [] }).channels.read()).resolves.toEqual([]);
        });

        it("tolerates unknown extra fields", async () => {
            await expect(harness({ ...STORED, extra: 1 }).channels.read()).resolves.toEqual([CHANNEL_ID, OTHER_CHANNEL_ID]);
        });

        it.each<[string, unknown]>([
            ["no version", { channelIds: [CHANNEL_ID] }],
            ["another version", { version: 2, channelIds: [CHANNEL_ID] }],
            ["a version as a string", { version: "1", channelIds: [CHANNEL_ID] }],
            ["no ids", { version: 1 }],
            ["ids that are not a list", { version: 1, channelIds: { [CHANNEL_ID]: true } }],
            ["an id that is not a string", { version: 1, channelIds: [7] }],
            ["an id without 0x", { version: 1, channelIds: ["1f".repeat(32)] }],
            ["an id in uppercase", { version: 1, channelIds: [`0x${"1F".repeat(32)}`] }],
            ["an id one byte short", { version: 1, channelIds: [`0x${"1f".repeat(31)}`] }],
            ["an id one byte long", { version: 1, channelIds: [`0x${"1f".repeat(33)}`] }],
            ["the same id twice", { version: 1, channelIds: [CHANNEL_ID, OTHER_CHANNEL_ID, CHANNEL_ID] }],
            ["an array", [CHANNEL_ID]],
            ["null", null],
        ])("throws on a record with %s", async (_, stored) => {
            await expect(harness(stored).channels.read()).rejects.toEqual(new TypeError(CORRUPT));
        });

        it("throws on a value that is not JSON", async () => {
            const h = harness();
            h.storage.map.set(KEY, "garbage");
            await expect(h.channels.read()).rejects.toEqual(new TypeError(`stored value at ${KEY} is not valid JSON`));
        });
    });

    describe("add", () => {
        it("writes the first channel into a fresh record", async () => {
            const h = harness();
            await h.channels.add(CHANNEL_ID);
            expect(storedAt(h.storage, KEY)).toEqual({ version: 1, channelIds: [CHANNEL_ID] });
        });

        it("appends a channel after those already listed", async () => {
            const h = harness(STORED);
            await h.channels.add(THIRD_CHANNEL_ID);
            expect(storedAt(h.storage, KEY)).toEqual({ version: 1, channelIds: [CHANNEL_ID, OTHER_CHANNEL_ID, THIRD_CHANNEL_ID] });
        });

        it("leaves a channel already listed where it is, writing nothing", async () => {
            const h = harness(STORED);
            await h.channels.add(CHANNEL_ID);
            expect(storedAt(h.storage, KEY)).toEqual(STORED);
            expect(writes(h.storage)).toEqual([]);
        });

        it("lists a channel once when two adds of it race", async () => {
            const h = harness();
            await Promise.all([h.channels.add(CHANNEL_ID), h.channels.add(CHANNEL_ID)]);
            expect(storedAt(h.storage, KEY)).toEqual({ version: 1, channelIds: [CHANNEL_ID] });
        });

        it.each<[string, unknown]>([
            ["not a string", 7],
            ["without 0x", "1f".repeat(32)],
            ["in uppercase", `0x${"1F".repeat(32)}`],
            ["one byte short", `0x${"1f".repeat(31)}`],
            ["one byte long", `0x${"1f".repeat(33)}`],
            ["null", null],
        ])("refuses an id %s, writing nothing", async (_, channelId) => {
            const h = harness();
            const error = await rejection(h.channels.add(channelId as string));
            expect(error).toEqual(new TypeError("channel id must be 32 bytes of 0x-prefixed lowercase hex"));
            expect(writes(h.storage)).toEqual([]);
        });

        it("throws on a corrupt record, writing nothing", async () => {
            const h = harness({ version: 1, channelIds: [CHANNEL_ID, CHANNEL_ID] });
            await expect(h.channels.add(OTHER_CHANNEL_ID)).rejects.toEqual(new TypeError(CORRUPT));
            expect(writes(h.storage)).toEqual([]);
        });
    });

    describe("remove", () => {
        it("drops a listed channel, keeping the others in order", async () => {
            const h = harness({ version: 1, channelIds: [CHANNEL_ID, OTHER_CHANNEL_ID, THIRD_CHANNEL_ID] });
            await h.channels.remove(OTHER_CHANNEL_ID);
            expect(storedAt(h.storage, KEY)).toEqual({ version: 1, channelIds: [CHANNEL_ID, THIRD_CHANNEL_ID] });
        });

        it("drops the last channel, leaving an empty list", async () => {
            const h = harness({ version: 1, channelIds: [CHANNEL_ID] });
            await h.channels.remove(CHANNEL_ID);
            expect(storedAt(h.storage, KEY)).toEqual({ version: 1, channelIds: [] });
        });

        it.each<[string, unknown]>([
            ["a channel not listed", STORED],
            ["any channel of a list never written", undefined],
        ])("leaves %s alone, writing nothing", async (_, stored) => {
            const h = harness(stored);
            await h.channels.remove(THIRD_CHANNEL_ID);
            expect(writes(h.storage)).toEqual([]);
        });

        it("refuses an id not in fiber's form, writing nothing", async () => {
            const h = harness(STORED);
            const error = await rejection(h.channels.remove("1f".repeat(32)));
            expect(error).toEqual(new TypeError("channel id must be 32 bytes of 0x-prefixed lowercase hex"));
            expect(writes(h.storage)).toEqual([]);
        });

        it("throws on a corrupt record, writing nothing", async () => {
            const h = harness({ version: 2, channelIds: [CHANNEL_ID] });
            await expect(h.channels.remove(CHANNEL_ID)).rejects.toEqual(new TypeError(CORRUPT));
            expect(writes(h.storage)).toEqual([]);
        });
    });

    describe("assertDeviceChannelsRecord", () => {
        it("accepts a record of the device's channels", () => {
            expect(() => assertDeviceChannelsRecord("record", STORED)).not.toThrow();
        });

        it("throws naming the value on one off its form", () => {
            expect(() => assertDeviceChannelsRecord("record", { version: 1, channelIds: [CHANNEL_ID, CHANNEL_ID] })).toThrow(
                new TypeError("record is not a valid device channels record"),
            );
        });
    });
});
