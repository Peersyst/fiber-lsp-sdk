import { HASH256_LENGTH, isPlainObject } from "../common";
import type { SignerRecordFormat, SignerStore } from "../policy";
import { isWireHex } from "../wire";
import { DEVICE_CHANNELS_RECORD_KEY, DEVICE_CHANNELS_RECORD_VERSION } from "./sdk.constants";
import type { DeviceChannelsRecord } from "./sdk.types";
import { assertActivityId } from "./utils";

/**
 * Checks that a value has the exact shape of a stored {@link DeviceChannelsRecord}: each id a channel's, and none twice.
 * @param value Value to check, typically freshly parsed JSON.
 * @returns Whether the value is a valid record of the device's channels.
 */
function isDeviceChannelsRecord(value: unknown): value is DeviceChannelsRecord {
    if (!isPlainObject(value) || value.version !== DEVICE_CHANNELS_RECORD_VERSION) return false;
    const { channelIds } = value;
    return (
        Array.isArray(channelIds) &&
        channelIds.every((channelId: unknown) => isWireHex(channelId, HASH256_LENGTH)) &&
        new Set(channelIds).size === channelIds.length
    );
}

/**
 * Asserts that a value has the exact shape of a stored record of the device's channels.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertDeviceChannelsRecord(name: string, value: unknown): asserts value is DeviceChannelsRecord {
    if (!isDeviceChannelsRecord(value)) throw new TypeError(`${name} is not a valid device channels record`);
}

const DEVICE_CHANNELS_RECORD_FORMAT: SignerRecordFormat<DeviceChannelsRecord> = {
    name: "device channels record",
    is: isDeviceChannelsRecord,
    assert: assertDeviceChannelsRecord,
    belongsAt: () => true,
};

export class DeviceChannelList {
    private readonly store: SignerStore;

    /**
     * Creates the list over the store that keeps it.
     * @param store Typed persistence the record is kept in.
     */
    constructor(store: SignerStore) {
        this.store = store;
    }

    /**
     * Reads the channels the device opened and still polls the node about.
     * @returns Their ids, in the order they were opened; empty when none was.
     */
    async read(): Promise<string[]> {
        return (await this.store.getRecord(DEVICE_CHANNELS_RECORD_KEY, DEVICE_CHANNELS_RECORD_FORMAT))?.channelIds ?? [];
    }

    /**
     * Adds a channel the device opened; one already listed stays where it is.
     * @param channelId The channel, as fiber names it.
     */
    async add(channelId: string): Promise<void> {
        assertActivityId("channel", channelId);
        await this.store.updateRecord(DEVICE_CHANNELS_RECORD_KEY, DEVICE_CHANNELS_RECORD_FORMAT, (current) => {
            const channelIds = current?.channelIds ?? [];
            if (channelIds.includes(channelId)) return current;
            return { version: DEVICE_CHANNELS_RECORD_VERSION, channelIds: [...channelIds, channelId] } satisfies DeviceChannelsRecord;
        });
    }

    /**
     * Drops a channel nothing more can be asked about; one not listed is left alone.
     * @param channelId The channel, as fiber names it.
     */
    async remove(channelId: string): Promise<void> {
        assertActivityId("channel", channelId);
        await this.store.updateRecord(DEVICE_CHANNELS_RECORD_KEY, DEVICE_CHANNELS_RECORD_FORMAT, (current) => {
            if (current === null || !current.channelIds.includes(channelId)) return current;
            return { ...current, channelIds: current.channelIds.filter((listed) => listed !== channelId) };
        });
    }
}
