import { bytesToHex } from "@noble/hashes/utils.js";
import { COMMITMENT_LOCK_MAINNET, COMMITMENT_LOCK_TESTNET, FUNDING_LOCK_MAINNET, FUNDING_LOCK_TESTNET } from "../../../../src/digest";
import { SDK_NETWORK_NAMES, SDK_NETWORK_PRESETS, resolveSdkNetwork } from "../../../../src/sdk";
import type { SdkNetwork } from "../../../../src/sdk";

const DEV_LOCK = { codeHash: new Uint8Array(32).fill(0x5d), hashType: "data1" } as const;
const DEV_FUNDING_LOCK = { codeHash: new Uint8Array(32).fill(0x6c), hashType: "data2" } as const;

describe("resolveSdkNetwork", () => {
    it("pins the two presets to fiber's commitment and funding locks, currencies and release epoch of 4 h", () => {
        expect(SDK_NETWORK_NAMES).toEqual(["mainnet", "testnet"]);
        expect(SDK_NETWORK_PRESETS.mainnet).toEqual({
            commitmentLock: COMMITMENT_LOCK_MAINNET,
            fundingLock: FUNDING_LOCK_MAINNET,
            invoiceCurrency: "Fibb",
            fundingLockCellDepsCount: 2,
            millisecondsPerEpoch: 14_400_000,
        });
        expect(SDK_NETWORK_PRESETS.testnet).toEqual({
            commitmentLock: COMMITMENT_LOCK_TESTNET,
            fundingLock: FUNDING_LOCK_TESTNET,
            invoiceCurrency: "Fibt",
            fundingLockCellDepsCount: 2,
            millisecondsPerEpoch: 14_400_000,
        });
        expect(bytesToHex(SDK_NETWORK_PRESETS.mainnet.commitmentLock.codeHash)).toBe(
            "2d45c4d3ed3e942f1945386ee82a5d1b7e4bb16d7fe1ab015421174ab747406c",
        );
        expect(bytesToHex(SDK_NETWORK_PRESETS.testnet.commitmentLock.codeHash)).toBe(
            "740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8",
        );
        expect(SDK_NETWORK_PRESETS.mainnet.commitmentLock.hashType).toBe("type");
        expect(SDK_NETWORK_PRESETS.testnet.commitmentLock.hashType).toBe("type");
        // The `FundingLock` of fiber's node configs, under the `type` hash type.
        expect(bytesToHex(SDK_NETWORK_PRESETS.mainnet.fundingLock.codeHash)).toBe(
            "e45b1f8f21bff23137035a3ab751d75b36a981deec3e7820194b9c042967f4f1",
        );
        expect(bytesToHex(SDK_NETWORK_PRESETS.testnet.fundingLock.codeHash)).toBe(
            "6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c",
        );
        expect(SDK_NETWORK_PRESETS.mainnet.fundingLock.hashType).toBe("type");
        expect(SDK_NETWORK_PRESETS.testnet.fundingLock.hashType).toBe("type");
    });

    it.each(SDK_NETWORK_NAMES)("resolves %s to its preset", (name) => {
        expect(resolveSdkNetwork(name)).toBe(SDK_NETWORK_PRESETS[name]);
    });

    it("takes a development chain's own locks, currency, cell deps count and epoch, copying the code hashes", () => {
        const codeHash = Uint8Array.from(DEV_LOCK.codeHash);
        const fundingCodeHash = Uint8Array.from(DEV_FUNDING_LOCK.codeHash);
        const resolved = resolveSdkNetwork({
            commitmentLock: { ...DEV_LOCK, codeHash },
            fundingLock: { ...DEV_FUNDING_LOCK, codeHash: fundingCodeHash },
            invoiceCurrency: "Fibd",
            fundingLockCellDepsCount: 3,
            millisecondsPerEpoch: 2_000,
        });
        expect(resolved).toEqual({
            commitmentLock: DEV_LOCK,
            fundingLock: DEV_FUNDING_LOCK,
            invoiceCurrency: "Fibd",
            fundingLockCellDepsCount: 3,
            millisecondsPerEpoch: 2_000,
        });
        codeHash.fill(0);
        fundingCodeHash.fill(0);
        expect(resolved.commitmentLock.codeHash).toEqual(DEV_LOCK.codeHash);
        expect(resolved.fundingLock.codeHash).toEqual(DEV_FUNDING_LOCK.codeHash);
    });

    it.each([1, 2, 255])("accepts a cell deps count of %d, the bounds included", (fundingLockCellDepsCount) => {
        const resolved = resolveSdkNetwork({
            commitmentLock: DEV_LOCK,
            fundingLock: DEV_FUNDING_LOCK,
            invoiceCurrency: "Fibd",
            fundingLockCellDepsCount,
            millisecondsPerEpoch: 2_000,
        });
        expect(resolved.fundingLockCellDepsCount).toBe(fundingLockCellDepsCount);
    });

    it.each([1, 2_000, 14_400_000, Number.MAX_SAFE_INTEGER])("accepts an epoch of %d ms, the bounds included", (millisecondsPerEpoch) => {
        const resolved = resolveSdkNetwork({
            commitmentLock: DEV_LOCK,
            fundingLock: DEV_FUNDING_LOCK,
            invoiceCurrency: "Fibd",
            fundingLockCellDepsCount: 2,
            millisecondsPerEpoch,
        });
        expect(resolved.millisecondsPerEpoch).toBe(millisecondsPerEpoch);
    });

    it.each(["data", "type", "data1", "data2"] as const)("keeps a development chain's hash type %s", (hashType) => {
        const resolved = resolveSdkNetwork({
            commitmentLock: { ...DEV_LOCK, hashType },
            fundingLock: DEV_FUNDING_LOCK,
            invoiceCurrency: "Fibd",
            fundingLockCellDepsCount: 2,
            millisecondsPerEpoch: 2_000,
        });
        expect(resolved.commitmentLock.hashType).toBe(hashType);
    });

    it.each(["data", "type", "data1", "data2"] as const)("keeps a development chain's funding lock hash type %s", (hashType) => {
        const resolved = resolveSdkNetwork({
            commitmentLock: DEV_LOCK,
            fundingLock: { ...DEV_FUNDING_LOCK, hashType },
            invoiceCurrency: "Fibd",
            fundingLockCellDepsCount: 2,
            millisecondsPerEpoch: 2_000,
        });
        expect(resolved.fundingLock.hashType).toBe(hashType);
    });

    it("keeps nothing of the development chain's object but the five constants", () => {
        const network = {
            commitmentLock: { ...DEV_LOCK, args: new Uint8Array(20) },
            fundingLock: { ...DEV_FUNDING_LOCK, args: new Uint8Array(20) },
            invoiceCurrency: "Fibt",
            fundingLockCellDepsCount: 2,
            millisecondsPerEpoch: 2_000,
            extra: true,
        } as SdkNetwork;
        expect(resolveSdkNetwork(network)).toStrictEqual({
            commitmentLock: DEV_LOCK,
            fundingLock: DEV_FUNDING_LOCK,
            invoiceCurrency: "Fibt",
            fundingLockCellDepsCount: 2,
            millisecondsPerEpoch: 2_000,
        });
    });

    it.each([
        ["an unknown name", "devnet", new TypeError("network must be one of mainnet, testnet")],
        ["an upper-case name", "Mainnet", new TypeError("network must be one of mainnet, testnet")],
        ["an empty name", "", new TypeError("network must be one of mainnet, testnet")],
        ["null", null, new TypeError("network must be a network name or an object")],
        ["undefined", undefined, new TypeError("network must be a network name or an object")],
        ["an array", [], new TypeError("network must be a network name or an object")],
        [
            "no commitment lock",
            { invoiceCurrency: "Fibt", fundingLockCellDepsCount: 2, millisecondsPerEpoch: 2_000 },
            new TypeError("network.commitmentLock must be an object"),
        ],
        [
            "a code hash of 31 bytes",
            {
                commitmentLock: { ...DEV_LOCK, codeHash: new Uint8Array(31) },
                fundingLock: DEV_FUNDING_LOCK,
                invoiceCurrency: "Fibt",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2_000,
            },
            new TypeError("network.commitmentLock.codeHash must be 32 bytes, got 31"),
        ],
        [
            "an unknown hash type",
            {
                commitmentLock: { ...DEV_LOCK, hashType: "data3" },
                fundingLock: DEV_FUNDING_LOCK,
                invoiceCurrency: "Fibt",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2_000,
            },
            new TypeError("network.commitmentLock.hashType must be one of data, type, data1, data2"),
        ],
        [
            "no funding lock",
            { commitmentLock: DEV_LOCK, invoiceCurrency: "Fibt", fundingLockCellDepsCount: 2, millisecondsPerEpoch: 2_000 },
            new TypeError("network.fundingLock must be an object"),
        ],
        [
            "a null funding lock",
            {
                commitmentLock: DEV_LOCK,
                fundingLock: null,
                invoiceCurrency: "Fibt",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2_000,
            },
            new TypeError("network.fundingLock must be an object"),
        ],
        [
            "a funding lock code hash of 31 bytes",
            {
                commitmentLock: DEV_LOCK,
                fundingLock: { ...DEV_FUNDING_LOCK, codeHash: new Uint8Array(31) },
                invoiceCurrency: "Fibt",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2_000,
            },
            new TypeError("network.fundingLock.codeHash must be 32 bytes, got 31"),
        ],
        [
            "a funding lock code hash of 33 bytes",
            {
                commitmentLock: DEV_LOCK,
                fundingLock: { ...DEV_FUNDING_LOCK, codeHash: new Uint8Array(33) },
                invoiceCurrency: "Fibt",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2_000,
            },
            new TypeError("network.fundingLock.codeHash must be 32 bytes, got 33"),
        ],
        [
            "a funding lock code hash in hex",
            {
                commitmentLock: DEV_LOCK,
                fundingLock: { ...DEV_FUNDING_LOCK, codeHash: "6c".repeat(32) },
                invoiceCurrency: "Fibt",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2_000,
            },
            new TypeError("network.fundingLock.codeHash must be a Uint8Array"),
        ],
        [
            "a funding lock under an unknown hash type",
            {
                commitmentLock: DEV_LOCK,
                fundingLock: { ...DEV_FUNDING_LOCK, hashType: "data3" },
                invoiceCurrency: "Fibt",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2_000,
            },
            new TypeError("network.fundingLock.hashType must be one of data, type, data1, data2"),
        ],
        [
            "a funding lock without a hash type",
            {
                commitmentLock: DEV_LOCK,
                fundingLock: { codeHash: DEV_FUNDING_LOCK.codeHash },
                invoiceCurrency: "Fibt",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2_000,
            },
            new TypeError("network.fundingLock.hashType must be one of data, type, data1, data2"),
        ],
        [
            "no currency",
            { commitmentLock: DEV_LOCK, fundingLock: DEV_FUNDING_LOCK, fundingLockCellDepsCount: 2, millisecondsPerEpoch: 2_000 },
            new TypeError("network.invoiceCurrency must be one of Fibb, Fibt, Fibd"),
        ],
        [
            "an unknown currency",
            {
                commitmentLock: DEV_LOCK,
                fundingLock: DEV_FUNDING_LOCK,
                invoiceCurrency: "fibt",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2_000,
            },
            new TypeError("network.invoiceCurrency must be one of Fibb, Fibt, Fibd"),
        ],
    ])("refuses %s", (_, network, error) => {
        expect(() => resolveSdkNetwork(network as SdkNetwork)).toThrow(error);
    });

    it.each([
        ["no cell deps count", undefined, "undefined"],
        ["a null cell deps count", null, "null"],
        ["a cell deps count of 0", 0, "0"],
        ["a negative cell deps count", -1, "-1"],
        ["a fractional cell deps count", 1.5, "1.5"],
        ["a cell deps count past the bound", 256, "256"],
        ["a cell deps count in a string", "2", "2"],
        ["a cell deps count in a bigint", 2n, "2"],
        ["a NaN cell deps count", Number.NaN, "NaN"],
    ])("refuses %s", (_, count, shown) => {
        const network = {
            commitmentLock: DEV_LOCK,
            fundingLock: DEV_FUNDING_LOCK,
            invoiceCurrency: "Fibt",
            fundingLockCellDepsCount: count,
            millisecondsPerEpoch: 2_000,
        } as unknown as SdkNetwork;
        expect(() => resolveSdkNetwork(network)).toThrow(
            new RangeError(`network.fundingLockCellDepsCount must be an integer between 1 and 255, got ${shown}`),
        );
    });

    it("refuses a development chain without an epoch, which no field it signs states", () => {
        const network = {
            commitmentLock: DEV_LOCK,
            fundingLock: DEV_FUNDING_LOCK,
            invoiceCurrency: "Fibd",
            fundingLockCellDepsCount: 2,
        } as unknown as SdkNetwork;
        expect(() => resolveSdkNetwork(network)).toThrow(
            new RangeError("network.millisecondsPerEpoch must be an integer between 1 and 9007199254740991, got undefined"),
        );
    });

    it.each([
        ["an undefined epoch", undefined, "undefined"],
        ["a null epoch", null, "null"],
        ["an epoch of 0 ms", 0, "0"],
        ["a negative epoch", -2_000, "-2000"],
        ["a fractional epoch", 2_000.5, "2000.5"],
        ["an epoch past the largest safe integer", Number.MAX_SAFE_INTEGER + 1, "9007199254740992"],
        ["an infinite epoch", Number.POSITIVE_INFINITY, "Infinity"],
        ["a negative infinite epoch", Number.NEGATIVE_INFINITY, "-Infinity"],
        ["a NaN epoch", Number.NaN, "NaN"],
        ["an epoch in a string", "14400000", "14400000"],
        ["an epoch in a bigint", 14_400_000n, "14400000"],
    ])("refuses %s", (_, millisecondsPerEpoch, shown) => {
        const network = {
            commitmentLock: DEV_LOCK,
            fundingLock: DEV_FUNDING_LOCK,
            invoiceCurrency: "Fibd",
            fundingLockCellDepsCount: 2,
            millisecondsPerEpoch,
        } as unknown as SdkNetwork;
        expect(() => resolveSdkNetwork(network)).toThrow(
            new RangeError(`network.millisecondsPerEpoch must be an integer between 1 and 9007199254740991, got ${shown}`),
        );
    });
});
