import { bytesToHex } from "@noble/hashes/utils.js";
import { COMMITMENT_LOCK_MAINNET, COMMITMENT_LOCK_TESTNET } from "../../../../src/digest";
import { SDK_NETWORK_NAMES, SDK_NETWORK_PRESETS, resolveSdkNetwork } from "../../../../src/sdk";
import type { SdkNetwork } from "../../../../src/sdk";

const DEV_LOCK = { codeHash: new Uint8Array(32).fill(0x5d), hashType: "data1" } as const;

describe("resolveSdkNetwork", () => {
    it("pins the two presets to fiber's commitment locks and currencies", () => {
        expect(SDK_NETWORK_NAMES).toEqual(["mainnet", "testnet"]);
        expect(SDK_NETWORK_PRESETS.mainnet).toEqual({ commitmentLock: COMMITMENT_LOCK_MAINNET, invoiceCurrency: "Fibb" });
        expect(SDK_NETWORK_PRESETS.testnet).toEqual({ commitmentLock: COMMITMENT_LOCK_TESTNET, invoiceCurrency: "Fibt" });
        expect(bytesToHex(SDK_NETWORK_PRESETS.mainnet.commitmentLock.codeHash)).toBe(
            "2d45c4d3ed3e942f1945386ee82a5d1b7e4bb16d7fe1ab015421174ab747406c",
        );
        expect(bytesToHex(SDK_NETWORK_PRESETS.testnet.commitmentLock.codeHash)).toBe(
            "740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8",
        );
        expect(SDK_NETWORK_PRESETS.mainnet.commitmentLock.hashType).toBe("type");
        expect(SDK_NETWORK_PRESETS.testnet.commitmentLock.hashType).toBe("type");
    });

    it.each(SDK_NETWORK_NAMES)("resolves %s to its preset", (name) => {
        expect(resolveSdkNetwork(name)).toBe(SDK_NETWORK_PRESETS[name]);
    });

    it("takes a development chain's own lock and currency, copying the code hash", () => {
        const codeHash = Uint8Array.from(DEV_LOCK.codeHash);
        const resolved = resolveSdkNetwork({ commitmentLock: { ...DEV_LOCK, codeHash }, invoiceCurrency: "Fibd" });
        expect(resolved).toEqual({ commitmentLock: DEV_LOCK, invoiceCurrency: "Fibd" });
        codeHash.fill(0);
        expect(resolved.commitmentLock.codeHash).toEqual(DEV_LOCK.codeHash);
    });

    it.each(["data", "type", "data1", "data2"] as const)("keeps a development chain's hash type %s", (hashType) => {
        const resolved = resolveSdkNetwork({ commitmentLock: { ...DEV_LOCK, hashType }, invoiceCurrency: "Fibd" });
        expect(resolved.commitmentLock.hashType).toBe(hashType);
    });

    it("keeps nothing of the development chain's object but the two constants", () => {
        const network = { commitmentLock: { ...DEV_LOCK, args: new Uint8Array(20) }, invoiceCurrency: "Fibt", extra: true } as SdkNetwork;
        expect(resolveSdkNetwork(network)).toEqual({ commitmentLock: DEV_LOCK, invoiceCurrency: "Fibt" });
    });

    it.each([
        ["an unknown name", "devnet", new TypeError("network must be one of mainnet, testnet")],
        ["an upper-case name", "Mainnet", new TypeError("network must be one of mainnet, testnet")],
        ["an empty name", "", new TypeError("network must be one of mainnet, testnet")],
        ["null", null, new TypeError("network must be a network name or an object")],
        ["undefined", undefined, new TypeError("network must be a network name or an object")],
        ["an array", [], new TypeError("network must be a network name or an object")],
        ["no commitment lock", { invoiceCurrency: "Fibt" }, new TypeError("network.commitmentLock must be an object")],
        [
            "a code hash of 31 bytes",
            { commitmentLock: { ...DEV_LOCK, codeHash: new Uint8Array(31) }, invoiceCurrency: "Fibt" },
            new TypeError("network.commitmentLock.codeHash must be 32 bytes, got 31"),
        ],
        [
            "an unknown hash type",
            { commitmentLock: { ...DEV_LOCK, hashType: "data3" }, invoiceCurrency: "Fibt" },
            new TypeError("network.commitmentLock.hashType must be one of data, type, data1, data2"),
        ],
        ["no currency", { commitmentLock: DEV_LOCK }, new TypeError("network.invoiceCurrency must be one of Fibb, Fibt, Fibd")],
        [
            "an unknown currency",
            { commitmentLock: DEV_LOCK, invoiceCurrency: "fibt" },
            new TypeError("network.invoiceCurrency must be one of Fibb, Fibt, Fibd"),
        ],
    ])("refuses %s", (_, network, error) => {
        expect(() => resolveSdkNetwork(network as SdkNetwork)).toThrow(error);
    });
});
