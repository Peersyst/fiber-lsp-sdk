import { hexToBytes } from "@noble/hashes/utils.js";
import type { OpenTenantChannelResult } from "../../../../src/rpc";
import type { SdkOpeningRequest } from "../../../../src/sdk";
import { SdkError, checkTenantOpening } from "../../../../src/sdk";
import { sdkRefusal } from "../../../utils/refusal";
import { withField } from "../../../utils/with-field";

// The device's keys at channel index 1_791_367_200 of the master seed 0x24 repeated; the peer's are the signing vectors'.
const DEVICE_FUNDING_PUBKEY = "033d7405b9260f20ed7352346928485f216a78f7f1a4cda82b629fc651d4e8dbfd";
const DEVICE_TLC_BASE_PUBKEY = "0276151a3496ee4b719ef2adb2cf62247040b7e6d3bc7151c53d354f07a7c3807f";
const PEER_FUNDING_PUBKEY = "026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638";
const PEER_TLC_BASE_PUBKEY = "032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21";
// tenantChannelId(DEVICE_TLC_BASE_PUBKEY, PEER_TLC_BASE_PUBKEY).
const CHANNEL_ID = "0x5df11183f0223c41ea85677270eeaf085d3d2fa00f4a35b1b870b7af25b0287f";
// The same, over the device's funding key instead of its TLC base key.
const FUNDING_KEY_CHANNEL_ID = "0xad65197b48f4aea2e5a2b7275db8fa9ba5c00961e7af95eafbee00196a8be562";
// fundingLockArgs(DEVICE_FUNDING_PUBKEY, PEER_FUNDING_PUBKEY).
const FUNDING_LOCK_ARGS = "d2062cbf42d7ba8d2a9c1ac3e81cef97e8fc0a78";
// fundingLockArgs of the device's funding key at index 1_791_367_201 and the peer's.
const OTHER_FUNDING_LOCK_ARGS = "b0901bdf23af3f27d40550c17bf509d3b80f1e22";
const TESTNET_FUNDING_LOCK_CODE_HASH = "6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c";
const MAINNET_FUNDING_LOCK_CODE_HASH = "e45b1f8f21bff23137035a3ab751d75b36a981deec3e7820194b9c042967f4f1";
const TESTNET_COMMITMENT_LOCK_CODE_HASH = "740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8";
const OFF_CURVE_KEY = Uint8Array.of(0x02, ...new Uint8Array(32));
const UINT64_MAX = 18_446_744_073_709_551_615n;

const USER_LOCK = {
    codeHash: hexToBytes("537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d769"),
    hashType: "type",
    args: hexToBytes("8d66477ba3b60a96feb27a3f57fe11f6697be87d"),
} as const;
const PEER_LOCK = {
    codeHash: hexToBytes("4d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba"),
    hashType: "type",
    args: hexToBytes("8f1e030962418183dc890ef5664b1f2a64b0064c"),
} as const;

const REQUEST: SdkOpeningRequest = {
    fundedShannons: "72000000000",
    userLock: USER_LOCK,
    commitmentDelayEpoch: 0x10000000001n,
    commitmentFeeRate: 1000n,
    fundingPubkey: hexToBytes(DEVICE_FUNDING_PUBKEY),
    tlcBasePubkey: hexToBytes(DEVICE_TLC_BASE_PUBKEY),
    fundingLock: { codeHash: hexToBytes(TESTNET_FUNDING_LOCK_CODE_HASH), hashType: "type" },
};

// The RPC vector's opening, over the keys and scripts above: 720 CKB funded, 285 CKB from the peer, both reserves 100 CKB
// under the full payment hash layout, and a change output for each party.
const ANSWER: OpenTenantChannelResult = {
    channelId: CHANNEL_ID,
    unsignedFundingTx: {
        version: 0,
        cellDeps: [
            {
                outPoint: { txHash: hexToBytes("d8ef9125d4bc98b9c3716fcf61110e302098a55222a2e79344a8264352fe7b9d"), index: 0 },
                depType: "dep_group",
            },
        ],
        headerDeps: [],
        inputs: [
            {
                since: 0n,
                previousOutput: { txHash: hexToBytes("89dc569f9eec0e82ca13a353be098d150e9164d79f9c5201079e422a283c8ee4"), index: 1 },
            },
            {
                since: 0n,
                previousOutput: { txHash: hexToBytes("ba99565f43b9baad46715753a94028906c73fdc052418acd24e473aebd15d47d"), index: 0 },
            },
        ],
        outputs: [
            {
                capacityShannons: 100_500_000_000n,
                lock: { codeHash: hexToBytes(TESTNET_FUNDING_LOCK_CODE_HASH), hashType: "type", args: hexToBytes(FUNDING_LOCK_ARGS) },
                type: null,
            },
            { capacityShannons: 10_000_000_000n, lock: USER_LOCK, type: null },
            { capacityShannons: 100_000_000_000n, lock: PEER_LOCK, type: null },
        ],
        outputsData: [new Uint8Array(0), new Uint8Array(0), new Uint8Array(0)],
        witnesses: [new Uint8Array(85), new Uint8Array(85)],
    },
    openingContext: {
        remoteFundingKey: hexToBytes(PEER_FUNDING_PUBKEY),
        remoteSettlementKey: hexToBytes(PEER_TLC_BASE_PUBKEY),
        remoteShutdownScript: PEER_LOCK,
        commitmentDelayEpoch: 0x10000000001n,
        commitmentFeeRate: 1000n,
        localAmountShannons: "72000000000",
        remoteAmountShannons: "28500000000",
        localReservedCkbShannons: "10000000000",
        remoteReservedCkbShannons: "10000000000",
    },
};

const PINS = {
    terms: {
        commitmentFeeRate: 1000n,
        remoteReservedCkbShannons: "10000000000",
        liquidCapacityShannons: "80500000000",
        remoteCloseScript: PEER_LOCK,
        remoteFundingPubkey: hexToBytes(PEER_FUNDING_PUBKEY),
        remoteTlcBasePubkey: hexToBytes(PEER_TLC_BASE_PUBKEY),
        commitmentDelayEpoch: 0x10000000001n,
    },
    fundingCapacityShannons: "100500000000",
};

function openingRejected(field: string, detail: string): SdkError {
    return new SdkError("opening_rejected", `the node's opening is refused: ${field} ${detail}`);
}

function withFields(answer: OpenTenantChannelResult, fields: [string, unknown][]): OpenTenantChannelResult {
    return fields.reduce((current, [path, value]) => withField(current, path, value), answer);
}

describe("checkTenantOpening", () => {
    it("accepts the node's answer to what was asked, returning the terms and the funding cell's capacity to pin", () => {
        expect(checkTenantOpening(REQUEST, ANSWER)).toStrictEqual(PINS);
    });

    it("returns keys and a close script of its own: writing to the answer afterwards changes nothing it returned", () => {
        const answer = structuredClone(ANSWER);
        const pins = checkTenantOpening(REQUEST, answer);
        answer.openingContext.remoteFundingKey.fill(0);
        answer.openingContext.remoteSettlementKey.fill(0);
        answer.openingContext.remoteShutdownScript.codeHash.fill(0);
        answer.openingContext.remoteShutdownScript.args.fill(0);
        expect(pins).toStrictEqual(PINS);
    });

    it("accepts both reserves under the legacy layout, the liquid capacity growing by both differences", () => {
        const answer = withFields(ANSWER, [
            ["openingContext.localReservedCkbShannons", "9900000000"],
            ["openingContext.remoteReservedCkbShannons", "9900000000"],
        ]);
        expect(checkTenantOpening(REQUEST, answer)).toStrictEqual({
            terms: { ...PINS.terms, remoteReservedCkbShannons: "9900000000", liquidCapacityShannons: "80700000000" },
            fundingCapacityShannons: "100500000000",
        });
    });

    it("accepts one reserve under either layout when a script's args are as long as both layouts' lock args, pinning each side's own", () => {
        const longLock = { ...PEER_LOCK, args: new Uint8Array(58).fill(0x8f) };
        // 8 + 32 + 1 + 58 bytes, then the shutdown fee: one value under both layouts.
        const answer = withFields(ANSWER, [
            ["openingContext.remoteShutdownScript", longLock],
            ["openingContext.localReservedCkbShannons", "9900000000"],
            ["openingContext.remoteReservedCkbShannons", "10000000000"],
        ]);
        expect(checkTenantOpening(REQUEST, answer)).toStrictEqual({
            terms: {
                ...PINS.terms,
                remoteReservedCkbShannons: "10000000000",
                liquidCapacityShannons: "80600000000",
                remoteCloseScript: longLock,
            },
            fundingCapacityShannons: "100500000000",
        });
    });

    it.each([
        ["legacy", "9900000000", "80600000000"],
        ["full payment hash", "10000000000", "80500000000"],
    ])(
        "accepts the peer's reserve under the %s layout when the user's lock args are as long as both layouts' lock args",
        (_, reserve, liquid) => {
            // 8 + 32 + 1 + 58 bytes, then the shutdown fee: the device's reserve is one value under both layouts.
            const request = { ...REQUEST, userLock: { ...USER_LOCK, args: new Uint8Array(58).fill(0x8d) } };
            const answer = withFields(ANSWER, [
                ["openingContext.localReservedCkbShannons", "10000000000"],
                ["openingContext.remoteReservedCkbShannons", reserve],
            ]);
            expect(checkTenantOpening(request, answer)).toStrictEqual({
                terms: { ...PINS.terms, remoteReservedCkbShannons: reserve, liquidCapacityShannons: liquid },
                fundingCapacityShannons: "100500000000",
            });
        },
    );

    it("accepts a peer that brings exactly its reserve", () => {
        const answer = withFields(ANSWER, [
            ["openingContext.remoteAmountShannons", "10000000000"],
            ["unsignedFundingTx.outputs[0].capacityShannons", 82_000_000_000n],
        ]);
        expect(checkTenantOpening(REQUEST, answer)).toStrictEqual({
            terms: { ...PINS.terms, liquidCapacityShannons: "62000000000" },
            fundingCapacityShannons: "82000000000",
        });
    });

    it("accepts a device that funds exactly its reserve", () => {
        const request = { ...REQUEST, fundedShannons: "10000000000" };
        const answer = withFields(ANSWER, [
            ["openingContext.localAmountShannons", "10000000000"],
            ["unsignedFundingTx.outputs[0].capacityShannons", 38_500_000_000n],
        ]);
        expect(checkTenantOpening(request, answer).terms.liquidCapacityShannons).toBe("18500000000");
    });

    it("accepts a funding cell of a u64's whole capacity", () => {
        const remote = UINT64_MAX - 72_000_000_000n;
        const answer = withFields(ANSWER, [
            ["openingContext.remoteAmountShannons", remote.toString()],
            ["unsignedFundingTx.outputs[0].capacityShannons", UINT64_MAX],
        ]);
        expect(checkTenantOpening(REQUEST, answer).fundingCapacityShannons).toBe(UINT64_MAX.toString());
    });

    it("judges no output but the funding cell, which may be followed by either party's change of any kind", () => {
        const answer = withFields(ANSWER, [
            ["unsignedFundingTx.outputs[1].type", PEER_LOCK],
            ["unsignedFundingTx.outputs[2].lock", USER_LOCK],
            ["unsignedFundingTx.outputsData[1]", Uint8Array.of(1, 2, 3)],
            ["unsignedFundingTx.outputsData[2]", undefined],
        ]);
        expect(
            checkTenantOpening(REQUEST, withField(answer, "unsignedFundingTx.outputs[3]", answer.unsignedFundingTx.outputs[1])),
        ).toStrictEqual(PINS);
    });

    it("accepts the funding lock's args whichever key sorts first", () => {
        const request = { ...REQUEST, fundingPubkey: hexToBytes(PEER_FUNDING_PUBKEY) };
        const answer = withField(ANSWER, "openingContext.remoteFundingKey", hexToBytes(DEVICE_FUNDING_PUBKEY));
        expect(checkTenantOpening(request, answer).terms.remoteFundingPubkey).toEqual(hexToBytes(DEVICE_FUNDING_PUBKEY));
    });

    describe("refuses", () => {
        it.each<[string, [string, unknown][], SdkError]>([
            [
                "another channel id",
                [["channelId", "0x41958bba3ff2755c67fb5d290a10f5b655a836c59124908a3bc5e7561e1f98bb"]],
                openingRejected(
                    "channelId",
                    `0x41958bba3ff2755c67fb5d290a10f5b655a836c59124908a3bc5e7561e1f98bb is not ${CHANNEL_ID}, the id of the two TLC base keys`,
                ),
            ],
            [
                "the id of the device's funding key in place of its TLC base key",
                [["channelId", FUNDING_KEY_CHANNEL_ID]],
                openingRejected("channelId", `${FUNDING_KEY_CHANNEL_ID} is not ${CHANNEL_ID}, the id of the two TLC base keys`),
            ],
            [
                "a settlement key off the curve",
                [["openingContext.remoteSettlementKey", OFF_CURVE_KEY]],
                openingRejected("openingContext.remoteSettlementKey", "is not a compressed point on secp256k1"),
            ],
            [
                "a settlement key under the uncompressed prefix",
                [["openingContext.remoteSettlementKey", Uint8Array.of(0x04, ...hexToBytes(PEER_TLC_BASE_PUBKEY).subarray(1))]],
                openingRejected("openingContext.remoteSettlementKey", "is not a compressed point on secp256k1"),
            ],
            [
                "the device's own TLC base key as the settlement key",
                [["openingContext.remoteSettlementKey", hexToBytes(DEVICE_TLC_BASE_PUBKEY)]],
                openingRejected("openingContext.remoteSettlementKey", "is the device's own TLC base key"),
            ],
            [
                "a delay one below the one asked",
                [["openingContext.commitmentDelayEpoch", 0x10000000000n]],
                openingRejected("openingContext.commitmentDelayEpoch", "is 1099511627776, not the 1099511627777 asked"),
            ],
            [
                "a delay one above the one asked",
                [["openingContext.commitmentDelayEpoch", 0x10000000002n]],
                openingRejected("openingContext.commitmentDelayEpoch", "is 1099511627778, not the 1099511627777 asked"),
            ],
            [
                "a fee rate one below the one asked",
                [["openingContext.commitmentFeeRate", 999n]],
                openingRejected("openingContext.commitmentFeeRate", "is 999, not the 1000 asked"),
            ],
            [
                "a fee rate one above the one asked",
                [["openingContext.commitmentFeeRate", 1001n]],
                openingRejected("openingContext.commitmentFeeRate", "is 1001, not the 1000 asked"),
            ],
            [
                "a local amount one below the funded one",
                [["openingContext.localAmountShannons", "71999999999"]],
                openingRejected("openingContext.localAmountShannons", "is 71999999999, not the 72000000000 funded"),
            ],
            [
                "a local amount one above the funded one",
                [["openingContext.localAmountShannons", "72000000001"]],
                openingRejected("openingContext.localAmountShannons", "is 72000000001, not the 72000000000 funded"),
            ],
            [
                "a local reserve one below the device's",
                [["openingContext.localReservedCkbShannons", "9999999999"]],
                openingRejected(
                    "openingContext.localReservedCkbShannons",
                    "9999999999 is not the device's reserve over its lock under either layout",
                ),
            ],
            [
                "a local reserve one above the device's",
                [["openingContext.localReservedCkbShannons", "10000000001"]],
                openingRejected(
                    "openingContext.localReservedCkbShannons",
                    "10000000001 is not the device's reserve over its lock under either layout",
                ),
            ],
            [
                "a local reserve of nothing",
                [["openingContext.localReservedCkbShannons", "0"]],
                openingRejected(
                    "openingContext.localReservedCkbShannons",
                    "0 is not the device's reserve over its lock under either layout",
                ),
            ],
            [
                "a remote reserve one below the peer's",
                [["openingContext.remoteReservedCkbShannons", "9999999999"]],
                openingRejected(
                    "openingContext.remoteReservedCkbShannons",
                    "9999999999 is not the peer's reserve over its shutdown script under the device's layout",
                ),
            ],
            [
                "a remote reserve one above the peer's",
                [["openingContext.remoteReservedCkbShannons", "10000000001"]],
                openingRejected(
                    "openingContext.remoteReservedCkbShannons",
                    "10000000001 is not the peer's reserve over its shutdown script under the device's layout",
                ),
            ],
            [
                "a legacy local reserve with a full payment hash remote one",
                [["openingContext.localReservedCkbShannons", "9900000000"]],
                openingRejected(
                    "openingContext.remoteReservedCkbShannons",
                    "10000000000 is not the peer's reserve over its shutdown script under the device's layout",
                ),
            ],
            [
                "a full payment hash local reserve with a legacy remote one",
                [["openingContext.remoteReservedCkbShannons", "9900000000"]],
                openingRejected(
                    "openingContext.remoteReservedCkbShannons",
                    "9900000000 is not the peer's reserve over its shutdown script under the device's layout",
                ),
            ],
            [
                "a peer that brings one shannon less than its reserve",
                [
                    ["openingContext.remoteAmountShannons", "9999999999"],
                    ["unsignedFundingTx.outputs[0].capacityShannons", 81_999_999_999n],
                ],
                openingRejected("openingContext.remoteAmountShannons", "9999999999 is below the peer's reserve 10000000000"),
            ],
            [
                "a funding cell that is missing",
                [
                    ["unsignedFundingTx.outputs", []],
                    ["unsignedFundingTx.outputsData", []],
                ],
                openingRejected("unsignedFundingTx.outputs[0]", "is missing"),
            ],
            [
                "a funding cell with a type",
                [["unsignedFundingTx.outputs[0].type", PEER_LOCK]],
                openingRejected("unsignedFundingTx.outputs[0].type", "is not null"),
            ],
            [
                "a funding cell without its data",
                [["unsignedFundingTx.outputsData", []]],
                openingRejected("unsignedFundingTx.outputsData[0]", "is missing"),
            ],
            [
                "a funding cell with one byte of data",
                [["unsignedFundingTx.outputsData[0]", Uint8Array.of(0)]],
                openingRejected("unsignedFundingTx.outputsData[0]", "is not empty"),
            ],
            [
                "a remote funding key off the curve",
                [["openingContext.remoteFundingKey", OFF_CURVE_KEY]],
                openingRejected("openingContext.remoteFundingKey", "is not a compressed point on secp256k1"),
            ],
            [
                "the device's own funding key as the remote one",
                [["openingContext.remoteFundingKey", hexToBytes(DEVICE_FUNDING_PUBKEY)]],
                openingRejected("openingContext.remoteFundingKey", "is the device's own funding key"),
            ],
            [
                "the mainnet funding lock",
                [["unsignedFundingTx.outputs[0].lock.codeHash", hexToBytes(MAINNET_FUNDING_LOCK_CODE_HASH)]],
                openingRejected("unsignedFundingTx.outputs[0].lock", "is not the network's funding lock over the two funding keys"),
            ],
            [
                "the commitment lock",
                [["unsignedFundingTx.outputs[0].lock.codeHash", hexToBytes(TESTNET_COMMITMENT_LOCK_CODE_HASH)]],
                openingRejected("unsignedFundingTx.outputs[0].lock", "is not the network's funding lock over the two funding keys"),
            ],
            [
                "the funding lock under another hash type",
                [["unsignedFundingTx.outputs[0].lock.hashType", "data1"]],
                openingRejected("unsignedFundingTx.outputs[0].lock", "is not the network's funding lock over the two funding keys"),
            ],
            [
                "the args of another funding key",
                [["unsignedFundingTx.outputs[0].lock.args", hexToBytes(OTHER_FUNDING_LOCK_ARGS)]],
                openingRejected("unsignedFundingTx.outputs[0].lock", "is not the network's funding lock over the two funding keys"),
            ],
            [
                "the args with one more byte",
                [["unsignedFundingTx.outputs[0].lock.args", hexToBytes(`${FUNDING_LOCK_ARGS}00`)]],
                openingRejected("unsignedFundingTx.outputs[0].lock", "is not the network's funding lock over the two funding keys"),
            ],
            [
                "no args",
                [["unsignedFundingTx.outputs[0].lock.args", new Uint8Array(0)]],
                openingRejected("unsignedFundingTx.outputs[0].lock", "is not the network's funding lock over the two funding keys"),
            ],
            [
                "two amounts one past a u64",
                [
                    ["openingContext.remoteAmountShannons", (UINT64_MAX - 72_000_000_000n + 1n).toString()],
                    ["unsignedFundingTx.outputs[0].capacityShannons", UINT64_MAX],
                ],
                openingRejected("openingContext.remoteAmountShannons", "takes the two amounts to 18446744073709551616, past a cell's u64"),
            ],
            [
                "a funding cell one shannon short of the two amounts",
                [["unsignedFundingTx.outputs[0].capacityShannons", 100_499_999_999n]],
                openingRejected(
                    "unsignedFundingTx.outputs[0].capacityShannons",
                    "is 100499999999, not the 100500000000 of the two amounts",
                ),
            ],
            [
                "a funding cell one shannon past the two amounts",
                [["unsignedFundingTx.outputs[0].capacityShannons", 100_500_000_001n]],
                openingRejected(
                    "unsignedFundingTx.outputs[0].capacityShannons",
                    "is 100500000001, not the 100500000000 of the two amounts",
                ),
            ],
        ])("%s", (_, fields, error) => {
            const thrown = sdkRefusal(() => checkTenantOpening(REQUEST, withFields(ANSWER, fields)));
            expect(thrown).toMatchObject({ code: "opening_rejected", message: error.message });
        });

        it("a device that funds one shannon less than its reserve", () => {
            const request = { ...REQUEST, fundedShannons: "9999999999" };
            const answer = withFields(ANSWER, [
                ["openingContext.localAmountShannons", "9999999999"],
                ["unsignedFundingTx.outputs[0].capacityShannons", 38_499_999_999n],
            ]);
            expect(() => checkTenantOpening(request, answer)).toThrow(
                openingRejected("openingContext.localAmountShannons", "9999999999 is below the device's reserve 10000000000"),
            );
        });

        it("an answer for another network's funding lock", () => {
            const request = {
                ...REQUEST,
                fundingLock: { codeHash: hexToBytes(MAINNET_FUNDING_LOCK_CODE_HASH), hashType: "type" as const },
            };
            expect(() => checkTenantOpening(request, ANSWER)).toThrow(
                openingRejected("unsignedFundingTx.outputs[0].lock", "is not the network's funding lock over the two funding keys"),
            );
        });
    });

    it("checks in order: an answer wrong everywhere names each field as the ones before it are put right", () => {
        const faults: [string, [string, unknown][]][] = [
            ["channelId", [["channelId", FUNDING_KEY_CHANNEL_ID]]],
            ["openingContext.commitmentDelayEpoch", [["openingContext.commitmentDelayEpoch", 0x10000000002n]]],
            ["openingContext.commitmentFeeRate", [["openingContext.commitmentFeeRate", 1001n]]],
            ["openingContext.localAmountShannons", [["openingContext.localAmountShannons", "72000000001"]]],
            ["openingContext.localReservedCkbShannons", [["openingContext.localReservedCkbShannons", "10000000001"]]],
            ["openingContext.remoteReservedCkbShannons", [["openingContext.remoteReservedCkbShannons", "10000000001"]]],
            ["openingContext.remoteAmountShannons", [["openingContext.remoteAmountShannons", "9999999999"]]],
            ["unsignedFundingTx.outputs[0].type", [["unsignedFundingTx.outputs[0].type", PEER_LOCK]]],
            ["unsignedFundingTx.outputsData[0]", [["unsignedFundingTx.outputsData[0]", Uint8Array.of(0)]]],
            ["openingContext.remoteFundingKey", [["openingContext.remoteFundingKey", OFF_CURVE_KEY]]],
            ["unsignedFundingTx.outputs[0].lock", [["unsignedFundingTx.outputs[0].lock.hashType", "data1"]]],
            ["unsignedFundingTx.outputs[0].capacityShannons", [["unsignedFundingTx.outputs[0].capacityShannons", 1n]]],
        ];
        faults.forEach(([field], index) => {
            const answer = withFields(
                ANSWER,
                faults.slice(index).flatMap(([, fields]) => fields),
            );
            const thrown = sdkRefusal(() => checkTenantOpening(REQUEST, answer));
            expect(thrown).toMatchObject({ code: "opening_rejected", message: expect.stringContaining(`refused: ${field} `) });
        });
    });
});
