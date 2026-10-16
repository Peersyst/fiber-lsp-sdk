import { hexToBytes } from "@noble/hashes/utils.js";
import type { Script } from "../../../src/common";
import type {
    ChannelOpenSignerMaterial,
    OpenChannelWithExternalFundingParams,
    OpenTenantChannelParams,
    ShutdownChannelParams,
    SubmitSignedFundingTxParams,
} from "../../../src/rpc";
import {
    FiberRpcClient,
    RPC_CHANNEL_STATE_FLAGS,
    RpcError,
    RpcResponseError,
    decodeAbandonChannelResult,
    decodeListChannelsResult,
    decodeOpenChannelWithExternalFundingResult,
    decodeOpenTenantChannelResult,
    decodeRpcChannelState,
    decodeShutdownChannelResult,
    decodeSubmitSignedFundingTxResult,
    encodeListChannelsParams,
    encodeOpenChannelWithExternalFundingParams,
    encodeOpenTenantChannelParams,
    encodeShutdownChannelParams,
    encodeSubmitSignedFundingTxParams,
} from "../../../src/rpc";
import { FetchMock } from "../../mocks/rpc";
import { caseOf } from "../../utils/interop-vectors";
import { refusal } from "../../utils/refusal";
import { rejection } from "../../utils/rejection";
import { RPC_RESULT_PATH as RESULT, answering, refusing, resultField as result, sent } from "../../utils/rpc-answers";
import {
    toChannel,
    toChannelState,
    toOpenChannelWithExternalFundingResult,
    toOpenTenantChannelParams,
    toOpenTenantChannelResult,
    toShutdownChannelParams,
    toSubmitSignedFundingTxParams,
    toSubmitSignedFundingTxResult,
    withoutNulls,
} from "../../utils/rpc-typed";
import { loadRpcVectors } from "../../utils/rpc-vectors";
import { ABOVE_U64, ABOVE_U128, U64_MAX_HEX, U128_MAX_HEX } from "../../utils/uint-hex";
import { withField } from "../../utils/with-field";

const vectors = loadRpcVectors();
const {
    open_channel_with_external_funding: open,
    submit_signed_funding_tx: submit,
    list_channels: list,
    open_tenant_channel: openTenant,
    shutdown_channel: shutdown,
} = vectors.methods;

const CHANNEL_ID = `0x${"11".repeat(32)}`;
const PEER = `02${"ab".repeat(32)}`;

const SHUTDOWN: Script = { codeHash: hexToBytes("9b".repeat(32)), hashType: "type", args: hexToBytes("42".repeat(20)) };
const FUNDING_LOCK: Script = { codeHash: hexToBytes("9b".repeat(32)), hashType: "type", args: hexToBytes("75".repeat(20)) };

const OPEN: OpenChannelWithExternalFundingParams = {
    peerPubkey: hexToBytes(PEER),
    fundingAmountShannons: "16000000000",
    public: false,
    shutdownScript: SHUTDOWN,
    fundingLockScript: FUNDING_LOCK,
};

const READY_CHANNEL = {
    channel_id: CHANNEL_ID,
    is_public: true,
    is_acceptor: false,
    is_one_way: false,
    channel_outpoint: `0x${"a3".repeat(36)}`,
    pubkey: PEER,
    funding_udt_type_script: null,
    state: { state_name: "ChannelReady" },
    local_balance: "0x12a05f200",
    offered_tlc_balance: "0x0",
    remote_balance: "0x3b9aca00",
    received_tlc_balance: "0x8f0d180",
    pending_tlcs: [],
    latest_commitment_transaction_hash: `0x${"66".repeat(32)}`,
    created_at: "0x191dd9dec00",
    enabled: true,
    tlc_expiry_delta: "0x5265c00",
    tlc_fee_proportional_millionths: "0x3e8",
    shutdown_transaction_hash: null,
    failure_detail: null,
};

const CLOSED_CHANNEL = {
    ...READY_CHANNEL,
    state: { state_name: "Closed", state_flags: "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT" },
    shutdown_transaction_hash: `0x${"5d".repeat(32)}`,
};

// A failed opening as `only_pending` synthesizes it: unfunded, told from a timeout by its detail alone.
const ABORTED_CHANNEL = {
    ...READY_CHANNEL,
    is_public: false,
    channel_outpoint: null,
    state: { state_name: "Closed", state_flags: "FUNDING_ABORTED" },
    remote_balance: "0x0",
    received_tlc_balance: "0x0",
    latest_commitment_transaction_hash: null,
    enabled: false,
    tlc_expiry_delta: "0x0",
    tlc_fee_proportional_millionths: "0x0",
    failure_detail: "Channel was abandoned",
};

const LISTING = { channels: [READY_CHANNEL, CLOSED_CHANNEL, ABORTED_CHANNEL] };

const FUNDING_PUBKEY = `02${"c1".repeat(32)}`;
const TLC_BASE_KEY = `03${"c2".repeat(32)}`;
const FIRST_POINT = `02${"c3".repeat(32)}`;
const SECOND_POINT = `03${"c4".repeat(32)}`;
const COMMITMENT_NONCE = `02${"d1".repeat(32)}03${"d2".repeat(32)}`;
const NEXT_COMMITMENT_NONCE = `02${"d3".repeat(32)}03${"d4".repeat(32)}`;
const REVOCATION_NONCE = `02${"d5".repeat(32)}03${"d6".repeat(32)}`;
const ANNOUNCEMENT_NONCE = `02${"d7".repeat(32)}03${"d8".repeat(32)}`;

const SIGNER_MATERIAL: ChannelOpenSignerMaterial = {
    fundingPubkey: hexToBytes(FUNDING_PUBKEY),
    tlcBaseKey: hexToBytes(TLC_BASE_KEY),
    firstCommitmentPoint: hexToBytes(FIRST_POINT),
    secondCommitmentPoint: hexToBytes(SECOND_POINT),
    commitmentNonce: hexToBytes(COMMITMENT_NONCE),
    nextCommitmentNonce: hexToBytes(NEXT_COMMITMENT_NONCE),
    revocationNonce: hexToBytes(REVOCATION_NONCE),
    channelAnnouncementNonce: null,
};

const SIGNER_MATERIAL_WIRE = {
    base_public_keys: { funding_pubkey: FUNDING_PUBKEY, tlc_base_key: TLC_BASE_KEY },
    first_commitment_point: FIRST_POINT,
    second_commitment_point: SECOND_POINT,
    commitment_nonce: `0x${COMMITMENT_NONCE}`,
    next_commitment_nonce: `0x${NEXT_COMMITMENT_NONCE}`,
    revocation_nonce: `0x${REVOCATION_NONCE}`,
};

const OPEN_TENANT: OpenTenantChannelParams = {
    peerPubkey: hexToBytes(PEER),
    fundingAmountShannons: "16000000000",
    shutdownScript: SHUTDOWN,
    fundingLockScript: FUNDING_LOCK,
    signerMaterial: SIGNER_MATERIAL,
};

const OPENING_CONTEXT = {
    remote_funding_key: `02${"e1".repeat(32)}`,
    remote_settlement_key: `03${"e2".repeat(32)}`,
    remote_shutdown_script: { code_hash: `0x${"9b".repeat(32)}`, hash_type: "type", args: `0x${"e3".repeat(20)}` },
    commitment_delay_epoch: "0x10000000001",
    commitment_fee_rate: "0x3e8",
    local_amount: "0x3b9aca000",
    remote_amount: "0x0",
    local_reserved_ckb_amount: "0x24e160300",
    remote_reserved_ckb_amount: "0x2540be400",
};

const CLOSE_SCRIPT: Script = { codeHash: hexToBytes("9b".repeat(32)), hashType: "type", args: hexToBytes("c5".repeat(20)) };
const CLOSE_SCRIPT_WIRE = { code_hash: `0x${"9b".repeat(32)}`, hash_type: "type", args: `0x${"c5".repeat(20)}` };

describe("open_channel_with_external_funding", () => {
    describe("encodeOpenChannelWithExternalFundingParams", () => {
        it("writes the client's closed subset, the pubkey bare and the amount in hex, leaving every option to the node", () => {
            const wire = encodeOpenChannelWithExternalFundingParams(OPEN);
            expect(wire).toEqual({
                pubkey: PEER,
                funding_amount: "0x3b9aca000",
                public: false,
                shutdown_script: { code_hash: `0x${"9b".repeat(32)}`, hash_type: "type", args: `0x${"42".repeat(20)}` },
                funding_lock_script: { code_hash: `0x${"9b".repeat(32)}`, hash_type: "type", args: `0x${"75".repeat(20)}` },
            });
            expect(Object.keys(wire)).toEqual(["pubkey", "funding_amount", "public", "shutdown_script", "funding_lock_script"]);
        });

        it("always sends public, true included, rather than inheriting fiber's default", () => {
            expect(encodeOpenChannelWithExternalFundingParams({ ...OPEN, public: true }).public).toBe(true);
        });

        it.each<[string, Partial<OpenChannelWithExternalFundingParams>, Error]>([
            ["a pubkey of 32 bytes", { peerPubkey: new Uint8Array(32) }, new TypeError("peerPubkey must be 33 bytes, got 32")],
            ["a pubkey as a string", { peerPubkey: PEER as unknown as Uint8Array }, new TypeError("peerPubkey must be a Uint8Array")],
            [
                "a fractional amount",
                { fundingAmountShannons: "1.0" },
                new TypeError("fundingAmountShannons must be an amount in decimal shannons"),
            ],
            [
                "an amount with a leading zero",
                { fundingAmountShannons: "01" },
                new TypeError("fundingAmountShannons must be an amount in decimal shannons"),
            ],
            [
                "an amount past a u128",
                { fundingAmountShannons: "340282366920938463463374607431768211456" },
                new TypeError("fundingAmountShannons must be an amount in decimal shannons"),
            ],
            ["a public that is not a boolean", { public: "true" as unknown as boolean }, new TypeError("public must be a boolean")],
            [
                "a shutdown script with a short code hash",
                { shutdownScript: { ...SHUTDOWN, codeHash: new Uint8Array(31) } },
                new TypeError("shutdownScript.codeHash must be 32 bytes, got 31"),
            ],
            [
                "a funding lock with an unknown hash type",
                { fundingLockScript: { ...FUNDING_LOCK, hashType: "data3" as Script["hashType"] } },
                new TypeError("fundingLockScript.hashType must be one of data, type, data1, data2"),
            ],
        ])("refuses %s", (_, change, expected) => {
            expect(() => encodeOpenChannelWithExternalFundingParams({ ...OPEN, ...change })).toThrow(expected);
        });
    });

    describe("decodeOpenChannelWithExternalFundingResult", () => {
        it.each(open.results.map((entry) => [entry.name, entry] as const))("reads the %s", (_, entry) => {
            expect(decodeOpenChannelWithExternalFundingResult(result(entry.json))).toEqual(
                toOpenChannelWithExternalFundingResult(entry.values),
            );
        });

        const json = caseOf(open.results, "ckb channel").json;

        it.each([
            ["channel_id", "11".repeat(32)],
            ["channel_id", `0x${"11".repeat(31)}`],
            ["channel_id", undefined],
            ["unsigned_funding_tx", undefined],
            ["unsigned_funding_tx.outputs[0].capacity", "6100000000"],
            ["unsigned_funding_tx.witnesses[0]", "0x5"],
        ])("refuses %s = %p, naming the field from the result", (path, value) => {
            expect(refusal(() => decodeOpenChannelWithExternalFundingResult(result(withField(json, path, value)))).path).toBe(
                `${RESULT}.${path}`,
            );
        });
    });
});

describe("submit_signed_funding_tx", () => {
    describe("encodeSubmitSignedFundingTxParams", () => {
        const params: SubmitSignedFundingTxParams = toSubmitSignedFundingTxParams(caseOf(submit.params, "ckb channel").values);

        it("writes the channel id as it is and the transaction in CKB's shape", () => {
            expect(encodeSubmitSignedFundingTxParams(params)).toEqual(caseOf(submit.params, "ckb channel").json);
        });

        it.each([
            ["a bare channel id", "11".repeat(32)],
            ["an uppercase channel id", `0x${"AA".repeat(32)}`],
            ["a channel id of 31 bytes", `0x${"11".repeat(31)}`],
            ["a padded channel id", `${CHANNEL_ID} `],
        ])("refuses %s", (_, channelId) => {
            expect(() => encodeSubmitSignedFundingTxParams({ ...params, channelId })).toThrow(
                new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
            );
        });

        it("refuses a transaction it cannot write, naming the field", () => {
            const signedFundingTx = withField(params.signedFundingTx, "outputs[0].lock.codeHash", new Uint8Array(31));
            expect(() => encodeSubmitSignedFundingTxParams({ ...params, signedFundingTx })).toThrow(
                new TypeError("signedFundingTx.outputs[0].lock.codeHash must be 32 bytes, got 31"),
            );
        });
    });

    describe("decodeSubmitSignedFundingTxResult", () => {
        it.each(submit.results.map((entry) => [entry.name, entry] as const))("reads the %s", (_, entry) => {
            expect(decodeSubmitSignedFundingTxResult(result(entry.json))).toEqual(toSubmitSignedFundingTxResult(entry.values));
        });

        const json = caseOf(submit.results, "submitted").json;

        it.each([
            ["channel_id", "11".repeat(32)],
            ["channel_id", undefined],
            ["funding_tx_hash", `0x${"c1".repeat(31)}`],
            ["funding_tx_hash", null],
        ])("refuses %s = %p", (path, value) => {
            expect(refusal(() => decodeSubmitSignedFundingTxResult(result(withField(json, path, value)))).path).toBe(`${RESULT}.${path}`);
        });

        it("refuses a result that is not an object", () => {
            expect(refusal(() => decodeSubmitSignedFundingTxResult(result(null))).path).toBe(RESULT);
        });
    });
});

describe("abandon_channel", () => {
    it.each(vectors.methods.abandon_channel.results.map((entry) => [entry.name, entry] as const))("reads the %s null", (_, entry) => {
        expect(decodeAbandonChannelResult(result(entry.json))).toBeUndefined();
    });

    it.each([{}, undefined, true, "null"])("refuses %p", (value) => {
        expect(refusal(() => decodeAbandonChannelResult(result(value))).message).toBe(`${RESULT} must be null`);
    });
});

describe("list_channels", () => {
    describe("encodeListChannelsParams", () => {
        it("sends nothing for the default mode, and the one flag of a filter", () => {
            expect(encodeListChannelsParams({})).toEqual({});
            expect(encodeListChannelsParams({ filter: "include_closed" })).toEqual({ include_closed: true });
            expect(encodeListChannelsParams({ filter: "only_pending" })).toEqual({ only_pending: true });
        });

        it("refuses a filter fiber has no flag for", () => {
            expect(() => encodeListChannelsParams({ filter: "closed" as "include_closed" })).toThrow(
                new TypeError("filter must be one of include_closed, only_pending"),
            );
        });
    });

    describe("decodeListChannelsResult", () => {
        it.each(list.results.map((entry) => [entry.name, entry] as const))("reads the %s listing", (_, entry) => {
            expect(decodeListChannelsResult(result(entry.json))).toEqual(entry.values.channels.map(toChannel));
        });

        it("reads a literal listing field by field", () => {
            expect(decodeListChannelsResult(result(LISTING))).toEqual([
                {
                    channelId: CHANNEL_ID,
                    peerPubkey: hexToBytes(PEER),
                    fundingUdtTypeScript: null,
                    state: { name: "ChannelReady", flags: [] },
                    localBalanceShannons: "5000000000",
                    remoteBalanceShannons: "1000000000",
                    offeredTlcBalanceShannons: "0",
                    receivedTlcBalanceShannons: "150000000",
                    createdAtMs: 1726000000000n,
                    shutdownTransactionHash: null,
                    failureDetail: null,
                },
                {
                    channelId: CHANNEL_ID,
                    peerPubkey: hexToBytes(PEER),
                    fundingUdtTypeScript: null,
                    state: { name: "Closed", flags: ["UNCOOPERATIVE_LOCAL", "WAITING_ONCHAIN_SETTLEMENT"] },
                    localBalanceShannons: "5000000000",
                    remoteBalanceShannons: "1000000000",
                    offeredTlcBalanceShannons: "0",
                    receivedTlcBalanceShannons: "150000000",
                    createdAtMs: 1726000000000n,
                    shutdownTransactionHash: hexToBytes("5d".repeat(32)),
                    failureDetail: null,
                },
                {
                    channelId: CHANNEL_ID,
                    peerPubkey: hexToBytes(PEER),
                    fundingUdtTypeScript: null,
                    state: { name: "Closed", flags: ["FUNDING_ABORTED"] },
                    localBalanceShannons: "5000000000",
                    remoteBalanceShannons: "0",
                    offeredTlcBalanceShannons: "0",
                    receivedTlcBalanceShannons: "0",
                    createdAtMs: 1726000000000n,
                    shutdownTransactionHash: null,
                    failureDetail: "Channel was abandoned",
                },
            ]);
        });

        it("reads the largest balance and timestamp", () => {
            const [channel] = decodeListChannelsResult(
                result({ channels: [{ ...READY_CHANNEL, local_balance: U128_MAX_HEX, created_at: U64_MAX_HEX }] }),
            );
            expect(channel?.localBalanceShannons).toBe("340282366920938463463374607431768211455");
            expect(channel?.createdAtMs).toBe(2n ** 64n - 1n);
        });

        it("ignores the members it does not read, even malformed", () => {
            const loose = { ...READY_CHANNEL, pending_tlcs: "x", is_public: 1, channel_outpoint: 5, enabled: null, extra: {} };
            expect(decodeListChannelsResult(result({ channels: [loose] }))).toEqual(
                decodeListChannelsResult(result({ channels: [READY_CHANNEL] })),
            );
        });

        it.each([
            ["channels", undefined],
            ["channels", {}],
            ["channels[1]", "channel"],
            ["channels[0].channel_id", "11".repeat(32)],
            ["channels[0].channel_id", `0x${"11".repeat(31)}`],
            ["channels[0].channel_id", undefined],
            ["channels[0].pubkey", `0x${PEER}`],
            ["channels[0].pubkey", PEER.slice(2)],
            ["channels[0].pubkey", PEER.toUpperCase()],
            ["channels[0].pubkey", undefined],
            ["channels[0].funding_udt_type_script", undefined],
            ["channels[0].funding_udt_type_script", "0x"],
            ["channels[0].state", undefined],
            ["channels[0].state.state_name", "Opened"],
            ["channels[0].state.state_name", "channel_ready"],
            ["channels[0].state.state_name", undefined],
            ["channels[0].state.state_flags", ""],
            ["channels[0].state.state_flags", null],
            ["channels[0].state.state_flags", "CHANNEL_READY"],
            ["channels[1].state.state_flags", undefined],
            ["channels[1].state.state_flags", null],
            ["channels[1].state.state_flags", "COOPERATIVE|OUR_SHUTDOWN_SENT"],
            ["channels[1].state.state_flags", "COOPERATIVE|COOPERATIVE"],
            ["channels[1].state.state_flags", "ABANDONED|"],
            ["channels[0].local_balance", "5000000000"],
            ["channels[0].local_balance", "0x012a05f200"],
            ["channels[0].local_balance", ABOVE_U128],
            ["channels[0].local_balance", 5000000000],
            ["channels[0].remote_balance", undefined],
            ["channels[0].offered_tlc_balance", "0"],
            ["channels[0].received_tlc_balance", null],
            ["channels[0].created_at", ABOVE_U64],
            ["channels[0].created_at", "1726000000000"],
            ["channels[0].created_at", undefined],
            ["channels[0].shutdown_transaction_hash", undefined],
            ["channels[1].shutdown_transaction_hash", "5d".repeat(32)],
            ["channels[1].shutdown_transaction_hash", `0x${"5d".repeat(31)}`],
            ["channels[0].failure_detail", undefined],
            ["channels[2].failure_detail", 1],
        ])("refuses %s = %p, naming the field from the result", (path, value) => {
            expect(refusal(() => decodeListChannelsResult(result(withField(LISTING, path, value)))).path).toBe(`${RESULT}.${path}`);
        });

        it("refuses a result that is not an object", () => {
            expect(refusal(() => decodeListChannelsResult(result([READY_CHANNEL]))).message).toBe(`${RESULT} must be an object`);
        });
    });
});

describe("open_tenant_channel", () => {
    describe("encodeOpenTenantChannelParams", () => {
        it("writes the open's five members, public always false, and the material, leaving the two options to the node", () => {
            const wire = encodeOpenTenantChannelParams(OPEN_TENANT);
            expect(wire).toEqual({
                pubkey: PEER,
                funding_amount: "0x3b9aca000",
                public: false,
                shutdown_script: { code_hash: `0x${"9b".repeat(32)}`, hash_type: "type", args: `0x${"42".repeat(20)}` },
                funding_lock_script: { code_hash: `0x${"9b".repeat(32)}`, hash_type: "type", args: `0x${"75".repeat(20)}` },
                external_channel_signer: SIGNER_MATERIAL_WIRE,
            });
            expect(Object.keys(wire)).toEqual([
                "pubkey",
                "funding_amount",
                "public",
                "shutdown_script",
                "funding_lock_script",
                "external_channel_signer",
            ]);
            expect(Object.keys(wire.external_channel_signer)).toEqual([
                "base_public_keys",
                "first_commitment_point",
                "second_commitment_point",
                "commitment_nonce",
                "next_commitment_nonce",
                "revocation_nonce",
            ]);
        });

        it("writes the delay, the fee rate and the announcement nonce when given, in fiber's order", () => {
            const wire = encodeOpenTenantChannelParams({
                ...OPEN_TENANT,
                commitmentDelayEpoch: 0x10000000001n,
                commitmentFeeRate: 1000n,
                signerMaterial: { ...SIGNER_MATERIAL, channelAnnouncementNonce: hexToBytes(ANNOUNCEMENT_NONCE) },
            });
            expect(wire).toMatchObject({
                commitment_delay_epoch: "0x10000000001",
                commitment_fee_rate: "0x3e8",
                external_channel_signer: { ...SIGNER_MATERIAL_WIRE, channel_announcement_nonce: `0x${ANNOUNCEMENT_NONCE}` },
            });
            expect(Object.keys(wire)).toEqual([
                "pubkey",
                "funding_amount",
                "public",
                "shutdown_script",
                "funding_lock_script",
                "commitment_delay_epoch",
                "commitment_fee_rate",
                "external_channel_signer",
            ]);
            expect(Object.keys(wire.external_channel_signer).at(-1)).toBe("channel_announcement_nonce");
        });

        it("writes each option on its own", () => {
            expect(Object.keys(encodeOpenTenantChannelParams({ ...OPEN_TENANT, commitmentDelayEpoch: 1n }))).toContain(
                "commitment_delay_epoch",
            );
            expect(Object.keys(encodeOpenTenantChannelParams({ ...OPEN_TENANT, commitmentDelayEpoch: 1n }))).not.toContain(
                "commitment_fee_rate",
            );
            expect(Object.keys(encodeOpenTenantChannelParams({ ...OPEN_TENANT, commitmentFeeRate: 1n }))).toContain("commitment_fee_rate");
            expect(Object.keys(encodeOpenTenantChannelParams({ ...OPEN_TENANT, commitmentFeeRate: 1n }))).not.toContain(
                "commitment_delay_epoch",
            );
        });

        it("writes the bounds of the delay and the fee rate", () => {
            const zero = encodeOpenTenantChannelParams({ ...OPEN_TENANT, commitmentDelayEpoch: 0n, commitmentFeeRate: 0n });
            expect(zero).toMatchObject({ commitment_delay_epoch: "0x0", commitment_fee_rate: "0x0" });
            const max = encodeOpenTenantChannelParams({
                ...OPEN_TENANT,
                commitmentDelayEpoch: 2n ** 64n - 1n,
                commitmentFeeRate: 2n ** 64n - 1n,
            });
            expect(max).toMatchObject({ commitment_delay_epoch: U64_MAX_HEX, commitment_fee_rate: U64_MAX_HEX });
        });

        it("sends public false even when the input carries public true", () => {
            expect(encodeOpenTenantChannelParams({ ...OPEN_TENANT, public: true } as OpenTenantChannelParams).public).toBe(false);
        });

        it.each(openTenant.params.map((entry) => [entry.name, entry] as const))("writes the %s case as fiber's serde does", (_, entry) => {
            expect(encodeOpenTenantChannelParams(toOpenTenantChannelParams(entry.values))).toEqual(withoutNulls(entry.json));
        });

        it.each<[string, Record<string, unknown>, Error]>([
            ["a pubkey of 32 bytes", { peerPubkey: new Uint8Array(32) }, new TypeError("peerPubkey must be 33 bytes, got 32")],
            [
                "a fractional amount",
                { fundingAmountShannons: "1.0" },
                new TypeError("fundingAmountShannons must be an amount in decimal shannons"),
            ],
            [
                "a shutdown script with a short code hash",
                { shutdownScript: { ...SHUTDOWN, codeHash: new Uint8Array(31) } },
                new TypeError("shutdownScript.codeHash must be 32 bytes, got 31"),
            ],
            [
                "a funding lock with an unknown hash type",
                { fundingLockScript: { ...FUNDING_LOCK, hashType: "data3" } },
                new TypeError("fundingLockScript.hashType must be one of data, type, data1, data2"),
            ],
            [
                "a negative delay",
                { commitmentDelayEpoch: -1n },
                new RangeError("commitmentDelayEpoch must be a bigint between 0 and 18446744073709551615, got -1"),
            ],
            [
                "a delay past a u64",
                { commitmentDelayEpoch: 2n ** 64n },
                new RangeError("commitmentDelayEpoch must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
            ],
            [
                "a delay as a number",
                { commitmentDelayEpoch: 1 },
                new RangeError("commitmentDelayEpoch must be a bigint between 0 and 18446744073709551615, got 1"),
            ],
            [
                "a delay given as null",
                { commitmentDelayEpoch: null },
                new RangeError("commitmentDelayEpoch must be a bigint between 0 and 18446744073709551615, got null"),
            ],
            [
                "a negative fee rate",
                { commitmentFeeRate: -1n },
                new RangeError("commitmentFeeRate must be a bigint between 0 and 18446744073709551615, got -1"),
            ],
            [
                "a fee rate past a u64",
                { commitmentFeeRate: 2n ** 64n },
                new RangeError("commitmentFeeRate must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
            ],
            [
                "a fee rate as a string",
                { commitmentFeeRate: "1000" },
                new RangeError("commitmentFeeRate must be a bigint between 0 and 18446744073709551615, got 1000"),
            ],
            [
                "a fee rate given as null",
                { commitmentFeeRate: null },
                new RangeError("commitmentFeeRate must be a bigint between 0 and 18446744073709551615, got null"),
            ],
            ["a missing material", { signerMaterial: undefined }, new TypeError("signerMaterial must be an object")],
            ["a material given as null", { signerMaterial: null }, new TypeError("signerMaterial must be an object")],
            [
                "a funding pubkey of 32 bytes",
                { signerMaterial: { ...SIGNER_MATERIAL, fundingPubkey: new Uint8Array(32) } },
                new TypeError("signerMaterial.fundingPubkey must be 33 bytes, got 32"),
            ],
            [
                "a TLC base key of 34 bytes",
                { signerMaterial: { ...SIGNER_MATERIAL, tlcBaseKey: new Uint8Array(34) } },
                new TypeError("signerMaterial.tlcBaseKey must be 33 bytes, got 34"),
            ],
            [
                "a first point as hex",
                { signerMaterial: { ...SIGNER_MATERIAL, firstCommitmentPoint: FIRST_POINT } },
                new TypeError("signerMaterial.firstCommitmentPoint must be a Uint8Array"),
            ],
            [
                "a second point of 32 bytes",
                { signerMaterial: { ...SIGNER_MATERIAL, secondCommitmentPoint: new Uint8Array(32) } },
                new TypeError("signerMaterial.secondCommitmentPoint must be 33 bytes, got 32"),
            ],
            [
                "a commitment nonce of 65 bytes",
                { signerMaterial: { ...SIGNER_MATERIAL, commitmentNonce: new Uint8Array(65) } },
                new TypeError("signerMaterial.commitmentNonce must be 66 bytes, got 65"),
            ],
            [
                "a next commitment nonce of 67 bytes",
                { signerMaterial: { ...SIGNER_MATERIAL, nextCommitmentNonce: new Uint8Array(67) } },
                new TypeError("signerMaterial.nextCommitmentNonce must be 66 bytes, got 67"),
            ],
            [
                "a revocation nonce of 33 bytes",
                { signerMaterial: { ...SIGNER_MATERIAL, revocationNonce: new Uint8Array(33) } },
                new TypeError("signerMaterial.revocationNonce must be 66 bytes, got 33"),
            ],
            [
                "an announcement nonce of 65 bytes",
                { signerMaterial: { ...SIGNER_MATERIAL, channelAnnouncementNonce: new Uint8Array(65) } },
                new TypeError("signerMaterial.channelAnnouncementNonce must be 66 bytes, got 65"),
            ],
            [
                "a missing announcement nonce, which is null and not absent",
                { signerMaterial: { ...SIGNER_MATERIAL, channelAnnouncementNonce: undefined } },
                new TypeError("signerMaterial.channelAnnouncementNonce must be a Uint8Array"),
            ],
        ])("refuses %s", (_, change, expected) => {
            expect(() => encodeOpenTenantChannelParams({ ...OPEN_TENANT, ...change } as OpenTenantChannelParams)).toThrow(expected);
        });
    });

    describe("decodeOpenTenantChannelResult", () => {
        it.each(openTenant.results.map((entry) => [entry.name, entry] as const))("reads the %s", (_, entry) => {
            expect(decodeOpenTenantChannelResult(result(entry.json))).toEqual(toOpenTenantChannelResult(entry.values));
        });

        const json = caseOf(openTenant.results, "opening context").json as Record<string, unknown>;

        it("reads a literal opening context field by field, the amounts and reserves in decimal shannons", () => {
            expect(decodeOpenTenantChannelResult(result({ ...json, opening_context: OPENING_CONTEXT })).openingContext).toEqual({
                remoteFundingKey: hexToBytes(`02${"e1".repeat(32)}`),
                remoteSettlementKey: hexToBytes(`03${"e2".repeat(32)}`),
                remoteShutdownScript: { codeHash: hexToBytes("9b".repeat(32)), hashType: "type", args: hexToBytes("e3".repeat(20)) },
                commitmentDelayEpoch: 0x10000000001n,
                commitmentFeeRate: 1000n,
                localAmountShannons: "16000000000",
                remoteAmountShannons: "0",
                localReservedCkbShannons: "9900000000",
                remoteReservedCkbShannons: "10000000000",
            });
        });

        it("reads the largest amounts, reserves, delay and fee rate", () => {
            const context = {
                ...OPENING_CONTEXT,
                commitment_delay_epoch: U64_MAX_HEX,
                commitment_fee_rate: U64_MAX_HEX,
                local_amount: U128_MAX_HEX,
                remote_amount: U128_MAX_HEX,
                local_reserved_ckb_amount: U64_MAX_HEX,
                remote_reserved_ckb_amount: U64_MAX_HEX,
            };
            expect(decodeOpenTenantChannelResult(result({ ...json, opening_context: context })).openingContext).toMatchObject({
                commitmentDelayEpoch: 2n ** 64n - 1n,
                commitmentFeeRate: 2n ** 64n - 1n,
                localAmountShannons: "340282366920938463463374607431768211455",
                remoteAmountShannons: "340282366920938463463374607431768211455",
                localReservedCkbShannons: "18446744073709551615",
                remoteReservedCkbShannons: "18446744073709551615",
            });
        });

        it("ignores the members it does not read", () => {
            const loose = { ...json, extra: 1, opening_context: { ...OPENING_CONTEXT, lock_layout: "x" } };
            expect(decodeOpenTenantChannelResult(result(loose))).toEqual(
                decodeOpenTenantChannelResult(result({ ...json, opening_context: OPENING_CONTEXT })),
            );
        });

        it.each([
            ["channel_id", "11".repeat(32)],
            ["channel_id", `0x${"11".repeat(31)}`],
            ["channel_id", undefined],
            ["unsigned_funding_tx", undefined],
            ["unsigned_funding_tx.outputs[0].capacity", "6100000000"],
            ["opening_context", undefined],
            ["opening_context", null],
            ["opening_context", "frozen"],
            ["opening_context.remote_funding_key", `0x02${"e1".repeat(32)}`],
            ["opening_context.remote_funding_key", `02${"e1".repeat(31)}`],
            ["opening_context.remote_funding_key", `02${"E1".repeat(32)}`],
            ["opening_context.remote_funding_key", undefined],
            ["opening_context.remote_funding_key", null],
            ["opening_context.remote_settlement_key", `0x03${"e2".repeat(32)}`],
            ["opening_context.remote_settlement_key", `03${"e2".repeat(33)}`],
            ["opening_context.remote_settlement_key", undefined],
            ["opening_context.remote_shutdown_script", undefined],
            ["opening_context.remote_shutdown_script", null],
            ["opening_context.remote_shutdown_script.code_hash", `0x${"9b".repeat(31)}`],
            ["opening_context.remote_shutdown_script.hash_type", "data3"],
            ["opening_context.remote_shutdown_script.args", "e3".repeat(20)],
            ["opening_context.commitment_delay_epoch", "1099511627777"],
            ["opening_context.commitment_delay_epoch", "0x010000000001"],
            ["opening_context.commitment_delay_epoch", ABOVE_U64],
            ["opening_context.commitment_delay_epoch", 1099511627777],
            ["opening_context.commitment_delay_epoch", undefined],
            ["opening_context.commitment_fee_rate", "1000"],
            ["opening_context.commitment_fee_rate", ABOVE_U64],
            ["opening_context.commitment_fee_rate", undefined],
            ["opening_context.commitment_fee_rate", null],
            ["opening_context.local_amount", "16000000000"],
            ["opening_context.local_amount", ABOVE_U128],
            ["opening_context.local_amount", undefined],
            ["opening_context.remote_amount", 0],
            ["opening_context.remote_amount", undefined],
            ["opening_context.remote_amount", null],
            ["opening_context.local_reserved_ckb_amount", ABOVE_U64],
            ["opening_context.local_reserved_ckb_amount", "9900000000"],
            ["opening_context.local_reserved_ckb_amount", undefined],
            ["opening_context.remote_reserved_ckb_amount", ABOVE_U64],
            ["opening_context.remote_reserved_ckb_amount", undefined],
            ["opening_context.remote_reserved_ckb_amount", null],
        ])("refuses %s = %p, naming the field from the result", (path, value) => {
            const base = { ...json, opening_context: OPENING_CONTEXT };
            expect(refusal(() => decodeOpenTenantChannelResult(result(withField(base, path, value)))).path).toBe(`${RESULT}.${path}`);
        });

        it.each([null, [], "opened"])("refuses the result %p, which is not an object", (value) => {
            expect(refusal(() => decodeOpenTenantChannelResult(result(value))).message).toBe(`${RESULT} must be an object`);
        });
    });
});

describe("shutdown_channel", () => {
    describe("encodeShutdownChannelParams", () => {
        it("writes the channel id alone, leaving the script, the fee rate and the force to the node", () => {
            const wire = encodeShutdownChannelParams({ channelId: CHANNEL_ID });
            expect(wire).toEqual({ channel_id: CHANNEL_ID });
            expect(Object.keys(wire)).toEqual(["channel_id"]);
        });

        it("writes the three options when given, in fiber's order", () => {
            const wire = encodeShutdownChannelParams({ channelId: CHANNEL_ID, closeScript: CLOSE_SCRIPT, feeRate: 1000n, force: true });
            expect(wire).toEqual({ channel_id: CHANNEL_ID, close_script: CLOSE_SCRIPT_WIRE, fee_rate: "0x3e8", force: true });
            expect(Object.keys(wire)).toEqual(["channel_id", "close_script", "fee_rate", "force"]);
        });

        it("writes each option on its own, force false and a zero fee rate included", () => {
            expect(encodeShutdownChannelParams({ channelId: CHANNEL_ID, closeScript: CLOSE_SCRIPT })).toEqual({
                channel_id: CHANNEL_ID,
                close_script: CLOSE_SCRIPT_WIRE,
            });
            expect(encodeShutdownChannelParams({ channelId: CHANNEL_ID, feeRate: 0n })).toEqual({
                channel_id: CHANNEL_ID,
                fee_rate: "0x0",
            });
            expect(encodeShutdownChannelParams({ channelId: CHANNEL_ID, force: false })).toEqual({ channel_id: CHANNEL_ID, force: false });
        });

        it("writes the largest fee rate", () => {
            expect(encodeShutdownChannelParams({ channelId: CHANNEL_ID, feeRate: 2n ** 64n - 1n }).fee_rate).toBe(U64_MAX_HEX);
        });

        it.each(shutdown.params.map((entry) => [entry.name, entry] as const))("writes the %s case as fiber's serde does", (_, entry) => {
            expect(encodeShutdownChannelParams(toShutdownChannelParams(entry.values))).toEqual(withoutNulls(entry.json));
        });

        it.each<[string, Record<string, unknown>, Error]>([
            ["a bare channel id", { channelId: "11".repeat(32) }, new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex")],
            [
                "a channel id of 31 bytes",
                { channelId: `0x${"11".repeat(31)}` },
                new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
            ],
            [
                "an uppercase channel id",
                { channelId: `0x${"AA".repeat(32)}` },
                new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
            ],
            ["a missing channel id", { channelId: undefined }, new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex")],
            ["a close script given as null", { closeScript: null }, new TypeError("closeScript must be an object")],
            [
                "a close script with a short code hash",
                { closeScript: { ...CLOSE_SCRIPT, codeHash: new Uint8Array(31) } },
                new TypeError("closeScript.codeHash must be 32 bytes, got 31"),
            ],
            [
                "a close script with an unknown hash type",
                { closeScript: { ...CLOSE_SCRIPT, hashType: "data3" } },
                new TypeError("closeScript.hashType must be one of data, type, data1, data2"),
            ],
            [
                "a close script with args as hex",
                { closeScript: { ...CLOSE_SCRIPT, args: "c5".repeat(20) } },
                new TypeError("closeScript.args must be a Uint8Array"),
            ],
            [
                "a fee rate given as null",
                { feeRate: null },
                new RangeError("feeRate must be a bigint between 0 and 18446744073709551615, got null"),
            ],
            [
                "a negative fee rate",
                { feeRate: -1n },
                new RangeError("feeRate must be a bigint between 0 and 18446744073709551615, got -1"),
            ],
            [
                "a fee rate past a u64",
                { feeRate: 2n ** 64n },
                new RangeError("feeRate must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
            ],
            [
                "a fee rate as a string",
                { feeRate: "1000" },
                new RangeError("feeRate must be a bigint between 0 and 18446744073709551615, got 1000"),
            ],
            ["a force given as null", { force: null }, new TypeError("force must be a boolean")],
            ["a force as a string", { force: "true" }, new TypeError("force must be a boolean")],
            ["a force as a number", { force: 1 }, new TypeError("force must be a boolean")],
        ])("refuses %s", (_, change, expected) => {
            expect(() => encodeShutdownChannelParams({ channelId: CHANNEL_ID, ...change } as ShutdownChannelParams)).toThrow(expected);
        });
    });

    describe("decodeShutdownChannelResult", () => {
        it.each(shutdown.results.map((entry) => [entry.name, entry] as const))("reads the %s", (_, entry) => {
            expect(decodeShutdownChannelResult(result(entry.json))).toBeUndefined();
        });

        it.each([{}, undefined, true, "null", 0])("refuses %p", (value) => {
            expect(refusal(() => decodeShutdownChannelResult(result(value))).message).toBe(`${RESULT} must be null`);
        });
    });
});

describe("decodeRpcChannelState", () => {
    function state(value: unknown): unknown {
        return decodeRpcChannelState({ value, path: "state" });
    }

    it("reads each state the vectors carry as the name and the flags fiber wrote", () => {
        for (const entry of list.results) {
            entry.values.channels.forEach((channel, index) => {
                const json = (entry.json as { channels: { state: unknown }[] }).channels[index]?.state;
                expect(state(json)).toEqual(toChannelState(channel.state));
            });
        }
    });

    it.each(Object.entries(RPC_CHANNEL_STATE_FLAGS).filter(([, flags]) => flags.length > 0))(
        "reads every flag %s has, and none",
        (name, flags) => {
            expect(state({ state_name: name, state_flags: flags.join("|") })).toEqual({ name, flags: [...flags] });
            expect(state({ state_name: name, state_flags: "" })).toEqual({ name, flags: [] });
        },
    );

    it.each(["ChannelReady", "Stale"])("reads %s, which has no flags, only without state_flags", (name) => {
        expect(state({ state_name: name })).toEqual({ name, flags: [] });
        expect(refusal(() => state({ state_name: name, state_flags: "" })).message).toBe(`state.state_flags must be absent for ${name}`);
    });

    it("keeps a leaked composite as fiber wrote it", () => {
        expect(state({ state_name: "NegotiatingFunding", state_flags: "OUR_INIT_SENT|INIT_SENT" })).toEqual({
            name: "NegotiatingFunding",
            flags: ["OUR_INIT_SENT", "INIT_SENT"],
        });
    });

    it("refuses a flag of another state", () => {
        expect(refusal(() => state({ state_name: "ShuttingDown", state_flags: "COOPERATIVE" })).path).toBe("state.state_flags");
    });
});

describe("FiberRpcClient channel methods", () => {
    const URL = "http://fiber.example:8227";

    it("opens a channel and reads the unsigned funding transaction", async () => {
        const entry = caseOf(open.results, "udt channel with deps");
        const mock = answering(entry.json);
        await expect(new FiberRpcClient({ url: URL, fetch: mock.fetch }).openChannelWithExternalFunding(OPEN)).resolves.toEqual(
            toOpenChannelWithExternalFundingResult(entry.values),
        );
        expect(sent(mock)).toEqual({
            jsonrpc: "2.0",
            id: 1,
            method: "open_channel_with_external_funding",
            params: [encodeOpenChannelWithExternalFundingParams(OPEN)],
        });
    });

    it("submits the signed funding transaction", async () => {
        const params = caseOf(submit.params, "udt channel with deps");
        const entry = caseOf(submit.results, "submitted");
        const mock = answering(entry.json);
        await expect(
            new FiberRpcClient({ url: URL, fetch: mock.fetch }).submitSignedFundingTx(toSubmitSignedFundingTxParams(params.values)),
        ).resolves.toEqual(toSubmitSignedFundingTxResult(entry.values));
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "submit_signed_funding_tx", params: [params.json] });
    });

    it("opens a tenant channel through call and reads the frozen terms", async () => {
        const entry = caseOf(openTenant.results, "opening context, large amounts");
        const mock = answering(entry.json);
        const client = new FiberRpcClient({ url: URL, fetch: mock.fetch });
        await expect(
            client.call("open_tenant_channel", encodeOpenTenantChannelParams(OPEN_TENANT), decodeOpenTenantChannelResult),
        ).resolves.toEqual(toOpenTenantChannelResult(entry.values));
        expect(sent(mock)).toEqual({
            jsonrpc: "2.0",
            id: 1,
            method: "open_tenant_channel",
            params: [encodeOpenTenantChannelParams(OPEN_TENANT)],
        });
    });

    it("shuts a channel down through call, sending the exact body and resolving with nothing", async () => {
        const mock = answering(null);
        const client = new FiberRpcClient({ url: URL, fetch: mock.fetch });
        const params = encodeShutdownChannelParams({ channelId: CHANNEL_ID, closeScript: CLOSE_SCRIPT, feeRate: 1000n, force: false });
        await expect(client.call("shutdown_channel", params, decodeShutdownChannelResult)).resolves.toBeUndefined();
        expect(sent(mock)).toEqual({
            jsonrpc: "2.0",
            id: 1,
            method: "shutdown_channel",
            params: [{ channel_id: CHANNEL_ID, close_script: CLOSE_SCRIPT_WIRE, fee_rate: "0x3e8", force: false }],
        });
    });

    it("abandons a channel, resolving with nothing", async () => {
        const mock = answering(null);
        await expect(
            new FiberRpcClient({ url: URL, fetch: mock.fetch }).abandonChannel({ channelId: CHANNEL_ID }),
        ).resolves.toBeUndefined();
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "abandon_channel", params: [{ channel_id: CHANNEL_ID }] });
    });

    it("lists channels in the default mode when given nothing", async () => {
        const mock = answering(LISTING);
        await expect(new FiberRpcClient({ url: URL, fetch: mock.fetch }).listChannels()).resolves.toHaveLength(3);
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "list_channels", params: [{}] });
    });

    it("lists channels with the filter's flag", async () => {
        const mock = answering({ channels: [] });
        await expect(new FiberRpcClient({ url: URL, fetch: mock.fetch }).listChannels({ filter: "only_pending" })).resolves.toEqual([]);
        expect(sent(mock)).toEqual({ jsonrpc: "2.0", id: 1, method: "list_channels", params: [{ only_pending: true }] });
    });

    it("refuses params it cannot write before sending anything", async () => {
        const mock = new FetchMock();
        const client = new FiberRpcClient({ url: URL, fetch: mock.fetch });
        await expect(client.abandonChannel({ channelId: "11" })).rejects.toThrow(TypeError);
        expect(mock.requests).toHaveLength(0);
    });

    it("passes the node's refusal through", async () => {
        const mock = refusing(-32000, "only_pending and include_closed are mutually exclusive");
        const error = await rejection(new FiberRpcClient({ url: URL, fetch: mock.fetch }).listChannels());
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({ method: "list_channels", code: -32000 });
    });

    it("names the nested field of an answer it cannot read", async () => {
        const mock = answering(withField(LISTING, "channels[1].state.state_flags", "COOPERATIVE|SHUTDOWN"));
        const error = await rejection(new FiberRpcClient({ url: URL, fetch: mock.fetch }).listChannels());
        expect(error).toBeInstanceOf(RpcResponseError);
        expect(error).toMatchObject({ method: "list_channels", path: "response.result.channels[1].state.state_flags" });
    });
});
