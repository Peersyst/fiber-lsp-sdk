import { hexToBytes } from "@noble/hashes/utils.js";
import type { CellDep, Script, Transaction } from "../../../src/common";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest";
import { ChannelPinError, ChannelRegistrationError, PolicyEngine, SignerStore } from "../../../src/policy";
import { FiberRpcClient, RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import type { SdkChannelOpeningOptions, SdkChannelOpening } from "../../../src/sdk";
import {
    ActivityTracker,
    DEFAULT_COMMITMENT_DELAY_EPOCH,
    DEFAULT_COMMITMENT_FEE_RATE,
    IndexAllocator,
    PendingOpeningStore,
    SDK_NETWORK_PRESETS,
    SdkError,
    buildChannelSigningStep,
    openSdkChannel,
    prepareSdkChannelOpen,
    submitSdkFundingTx,
} from "../../../src/sdk";
import { SignerDispatch } from "../../../src/signer";
import { InMemorySignerStorage } from "../../mocks/policy";
import type { SentCall } from "../../mocks/rpc";
import { ScriptedNode } from "../../mocks/rpc";
import { asRecord } from "../../utils/json-shape";
import { rejection } from "../../utils/rejection";
import { LIST_CHANNELS_CALL, signingStatusCall } from "../../utils/rpc-answers";
import { withField } from "../../utils/with-field";
import { storedAt, writes } from "../../utils/stored-records";

const URL = "http://127.0.0.1:8227";
const MASTER_SEED = hexToBytes("24".repeat(32));
// The clock reads channel index 1_791_367_200.
const NOW_MS = 1_791_367_200_250;
const INDEX = 1_791_367_200;
const NEXT_INDEX = 1_791_367_201;
// The RPC vector's peer.
const LSP_PUBKEY = "02106fa580a1c56411d6ee7deabcc98aae6f6479858f924487cf58c4c2ca302304";
const AMOUNT = "72000000000";
const OTHER_ID = `0x${"2e".repeat(32)}`;

const ALLOCATOR_KEY = "fiber-lsp-sdk:allocator:channel";
const OPENING_KEY = "fiber-lsp-sdk:opening";
const ACTIVITY_KEY = "fiber-lsp-sdk:activity";
const RECORD_KEY = `fiber-lsp-sdk:channel:${INDEX}`;

// The device's keys and material at INDEX of the master seed; the peer's keys and scripts are the signing vectors'.
const DEVICE_FUNDING_PUBKEY = "033d7405b9260f20ed7352346928485f216a78f7f1a4cda82b629fc651d4e8dbfd";
const DEVICE_TLC_BASE_PUBKEY = "0276151a3496ee4b719ef2adb2cf62247040b7e6d3bc7151c53d354f07a7c3807f";
// The device's keys at NEXT_INDEX.
const NEXT_BASE_PUBLIC_KEYS = {
    funding_pubkey: "022aaa11ca19a14b5523de28a3c1d6a2b66ec7eef8f5ad82ac602cd066019832e3",
    tlc_base_key: "024d8c13ff6149cce95fcd5b549649be205517c31bf84c4c1395780bc6fa271de3",
};
const PEER_FUNDING_PUBKEY = "026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638";
const PEER_TLC_BASE_PUBKEY = "032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21";
// The channel id and the funding lock's args of the device's keys at NEXT_INDEX.
const NEXT_CHANNEL_ID = "0x89ca0a4cb78121bad2d5044d5d583e2a9ff5dd7a741a7c5bb937d678079774d6";
const NEXT_FUNDING_LOCK_ARGS = "b0901bdf23af3f27d40550c17bf509d3b80f1e22";
// tenantChannelId(DEVICE_TLC_BASE_PUBKEY, PEER_TLC_BASE_PUBKEY).
const CHANNEL_ID = "0x5df11183f0223c41ea85677270eeaf085d3d2fa00f4a35b1b870b7af25b0287f";
const ALIAS_KEY = `fiber-lsp-sdk:alias:${CHANNEL_ID}`;
// fundingLockArgs(DEVICE_FUNDING_PUBKEY, PEER_FUNDING_PUBKEY), under testnet's funding lock.
const FUNDING_LOCK_ARGS = "d2062cbf42d7ba8d2a9c1ac3e81cef97e8fc0a78";
const TESTNET_FUNDING_LOCK_CODE_HASH = "6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c";
// computeTxHash of the unsigned funding tx below, and of the same with output 1 one shannon larger.
const FUNDING_TX_HASH = "50683c27e89bd4d2373af33b667f91c6eb23e06af00680ec9a688148aaa04a89";
const ALTERED_TX_HASH = "b8459e00d87d3944ebff78a722a8eb0a905e33d3a859aad287a9d66da95abe36";

const USER_LOCK: Script = {
    codeHash: hexToBytes("537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d769"),
    hashType: "type",
    args: hexToBytes("8d66477ba3b60a96feb27a3f57fe11f6697be87d"),
};
const OTHER_LOCK: Script = { ...USER_LOCK, args: hexToBytes("8d66477ba3b60a96feb27a3f57fe11f6697be87e") };
const PEER_LOCK: Script = {
    codeHash: hexToBytes("4d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba"),
    hashType: "type",
    args: hexToBytes("8f1e030962418183dc890ef5664b1f2a64b0064c"),
};
// The molecule table of USER_LOCK, the policy's pin form.
const USER_LOCK_HEX =
    "49000000100000003000000031000000537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d76901140000008d66477ba3b60a96feb27a3f57fe11f6697be87d";
// The molecule table of PEER_LOCK, the pin of the peer's close script.
const PEER_LOCK_HEX =
    "490000001000000030000000310000004d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba01140000008f1e030962418183dc890ef5664b1f2a64b0064c";
const USER_LOCK_WIRE = {
    code_hash: "0x537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d769",
    hash_type: "type",
    args: "0x8d66477ba3b60a96feb27a3f57fe11f6697be87d",
};
const PEER_LOCK_WIRE = {
    code_hash: "0x4d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba",
    hash_type: "type",
    args: "0x8f1e030962418183dc890ef5664b1f2a64b0064c",
};
const CELL_DEPS: CellDep[] = [
    { outPoint: { txHash: hexToBytes("25420fa6561f27d788553529c5a2d7758ce5ed85823df5f12b21f7a0f105acd9"), index: 2 }, depType: "code" },
    {
        outPoint: { txHash: hexToBytes("d8ef9125d4bc98b9c3716fcf61110e302098a55222a2e79344a8264352fe7b9d"), index: 0 },
        depType: "dep_group",
    },
];
const CELL_DEPS_WIRE = [
    { out_point: { tx_hash: "0x25420fa6561f27d788553529c5a2d7758ce5ed85823df5f12b21f7a0f105acd9", index: "0x2" }, dep_type: "code" },
    { out_point: { tx_hash: "0xd8ef9125d4bc98b9c3716fcf61110e302098a55222a2e79344a8264352fe7b9d", index: "0x0" }, dep_type: "dep_group" },
];
const CELL_DEPS_STORED = [
    { txHash: "25420fa6561f27d788553529c5a2d7758ce5ed85823df5f12b21f7a0f105acd9", index: 2, depType: "code" },
    { txHash: "d8ef9125d4bc98b9c3716fcf61110e302098a55222a2e79344a8264352fe7b9d", index: 0, depType: "dep_group" },
];
// A WitnessArgs whose lock is fiber's 65-byte placeholder, and the same signed.
const PLACEHOLDER_WITNESS = `0x5500000010000000550000005500000041000000${"00".repeat(65)}`;
const SIGNED_WITNESS = `0x5500000010000000550000005500000041000000${"5a".repeat(65)}`;

const OPEN_PARAMS = {
    pubkey: LSP_PUBKEY,
    funding_amount: "0x10c388d000",
    public: false,
    shutdown_script: USER_LOCK_WIRE,
    funding_lock_script: USER_LOCK_WIRE,
    commitment_delay_epoch: "0x10000000001",
    commitment_fee_rate: "0x3e8",
    external_channel_signer: {
        base_public_keys: { funding_pubkey: DEVICE_FUNDING_PUBKEY, tlc_base_key: DEVICE_TLC_BASE_PUBKEY },
        first_commitment_point: "031fb5b38f7f6b559a8a9eb93fc318be7e62af08631c235d984fd77da5d25d7e79",
        second_commitment_point: "03a027c76a39d0d90fbf9ee8e5ddb5ca42c49334b2d3ec71ed5d65eda71e9ac786",
        commitment_nonce:
            "0x026d654c7bd8a073be43dc25f034bd48a169b6de15f8a764906ebf57e065816d2a0287422bc94dacecfe8e6f019a3436e42a86e9ee4b6b60978e5eb68b54900fcc46",
        next_commitment_nonce:
            "0x02a5a4dc2d880d459a73b9d1b738b7b09a584ddd5488af511d5896ddc341c4f6f802771d7f39e263471a9bc4754fbabd4448b38b6bd9c30ba9a1a656207670a93911",
        revocation_nonce:
            "0x0385aa2e1d0acb77b798d3ef40f3374cb7039a66671b71bb62c5319e50f5aeed4f039906feb99aeeaa86a2e49d19932ba03ffec6165ba4ec543e71740f330e8eaae7",
    },
};

// The RPC vector's opening over the keys and scripts above: 720 CKB funded, 285 CKB from the peer, both reserves 100 CKB
// under the full payment hash layout, the funding cell first and a change output for each party.
const UNSIGNED_TX_WIRE = {
    version: "0x0",
    cell_deps: [
        {
            out_point: { tx_hash: "0xd8ef9125d4bc98b9c3716fcf61110e302098a55222a2e79344a8264352fe7b9d", index: "0x0" },
            dep_type: "dep_group",
        },
    ],
    header_deps: [],
    inputs: [
        { since: "0x0", previous_output: { tx_hash: "0x89dc569f9eec0e82ca13a353be098d150e9164d79f9c5201079e422a283c8ee4", index: "0x1" } },
        { since: "0x0", previous_output: { tx_hash: "0xba99565f43b9baad46715753a94028906c73fdc052418acd24e473aebd15d47d", index: "0x0" } },
    ],
    outputs: [
        {
            capacity: "0x1766444d00",
            lock: { code_hash: `0x${TESTNET_FUNDING_LOCK_CODE_HASH}`, hash_type: "type", args: `0x${FUNDING_LOCK_ARGS}` },
            type: null,
        },
        { capacity: "0x2540be400", lock: USER_LOCK_WIRE, type: null },
        { capacity: "0x174876e800", lock: PEER_LOCK_WIRE, type: null },
    ],
    outputs_data: ["0x", "0x", "0x"],
    witnesses: [PLACEHOLDER_WITNESS, PLACEHOLDER_WITNESS],
};

const OPEN_ANSWER = {
    channel_id: CHANNEL_ID,
    unsigned_funding_tx: UNSIGNED_TX_WIRE,
    opening_context: {
        remote_funding_key: PEER_FUNDING_PUBKEY,
        remote_settlement_key: PEER_TLC_BASE_PUBKEY,
        remote_shutdown_script: PEER_LOCK_WIRE,
        commitment_delay_epoch: "0x10000000001",
        commitment_fee_rate: "0x3e8",
        local_amount: "0x10c388d000",
        remote_amount: "0x6a2bb7d00",
        local_reserved_ckb_amount: "0x2540be400",
        remote_reserved_ckb_amount: "0x2540be400",
    },
};

const UNSIGNED_TX: Transaction = {
    version: 0,
    cellDeps: [
        {
            outPoint: { txHash: hexToBytes("d8ef9125d4bc98b9c3716fcf61110e302098a55222a2e79344a8264352fe7b9d"), index: 0 },
            depType: "dep_group",
        },
    ],
    headerDeps: [],
    inputs: [
        { since: 0n, previousOutput: { txHash: hexToBytes("89dc569f9eec0e82ca13a353be098d150e9164d79f9c5201079e422a283c8ee4"), index: 1 } },
        { since: 0n, previousOutput: { txHash: hexToBytes("ba99565f43b9baad46715753a94028906c73fdc052418acd24e473aebd15d47d"), index: 0 } },
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
    witnesses: [hexToBytes(PLACEHOLDER_WITNESS.slice(2)), hexToBytes(PLACEHOLDER_WITNESS.slice(2))],
};

const OPENING: SdkChannelOpening = {
    channelId: CHANNEL_ID,
    unsignedFundingTx: UNSIGNED_TX,
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

const SIGNED_TX: Transaction = { ...UNSIGNED_TX, witnesses: [hexToBytes(SIGNED_WITNESS.slice(2)), hexToBytes(SIGNED_WITNESS.slice(2))] };

const SUBMIT_CALL: SentCall = {
    method: "submit_signed_funding_tx",
    params: { channel_id: CHANNEL_ID, signed_funding_tx: { ...UNSIGNED_TX_WIRE, witnesses: [SIGNED_WITNESS, SIGNED_WITNESS] } },
};
const SUBMIT_ANSWER = { channel_id: CHANNEL_ID, funding_tx_hash: `0x${FUNDING_TX_HASH}` };
const ONLY_PENDING_CALL: SentCall = { method: "list_channels", params: { only_pending: true } };
const OPENING_STATE = { state_name: "NegotiatingFunding", state_flags: "AWAITING_EXTERNAL_FUNDING" };
const ABORTED = { state_name: "Closed", state_flags: "FUNDING_ABORTED" };

const PINS = {
    fundedShannons: AMOUNT,
    localCloseScript: USER_LOCK_HEX,
    localReservedCkbShannons: { legacy: "9900000000", fullPaymentHash: "10000000000" },
    udtTypeScript: null,
    liquidCapacityShannons: "80500000000",
    commitmentFeeRate: "1000",
    remoteReservedCkbShannons: "10000000000",
    remoteCloseScript: PEER_LOCK_HEX,
    remoteFundingPubkey: PEER_FUNDING_PUBKEY,
    remoteTlcBasePubkey: PEER_TLC_BASE_PUBKEY,
    commitmentDelayEpoch: "1099511627777",
    fundingOutPoint: `${FUNDING_TX_HASH}:0`,
    fundingCapacityShannons: "100500000000",
};

type Harness = {
    storage: InMemorySignerStorage;
    store: SignerStore;
    policy: PolicyEngine;
    node: ScriptedNode;
    options: SdkChannelOpeningOptions;
};

function harness(): Harness {
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    const policy = new PolicyEngine(store);
    const node = new ScriptedNode();
    const options: SdkChannelOpeningOptions = {
        network: SDK_NETWORK_PRESETS.testnet,
        lspPubkey: hexToBytes(LSP_PUBKEY),
        store,
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
        policy,
        dispatch: new SignerDispatch({
            masterSeed: MASTER_SEED,
            commitmentLock: COMMITMENT_LOCK_TESTNET,
            fundingLockCellDepsCount: 2,
            millisecondsPerEpoch: 14_400_000,
            policy,
        }),
        allocator: new IndexAllocator(store, () => NOW_MS),
        activity: new ActivityTracker(store),
        openings: new PendingOpeningStore(store),
    };
    return { storage, store, policy, node, options };
}

function pendingOf(channelIndex: number, channelId: string | null, fundedShannons: string = AMOUNT): unknown {
    return { version: 1, opening: { channelIndex, fundedShannons, userLock: USER_LOCK_HEX, channelId } };
}

function pendingWithDepsOf(channelIndex: number, channelId: string | null): unknown {
    return {
        version: 1,
        opening: { channelIndex, fundedShannons: AMOUNT, userLock: USER_LOCK_HEX, userLockCellDeps: CELL_DEPS_STORED, channelId },
    };
}

function nextIndexAnswer(): unknown {
    return withField(
        withField(OPEN_ANSWER, "channel_id", NEXT_CHANNEL_ID),
        "unsigned_funding_tx.outputs[0].lock.args",
        `0x${NEXT_FUNDING_LOCK_ARGS}`,
    );
}

function failingDrop(h: Harness): void {
    const set = h.storage.set.bind(h.storage);
    jest.spyOn(h.storage, "set").mockImplementation((key, value) => {
        if (key === OPENING_KEY && asRecord(JSON.parse(value), "record").opening === null) throw new Error("storage offline");
        set(key, value);
    });
}

function seeded(opening: unknown): Harness {
    const h = harness();
    h.storage.map.set(OPENING_KEY, JSON.stringify(opening));
    h.storage.map.set(ALLOCATOR_KEY, JSON.stringify(INDEX));
    return h;
}

function openCall(params: unknown = OPEN_PARAMS): SentCall {
    return { method: "open_tenant_channel", params };
}

function baseKeysSent(h: Harness, call: number): unknown {
    const params = h.node.calls()[call]?.params as { external_channel_signer: { base_public_keys: unknown } };
    return params.external_channel_signer.base_public_keys;
}

async function opened(): Promise<Harness> {
    const h = harness();
    h.node.result(OPEN_ANSWER);
    await prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK);
    return h;
}

describe("prepareSdkChannelOpen", () => {
    it("asks the node with the device's material, the user's lock as both scripts, and fiber's default delay and fee rate", async () => {
        const h = harness();
        h.node.result(OPEN_ANSWER);
        await prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK);
        expect(DEFAULT_COMMITMENT_DELAY_EPOCH).toBe(0x10000000001n);
        expect(DEFAULT_COMMITMENT_FEE_RATE).toBe(1000n);
        expect(h.node.calls()).toEqual([openCall()]);
    });

    it.each([
        [
            "delay",
            "opening_context.commitment_delay_epoch",
            "0x10000000002",
            "openingContext.commitmentDelayEpoch is 1099511627778, not the 1099511627777 asked",
        ],
        ["fee rate", "opening_context.commitment_fee_rate", "0x3e9", "openingContext.commitmentFeeRate is 1001, not the 1000 asked"],
    ])("refuses an answer at another %s than the one it sent, registering nothing", async (_, path, value, detail) => {
        const h = harness();
        h.node.result(withField(OPEN_ANSWER, path, value));
        const error = await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK));
        expect(error).toEqual(new SdkError("opening_rejected", `the node's opening is refused: ${detail}`));
        expect(await h.store.resolveChannelIndex(CHANNEL_ID)).toBeNull();
    });

    it("hands back the node's channel id, unsigned funding tx and opening context", async () => {
        const h = harness();
        h.node.result(OPEN_ANSWER);
        await expect(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK)).resolves.toStrictEqual(OPENING);
    });

    it("records the opening under a freshly allocated index before it asks the node", async () => {
        const h = harness();
        let pending: unknown;
        h.node.onCall("open_tenant_channel", () => {
            pending = storedAt(h.storage, OPENING_KEY);
        });
        h.node.result(OPEN_ANSWER);
        await prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK);
        expect(pending).toEqual(pendingOf(INDEX, null));
        expect(storedAt(h.storage, ALLOCATOR_KEY)).toBe(INDEX);
    });

    it("names the opening, then registers and pins the whole answer and watches the channel, all before handing the tx out", async () => {
        const h = await opened();
        expect(writes(h.storage)).toEqual([
            ALLOCATOR_KEY,
            OPENING_KEY,
            OPENING_KEY,
            RECORD_KEY,
            ALIAS_KEY,
            RECORD_KEY,
            RECORD_KEY,
            ACTIVITY_KEY,
        ]);
        expect(await h.store.resolveChannelIndex(CHANNEL_ID)).toBe(INDEX);
        expect((await h.store.getChannelRecord(INDEX))?.pins).toStrictEqual(PINS);
        expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual({
            version: 1,
            channels: { [CHANNEL_ID]: { status: null } },
            payments: {},
            invoices: {},
        });
        expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
    });

    it("leaves the channel served by the signing step before its tx is submitted, and not before it is prepared", async () => {
        const tick = async (h: Harness): Promise<void> => {
            const { rpc, store, dispatch } = h.options;
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID }] })
                .result({ channel_id: CHANNEL_ID, status: { type: "NoSignatureRequired" } });
            await buildChannelSigningStep({ rpc, store, dispatch, emit: () => undefined })({ abandoned: false });
        };
        const fresh = harness();
        await tick(fresh);
        expect(fresh.node.calls()).toEqual([LIST_CHANNELS_CALL]);
        const h = await opened();
        await tick(h);
        expect(h.node.calls()).toEqual([openCall(), LIST_CHANNELS_CALL, signingStatusCall(CHANNEL_ID)]);
    });

    describe("the pending opening", () => {
        it("resumes after an unknown outcome under the same index, resending the identical request", async () => {
            const h = harness();
            h.node.reject(new Error("offline"));
            expect(await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK))).toBeInstanceOf(RpcTransportError);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, null));
            h.node.result(OPEN_ANSWER);
            await expect(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK)).resolves.toStrictEqual(OPENING);
            expect(h.node.calls()).toEqual([openCall(), openCall()]);
            expect(writes(h.storage).filter((key) => key === ALLOCATOR_KEY)).toHaveLength(1);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
        });

        it("keeps it when the node's answer cannot be read, an outcome as unknown as a lost one", async () => {
            const h = harness();
            h.node.result({ channel_id: CHANNEL_ID });
            expect(await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK))).toBeInstanceOf(RpcResponseError);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, null));
        });

        it("keeps it through an interruption fiber answers as an error, and the next call resends the identical request", async () => {
            const h = harness();
            h.node.error(-32000, "tenant opening interrupted; retry the same request: Timeout");
            const error = await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK));
            expect(error).toBeInstanceOf(RpcError);
            expect(error).toMatchObject({
                method: "open_tenant_channel",
                code: -32000,
                message: "tenant opening interrupted; retry the same request: Timeout",
            });
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, null));
            h.node.result(OPEN_ANSWER);
            await expect(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK)).resolves.toStrictEqual(OPENING);
            expect(h.node.calls()).toEqual([openCall(), openCall()]);
            expect(writes(h.storage).filter((key) => key === ALLOCATOR_KEY)).toHaveLength(1);
        });

        it.each([
            "tenant channel opening stopped: Normal",
            "tenant already has a different channel opening",
            "tenant already has a channel",
        ])("keeps it when fiber refuses with %s, letting the refusal through", async (message) => {
            const h = harness();
            h.node.error(-32000, message);
            expect(await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK))).toMatchObject({ code: -32000, message });
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, null));
        });

        it("resumes one that named its channel while the node lists the channel opening, pinning nothing new", async () => {
            const h = await opened();
            const record = h.storage.map.get(RECORD_KEY);
            h.node.result({ channels: [{ channel_id: CHANNEL_ID, state: OPENING_STATE }] }).result(OPEN_ANSWER);
            await expect(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK)).resolves.toStrictEqual(OPENING);
            expect(h.node.calls()).toEqual([openCall(), ONLY_PENDING_CALL, openCall()]);
            expect(h.storage.map.get(RECORD_KEY)).toBe(record);
            expect(writes(h.storage)).toHaveLength(8);
        });

        it("drops one whose channel the node aborted, and opens under a fresh index", async () => {
            const h = seeded(pendingOf(INDEX, CHANNEL_ID));
            h.node.result({ channels: [{ channel_id: CHANNEL_ID, state: ABORTED }] }).reject(new Error("offline"));
            expect(await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK))).toBeInstanceOf(RpcTransportError);
            expect(h.node.calls()).toEqual([ONLY_PENDING_CALL, expect.objectContaining({ method: "open_tenant_channel" })]);
            expect(baseKeysSent(h, 1)).toEqual(NEXT_BASE_PUBLIC_KEYS);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(NEXT_INDEX, null));
        });

        it("drops only the aborted opening: one another call wrote meanwhile is not cleared", async () => {
            const h = seeded(pendingOf(INDEX, CHANNEL_ID));
            h.node.onCall("list_channels", () =>
                h.storage.map.set(OPENING_KEY, JSON.stringify(pendingOf(NEXT_INDEX, null, "50000000000"))),
            );
            h.node.result({ channels: [{ channel_id: CHANNEL_ID, state: ABORTED }] }).reject(new Error("offline"));
            await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK));
            // No write clears the other call's opening before the fresh one replaces it.
            expect(writes(h.storage)).toEqual([ALLOCATOR_KEY, OPENING_KEY]);
        });

        it("drops one whose channel the node aborted even when no fresh index can be allocated", async () => {
            const h = seeded(pendingOf(INDEX, CHANNEL_ID));
            jest.spyOn(h.options.allocator, "allocateChannelIndex").mockRejectedValueOnce(new Error("storage offline"));
            h.node.result({ channels: [{ channel_id: CHANNEL_ID, state: ABORTED }] });
            expect(await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK))).toEqual(new Error("storage offline"));
            expect(h.node.calls()).toEqual([ONLY_PENDING_CALL]);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual({ version: 1, opening: null });
        });

        it.each([
            ["the node lists no pending channel", []],
            ["the node lists another channel aborted", [{ channel_id: OTHER_ID, state: ABORTED }]],
        ])("resumes one that named its channel when %s", async (_, channels) => {
            const h = seeded(pendingOf(INDEX, CHANNEL_ID));
            h.node.result({ channels }).reject(new Error("offline"));
            await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK));
            expect(h.node.calls()).toEqual([ONLY_PENDING_CALL, openCall()]);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
        });

        it("keeps one that named its channel when fiber refuses the resumed request as already open", async () => {
            const h = seeded(pendingOf(INDEX, CHANNEL_ID));
            h.node.result({ channels: [] }).error(-32000, "tenant channel is already open");
            expect(await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK))).toBeInstanceOf(RpcError);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
        });

        it("drops only its own unnamed opening when the answer fails the check: one written meanwhile survives", async () => {
            const h = seeded(pendingOf(INDEX, null));
            const meanwhile = pendingOf(NEXT_INDEX, null, "50000000000");
            h.node.onCall("open_tenant_channel", () => h.storage.map.set(OPENING_KEY, JSON.stringify(meanwhile)));
            h.node.result(withField(OPEN_ANSWER, "opening_context.commitment_delay_epoch", "0x10000000000"));
            expect(await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK))).toMatchObject({ code: "opening_rejected" });
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(meanwhile);
        });

        it("keeps it when the pending channels cannot be listed, asking nothing more", async () => {
            const h = seeded(pendingOf(INDEX, CHANNEL_ID));
            h.node.reject(new Error("offline"));
            expect(await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK))).toBeInstanceOf(RpcTransportError);
            expect(h.node.calls()).toEqual([ONLY_PENDING_CALL]);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
        });

        it.each<[string, string, Script]>([
            ["another amount", "50000000000", USER_LOCK],
            ["another lock", AMOUNT, OTHER_LOCK],
        ])("opens under a fresh index when the pending one was asked with %s, without listing", async (_, amount, lock) => {
            const h = seeded({
                version: 1,
                opening: { channelIndex: INDEX, fundedShannons: AMOUNT, userLock: USER_LOCK_HEX, channelId: CHANNEL_ID },
            });
            h.node.reject(new Error("offline"));
            await rejection(prepareSdkChannelOpen(h.options, amount, lock));
            expect(h.node.calls()).toHaveLength(1);
            expect(baseKeysSent(h, 0)).toEqual(NEXT_BASE_PUBLIC_KEYS);
            expect(await h.options.openings.read()).toEqual({
                channelIndex: NEXT_INDEX,
                fundedShannons: amount,
                userLock: expect.any(String),
                channelId: null,
            });
        });

        it("drops it when the answer fails the check, pinning nothing", async () => {
            const h = harness();
            h.node.result(withField(OPEN_ANSWER, "opening_context.commitment_delay_epoch", "0x10000000000"));
            const error = await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK));
            expect(error).toBeInstanceOf(SdkError);
            expect(error).toMatchObject({
                code: "opening_rejected",
                message: "the node's opening is refused: openingContext.commitmentDelayEpoch is 1099511627776, not the 1099511627777 asked",
            });
            expect(storedAt(h.storage, OPENING_KEY)).toEqual({ version: 1, opening: null });
            expect(writes(h.storage)).toEqual([ALLOCATOR_KEY, OPENING_KEY, OPENING_KEY]);
        });

        it("keeps it, named, when pinning fails short of a conflict, and the same call then pins what is left", async () => {
            const h = harness();
            jest.spyOn(h.options.activity, "watch").mockRejectedValueOnce(new Error("storage offline"));
            h.node.result(OPEN_ANSWER);
            expect(await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK))).toEqual(new Error("storage offline"));
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
            h.node.result({ channels: [{ channel_id: CHANNEL_ID, state: OPENING_STATE }] }).result(OPEN_ANSWER);
            await expect(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK)).resolves.toStrictEqual(OPENING);
            expect(h.node.calls()).toEqual([openCall(), ONLY_PENDING_CALL, openCall()]);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual({
                version: 1,
                channels: { [CHANNEL_ID]: { status: null } },
                payments: {},
                invoices: {},
            });
        });

        it("drops an opening that failed past its pins once the node aborts it, and opens afresh without a conflict", async () => {
            const h = harness();
            jest.spyOn(h.options.activity, "watch").mockRejectedValueOnce(new Error("storage offline"));
            h.node.result(OPEN_ANSWER);
            await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK));
            h.node.result({ channels: [{ channel_id: CHANNEL_ID, state: ABORTED }] }).result(nextIndexAnswer());
            await expect(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK)).resolves.toMatchObject({ channelId: NEXT_CHANNEL_ID });
            expect(baseKeysSent(h, 2)).toEqual(NEXT_BASE_PUBLIC_KEYS);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(NEXT_INDEX, NEXT_CHANNEL_ID));
            expect(await h.store.resolveChannelIndex(NEXT_CHANNEL_ID)).toBe(NEXT_INDEX);
        });
    });

    describe("the user lock's cell deps", () => {
        it("sends them in the request, as fiber writes cell deps, and keeps them in the pending opening", async () => {
            const h = harness();
            h.node.reject(new Error("offline"));
            await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK, CELL_DEPS));
            expect(h.node.calls()).toEqual([openCall({ ...OPEN_PARAMS, funding_lock_script_cell_deps: CELL_DEPS_WIRE })]);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingWithDepsOf(INDEX, null));
        });

        it.each<[string, CellDep[] | undefined]>([
            ["none", undefined],
            ["an empty list, which fiber reads as none", []],
        ])("sends no cell deps for %s", async (_, deps) => {
            const h = harness();
            h.node.reject(new Error("offline"));
            await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK, deps));
            expect(h.node.calls()).toEqual([openCall()]);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, null));
        });

        it("resumes the opening asked with the same cell deps, resending the identical request", async () => {
            const h = harness();
            h.node.reject(new Error("offline")).reject(new Error("offline"));
            await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK, CELL_DEPS));
            await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK, structuredClone(CELL_DEPS)));
            const [first, second] = h.node.calls();
            expect(second).toEqual(first);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingWithDepsOf(INDEX, null));
        });

        it.each<[string, unknown, CellDep[] | undefined]>([
            ["no cell deps when the pending opening named some", pendingWithDepsOf(INDEX, CHANNEL_ID), undefined],
            ["cell deps when the pending opening named none", pendingOf(INDEX, CHANNEL_ID), CELL_DEPS],
            ["other cell deps", pendingWithDepsOf(INDEX, CHANNEL_ID), CELL_DEPS.slice(1)],
        ])("opens under a fresh index for %s, without listing", async (_, stored, deps) => {
            const h = seeded(stored);
            h.node.reject(new Error("offline"));
            await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK, deps));
            expect(h.node.calls()).toHaveLength(1);
            expect(baseKeysSent(h, 0)).toEqual(NEXT_BASE_PUBLIC_KEYS);
            expect((await h.options.openings.read())?.channelIndex).toBe(NEXT_INDEX);
        });

        it("sends them from openChannel too", async () => {
            const h = harness();
            h.node.reject(new Error("offline"));
            await rejection(openSdkChannel(h.options, AMOUNT, USER_LOCK, async () => SIGNED_TX, CELL_DEPS));
            expect(h.node.calls()).toEqual([openCall({ ...OPEN_PARAMS, funding_lock_script_cell_deps: CELL_DEPS_WIRE })]);
        });

        it.each<[string, unknown, Error]>([
            ["cell deps that are not a list", CELL_DEPS[0], new TypeError("userLockCellDeps must be an array")],
            ["null cell deps", null, new TypeError("userLockCellDeps must be an array")],
            ["a cell dep that is not an object", [CELL_DEPS[0], "dep"], new TypeError("userLockCellDeps[1] must be an object")],
            ["a cell dep without an out point", [{ depType: "code" }], new TypeError("userLockCellDeps[0].outPoint must be an object")],
            [
                "a cell dep with a tx hash in hex",
                [{ outPoint: { txHash: "25".repeat(32), index: 2 }, depType: "code" }],
                new TypeError("userLockCellDeps[0].outPoint.txHash must be a Uint8Array"),
            ],
            [
                "a cell dep with a short tx hash",
                [{ outPoint: { txHash: new Uint8Array(31), index: 2 }, depType: "code" }],
                new TypeError("userLockCellDeps[0].outPoint.txHash must be 32 bytes, got 31"),
            ],
            [
                "a cell dep with an index past a u32",
                [{ outPoint: { txHash: new Uint8Array(32), index: 2 ** 32 }, depType: "code" }],
                new RangeError("userLockCellDeps[0].outPoint.index must be an integer between 0 and 4294967295, got 4294967296"),
            ],
            [
                "a cell dep without a dep type",
                [{ outPoint: { txHash: new Uint8Array(32), index: 2 } }],
                new TypeError("userLockCellDeps[0].depType must be one of code, dep_group"),
            ],
            [
                "a cell dep with a dep type in camel case",
                [{ outPoint: { txHash: new Uint8Array(32), index: 2 }, depType: "depGroup" }],
                new TypeError("userLockCellDeps[0].depType must be one of code, dep_group"),
            ],
        ])("refuses %s, writing and sending nothing", async (_, deps, error) => {
            const h = harness();
            const thrown = await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK, deps as CellDep[]));
            expect(thrown).toEqual(error);
            expect(thrown).toBeInstanceOf(error.constructor);
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
        });
    });

    describe("the caller's objects", () => {
        it("keeps its own copy of the lock: writing to the caller's during the call changes neither the pins nor the opening", async () => {
            const h = harness();
            const lock: Script = { ...USER_LOCK, codeHash: Uint8Array.from(USER_LOCK.codeHash), args: Uint8Array.from(USER_LOCK.args) };
            h.node.onCall("open_tenant_channel", () => {
                lock.codeHash.fill(0);
                lock.args.fill(0);
            });
            h.node.result(OPEN_ANSWER);
            await expect(prepareSdkChannelOpen(h.options, AMOUNT, lock)).resolves.toStrictEqual(OPENING);
            expect((await h.store.getChannelRecord(INDEX))?.pins).toStrictEqual(PINS);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
        });

        it("keeps its own copy of the cell deps: writing to the caller's before they are recorded changes nothing", async () => {
            const h = harness();
            const deps = structuredClone(CELL_DEPS);
            const allocate = h.options.allocator.allocateChannelIndex.bind(h.options.allocator);
            jest.spyOn(h.options.allocator, "allocateChannelIndex").mockImplementationOnce(async () => {
                deps[0]?.outPoint.txHash.fill(0);
                return allocate();
            });
            h.node.reject(new Error("offline"));
            await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK, deps));
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingWithDepsOf(INDEX, null));
            expect(h.node.calls()).toEqual([openCall({ ...OPEN_PARAMS, funding_lock_script_cell_deps: CELL_DEPS_WIRE })]);
        });
    });

    describe("a conflict with the device's record", () => {
        async function conflictOf(h: Harness): Promise<SdkError> {
            const error = await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK));
            if (!(error instanceof SdkError)) throw new Error("not an SdkError");
            expect(error.code).toBe("opening_conflict");
            expect(storedAt(h.storage, OPENING_KEY)).toEqual({ version: 1, opening: null });
            return error;
        }

        it("is opening_conflict when the channel pins other terms, the pin's refusal as its cause", async () => {
            const h = await opened();
            const answer = withField(
                withField(OPEN_ANSWER, "opening_context.remote_amount", "0x6fc23ac00"),
                "unsigned_funding_tx.outputs[0].capacity",
                "0x17bfac7c00",
            );
            h.node.result({ channels: [{ channel_id: CHANNEL_ID, state: OPENING_STATE }] }).result(answer);
            const error = await conflictOf(h);
            expect(error.cause).toBeInstanceOf(ChannelPinError);
            expect(error.message).toBe(
                `the node's opening of channel ${CHANNEL_ID} conflicts with the device's record: ` +
                    `channel ${CHANNEL_ID} already pins liquidCapacityShannons to 80500000000, not 82000000000`,
            );
        });

        it("is opening_conflict when the channel pins another close script of the peer", async () => {
            const h = await opened();
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID, state: OPENING_STATE }] })
                .result(
                    withField(OPEN_ANSWER, "opening_context.remote_shutdown_script.args", "0x8f1e030962418183dc890ef5664b1f2a64b0064d"),
                );
            const error = await conflictOf(h);
            expect(error.cause).toBeInstanceOf(ChannelPinError);
            expect(error.message).toBe(
                `the node's opening of channel ${CHANNEL_ID} conflicts with the device's record: ` +
                    `channel ${CHANNEL_ID} already pins remoteCloseScript to ${PEER_LOCK_HEX}, not ${PEER_LOCK_HEX.slice(0, -1)}d`,
            );
        });

        it("is opening_conflict when the channel pins another funding cell", async () => {
            const h = await opened();
            h.node
                .result({ channels: [{ channel_id: CHANNEL_ID, state: OPENING_STATE }] })
                .result(withField(OPEN_ANSWER, "unsigned_funding_tx.outputs[1].capacity", "0x2540be401"));
            const error = await conflictOf(h);
            expect(error.cause).toBeInstanceOf(ChannelPinError);
            expect(error.message).toBe(
                `the node's opening of channel ${CHANNEL_ID} conflicts with the device's record: ` +
                    `channel ${CHANNEL_ID} already pins fundingOutPoint to ${FUNDING_TX_HASH}:0, not ${ALTERED_TX_HASH}:0`,
            );
        });

        it("is opening_conflict when the node names a channel registered under another index", async () => {
            const h = harness();
            await h.policy.registerChannel(CHANNEL_ID, 7, AMOUNT, USER_LOCK);
            h.node.result(OPEN_ANSWER);
            const error = await conflictOf(h);
            expect(error.cause).toBeInstanceOf(ChannelRegistrationError);
            expect(error.cause).toMatchObject({
                channelId: CHANNEL_ID,
                channelIndex: INDEX,
                message: `channel ${CHANNEL_ID} is already registered under a different channel index`,
            });
        });

        it("is opening_conflict when the resumed index holds a channel of another funded amount", async () => {
            const h = seeded(pendingOf(INDEX, null));
            await h.policy.registerChannel(OTHER_ID, INDEX, "50000000000", USER_LOCK);
            h.node.result(OPEN_ANSWER);
            const error = await conflictOf(h);
            expect(error.cause).toBeInstanceOf(ChannelRegistrationError);
            expect(error.cause).toMatchObject({
                message: `channel index ${INDEX} is already registered with another funded amount or close script`,
            });
            expect(await h.store.resolveChannelIndex(CHANNEL_ID)).toBeNull();
        });

        it("is opening_conflict when the resumed index already serves another channel", async () => {
            const h = seeded(pendingOf(INDEX, null));
            await h.policy.registerChannel(OTHER_ID, INDEX, AMOUNT, USER_LOCK);
            await h.store.updateChannelRecord(INDEX, (current) => {
                if (current === null) throw new Error("the index holds no record");
                return { ...current, lastSignedCommitmentNumbers: { "COMMITMENT:local": 0 } };
            });
            h.node.result(OPEN_ANSWER);
            const error = await conflictOf(h);
            expect(error.cause).toBeInstanceOf(ChannelRegistrationError);
            expect(error.cause).toMatchObject({ message: `channel index ${INDEX} already serves channel ${OTHER_ID}` });
            expect(await h.store.resolveChannelIndex(CHANNEL_ID)).toBeNull();
        });
    });

    describe("a drop the store refuses", () => {
        it("keeps opening_rejected, telling the failed drop in its message, and leaves the opening for the next call", async () => {
            const h = harness();
            failingDrop(h);
            h.node.result(withField(OPEN_ANSWER, "opening_context.commitment_delay_epoch", "0x10000000000"));
            const error = await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK));
            expect(error).toBeInstanceOf(SdkError);
            expect(error).toMatchObject({
                code: "opening_rejected",
                message:
                    "the node's opening is refused: openingContext.commitmentDelayEpoch is 1099511627776, not the 1099511627777 asked; " +
                    "the pending opening could not be dropped: storage offline",
            });
            expect(error).not.toHaveProperty("cause");
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, null));
        });

        it("keeps opening_conflict and its cause, telling the failed drop in its message, and leaves the opening", async () => {
            const h = await opened();
            failingDrop(h);
            const answer = withField(
                withField(OPEN_ANSWER, "opening_context.remote_amount", "0x6fc23ac00"),
                "unsigned_funding_tx.outputs[0].capacity",
                "0x17bfac7c00",
            );
            h.node.result({ channels: [{ channel_id: CHANNEL_ID, state: OPENING_STATE }] }).result(answer);
            const error = await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK));
            expect(error).toBeInstanceOf(SdkError);
            expect(error).toMatchObject({
                code: "opening_conflict",
                message:
                    `the node's opening of channel ${CHANNEL_ID} conflicts with the device's record: ` +
                    `channel ${CHANNEL_ID} already pins liquidCapacityShannons to 80500000000, not 82000000000; ` +
                    "the pending opening could not be dropped: storage offline",
            });
            expect((error as SdkError).cause).toBeInstanceOf(ChannelPinError);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
        });
    });

    describe("a broken store", () => {
        it.each([
            ["channel record", RECORD_KEY, `stored value at ${RECORD_KEY} is not a channel policy record`],
            ["channel alias", ALIAS_KEY, `stored value at ${ALIAS_KEY} is not a channel index`],
        ])("lets a corrupt %s through as itself, not a conflict, keeping the pending opening, named", async (_, key, message) => {
            const h = seeded(pendingOf(INDEX, null));
            h.storage.map.set(key, JSON.stringify({ corrupt: true }));
            h.node.result(OPEN_ANSWER);
            const error = await rejection(prepareSdkChannelOpen(h.options, AMOUNT, USER_LOCK));
            expect(error).toEqual(new TypeError(message));
            expect(error).not.toBeInstanceOf(ChannelRegistrationError);
            expect(error).not.toBeInstanceOf(SdkError);
            expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
        });
    });

    describe("its arguments", () => {
        it.each<[string, unknown, unknown, Error]>([
            ["no amount", undefined, USER_LOCK, new TypeError("amountShannons must be an amount in decimal shannons")],
            ["an amount in a number", 72_000_000_000, USER_LOCK, new TypeError("amountShannons must be an amount in decimal shannons")],
            ["an amount in a bigint", 72_000_000_000n, USER_LOCK, new TypeError("amountShannons must be an amount in decimal shannons")],
            ["an empty amount", "", USER_LOCK, new TypeError("amountShannons must be an amount in decimal shannons")],
            ["a negative amount", "-1", USER_LOCK, new TypeError("amountShannons must be an amount in decimal shannons")],
            ["a fractional amount", "1.5", USER_LOCK, new TypeError("amountShannons must be an amount in decimal shannons")],
            ["an amount in hex", "0x10c388d000", USER_LOCK, new TypeError("amountShannons must be an amount in decimal shannons")],
            [
                "an amount with a leading zero",
                "072000000000",
                USER_LOCK,
                new TypeError("amountShannons must be an amount in decimal shannons"),
            ],
            [
                "an amount one below the device's least reserve",
                "9899999999",
                USER_LOCK,
                new RangeError("fundedShannons 9899999999 is below the 9900000000 the device's reserve takes over that close script"),
            ],
            [
                "an amount of a u64's whole capacity",
                "18446744073709551615",
                USER_LOCK,
                new RangeError("fundedShannons must be below 18446744073709551615, the most a CKB channel's capacity holds"),
            ],
            ["no lock", AMOUNT, undefined, new TypeError("userLock must be an object")],
            ["a null lock", AMOUNT, null, new TypeError("userLock must be an object")],
            [
                "a lock with a short code hash",
                AMOUNT,
                { ...USER_LOCK, codeHash: new Uint8Array(31) },
                new TypeError("userLock.codeHash must be 32 bytes, got 31"),
            ],
            [
                "a lock with an unknown hash type",
                AMOUNT,
                { ...USER_LOCK, hashType: "data3" },
                new TypeError("userLock.hashType must be one of data, type, data1, data2"),
            ],
            [
                "a lock without args",
                AMOUNT,
                { codeHash: USER_LOCK.codeHash, hashType: "type" },
                new TypeError("userLock.args must be a Uint8Array"),
            ],
            [
                "a lock with args in hex",
                AMOUNT,
                { ...USER_LOCK, args: "8d66477ba3b60a96feb27a3f57fe11f6697be87d" },
                new TypeError("userLock.args must be a Uint8Array"),
            ],
        ])("refuses %s, writing and sending nothing", async (_, amount, lock, error) => {
            const h = harness();
            const thrown = await rejection(prepareSdkChannelOpen(h.options, amount as string, lock as Script));
            expect(thrown).toEqual(error);
            expect(thrown).toBeInstanceOf(error.constructor);
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
        });

        it.each([
            ["the device's least reserve", "9900000000", "0x24e160300"],
            ["one below a u64's whole capacity", "18446744073709551614", "0xfffffffffffffffe"],
        ])("asks the node for an amount of %s", async (_, amount, wire) => {
            const h = harness();
            h.node.reject(new Error("offline"));
            await rejection(prepareSdkChannelOpen(h.options, amount, USER_LOCK));
            expect(h.node.calls()).toEqual([openCall(withField(OPEN_PARAMS, "funding_amount", wire))]);
        });
    });
});

describe("submitSdkFundingTx", () => {
    it("hands the node the signed tx when its raw part is the one frozen, writing nothing", async () => {
        const h = await opened();
        h.node.result(SUBMIT_ANSWER);
        await expect(submitSdkFundingTx(h.options, CHANNEL_ID, SIGNED_TX)).resolves.toBeUndefined();
        expect(h.node.calls().at(-1)).toEqual(SUBMIT_CALL);
        expect(writes(h.storage)).toHaveLength(8);
    });

    it.each<[string, string, unknown]>([
        ["output 1 one shannon larger", "outputs[1].capacityShannons", 10_000_000_001n],
        ["an output more", "outputs[3]", { capacityShannons: 1n, lock: USER_LOCK, type: null }],
        ["the funding cell paid to another lock", "outputs[0].lock", USER_LOCK],
        ["another input", "inputs[1].previousOutput.index", 1],
        ["an input under a since", "inputs[0].since", 1n],
        ["a cell dep less", "cellDeps", []],
        ["a header dep more", "headerDeps", [new Uint8Array(32).fill(0xc1)]],
        ["another version", "version", 1],
        ["data in the change", "outputsData[1]", Uint8Array.of(0)],
    ])("refuses a signed tx with %s as funding_tx_altered, sending nothing", async (_, path, value) => {
        const h = await opened();
        const error = await rejection(submitSdkFundingTx(h.options, CHANNEL_ID, withField(SIGNED_TX, path, value)));
        expect(error).toBeInstanceOf(SdkError);
        expect(error).toMatchObject({ code: "funding_tx_altered" });
        expect((error as SdkError).cause).toBeInstanceOf(ChannelPinError);
        expect(h.node.calls()).toEqual([openCall()]);
        expect((await h.store.getChannelRecord(INDEX))?.pins).toStrictEqual(PINS);
    });

    it("names both funding cells when it refuses", async () => {
        const h = await opened();
        const error = await rejection(
            submitSdkFundingTx(h.options, CHANNEL_ID, withField(SIGNED_TX, "outputs[1].capacityShannons", 10_000_000_001n)),
        );
        expect(error).toEqual(
            new SdkError(
                "funding_tx_altered",
                `the signed tx is not the funding tx the device froze: channel ${CHANNEL_ID} already pins fundingOutPoint to ${FUNDING_TX_HASH}:0, not ${ALTERED_TX_HASH}:0`,
            ),
        );
    });

    it("refuses a channel this device never registered as unknown_channel, sending nothing", async () => {
        const h = harness();
        const error = await rejection(submitSdkFundingTx(h.options, CHANNEL_ID, SIGNED_TX));
        expect(error).toEqual(new SdkError("unknown_channel", `channel ${CHANNEL_ID} is not registered on this device`));
        expect(error).toMatchObject({ code: "unknown_channel" });
        expect(h.node.calls()).toEqual([]);
    });

    it("refuses a registered channel with no funding cell pinned as funding_tx_altered", async () => {
        const h = harness();
        await h.policy.registerChannel(OTHER_ID, 7, AMOUNT, USER_LOCK);
        const error = await rejection(submitSdkFundingTx(h.options, OTHER_ID, SIGNED_TX));
        expect(error).toEqual(
            new SdkError("funding_tx_altered", `channel ${OTHER_ID} pins no funding cell to check the signed tx against`),
        );
        expect(error).toMatchObject({ code: "funding_tx_altered" });
        expect(h.node.calls()).toEqual([]);
    });

    it("refuses a registered channel whose out point was pinned with no capacity as funding_tx_altered", async () => {
        const h = harness();
        await h.policy.registerChannel(OTHER_ID, 7, AMOUNT, USER_LOCK);
        // A close states the funding out point and no capacity, so it may pin the one without the other.
        const key = "fiber-lsp-sdk:channel:7";
        const record = storedAt(h.storage, key) as { pins: object };
        h.storage.map.set(key, JSON.stringify({ ...record, pins: { ...record.pins, fundingOutPoint: `${FUNDING_TX_HASH}:0` } }));
        const error = await rejection(submitSdkFundingTx(h.options, OTHER_ID, SIGNED_TX));
        expect(error).toEqual(
            new SdkError("funding_tx_altered", `channel ${OTHER_ID} pins no funding cell to check the signed tx against`),
        );
        expect(error).toMatchObject({ code: "funding_tx_altered" });
        expect(h.node.calls()).toEqual([]);
    });

    it("lets a failure of the pin short of a conflict through as itself, sending nothing", async () => {
        const h = await opened();
        jest.spyOn(h.policy, "pinFundingCell").mockRejectedValueOnce(new Error("storage offline"));
        const error = await rejection(submitSdkFundingTx(h.options, CHANNEL_ID, SIGNED_TX));
        expect(error).toEqual(new Error("storage offline"));
        expect(error).not.toBeInstanceOf(SdkError);
        expect(h.node.calls()).toEqual([openCall()]);
    });

    it("submits its own copy of the signed tx: writing to the caller's while the cell is checked changes nothing", async () => {
        const h = await opened();
        const signedTx = structuredClone(SIGNED_TX);
        const pin = h.policy.pinFundingCell.bind(h.policy);
        jest.spyOn(h.policy, "pinFundingCell").mockImplementationOnce(async (...args) => {
            const output = signedTx.outputs[1];
            if (output !== undefined) output.capacityShannons += 1n;
            return pin(...args);
        });
        h.node.result(SUBMIT_ANSWER);
        await submitSdkFundingTx(h.options, CHANNEL_ID, signedTx);
        expect(h.node.calls().at(-1)).toEqual(SUBMIT_CALL);
    });

    it("submits the copy it hashed: writing to the caller's while the channel's record is read changes nothing", async () => {
        const h = await opened();
        const signedTx = structuredClone(SIGNED_TX);
        const resolve = h.store.resolveChannelIndex.bind(h.store);
        jest.spyOn(h.store, "resolveChannelIndex").mockImplementationOnce(async (channelId) => {
            const output = signedTx.outputs[1];
            if (output !== undefined) output.capacityShannons += 1n;
            return resolve(channelId);
        });
        h.node.result(SUBMIT_ANSWER);
        await submitSdkFundingTx(h.options, CHANNEL_ID, signedTx);
        expect(h.node.calls().at(-1)).toEqual(SUBMIT_CALL);
    });

    it("lets the node's refusal through unwrapped", async () => {
        const h = await opened();
        h.node.error(-32000, "Repeated processing message: Signed funding tx has already been submitted");
        const error = await rejection(submitSdkFundingTx(h.options, CHANNEL_ID, SIGNED_TX));
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({
            method: "submit_signed_funding_tx",
            message: "Repeated processing message: Signed funding tx has already been submitted",
        });
    });

    it("lets an unknown outcome through, keeping the pending opening", async () => {
        const h = await opened();
        h.node.reject(new Error("offline"));
        expect(await rejection(submitSdkFundingTx(h.options, CHANNEL_ID, SIGNED_TX))).toBeInstanceOf(RpcTransportError);
        expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
    });

    describe("its arguments", () => {
        it.each<[string, unknown, unknown, TypeError]>([
            ["no channel id", undefined, SIGNED_TX, new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex")],
            [
                "a channel id in bare hex",
                CHANNEL_ID.slice(2),
                SIGNED_TX,
                new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
            ],
            [
                "a channel id in upper case",
                CHANNEL_ID.toUpperCase().replace("0X", "0x"),
                SIGNED_TX,
                new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
            ],
            [
                "a channel id of 31 bytes",
                CHANNEL_ID.slice(0, -2),
                SIGNED_TX,
                new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
            ],
            ["no signed tx", CHANNEL_ID, undefined, new TypeError("signedTx must be an object")],
            ["a null signed tx", CHANNEL_ID, null, new TypeError("signedTx must be an object")],
            ["a signed tx in an array", CHANNEL_ID, [SIGNED_TX], new TypeError("signedTx must be an object")],
            [
                "a signed tx without witnesses",
                CHANNEL_ID,
                withField(SIGNED_TX, "witnesses", undefined),
                new TypeError("signedTx.witnesses must be an array"),
            ],
            [
                "a witness in hex",
                CHANNEL_ID,
                withField(SIGNED_TX, "witnesses[1]", SIGNED_WITNESS),
                new TypeError("signedTx.witnesses[1] must be a Uint8Array"),
            ],
            [
                "a signed tx without inputs",
                CHANNEL_ID,
                withField(SIGNED_TX, "inputs", undefined),
                new TypeError("signedTx is not a transaction: transaction.inputs must be an array"),
            ],
            [
                "an input under a negative since",
                CHANNEL_ID,
                withField(SIGNED_TX, "inputs[0].since", -1n),
                new TypeError(
                    "signedTx is not a transaction: transaction.inputs[0].since must be a bigint between 0 and 18446744073709551615, got -1",
                ),
            ],
            [
                "a fractional version",
                CHANNEL_ID,
                withField(SIGNED_TX, "version", 0.5),
                new TypeError("signedTx is not a transaction: transaction.version must be an integer between 0 and 4294967295, got 0.5"),
            ],
        ])("refuses %s before reading or sending anything", async (_, channelId, signedTx, error) => {
            const h = harness();
            const thrown = await rejection(submitSdkFundingTx(h.options, channelId as string, signedTx as Transaction));
            expect(thrown).toEqual(error);
            expect(thrown).toBeInstanceOf(TypeError);
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
        });

        it("names the channel id first when the signed tx is wrong too", async () => {
            const thrown = await rejection(submitSdkFundingTx(harness().options, CHANNEL_ID.slice(2), undefined as unknown as Transaction));
            expect(thrown).toEqual(new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"));
        });

        it("keeps what refused the transaction as the cause", async () => {
            const thrown = await rejection(submitSdkFundingTx(harness().options, CHANNEL_ID, withField(SIGNED_TX, "inputs", undefined)));
            expect((thrown as TypeError).cause).toEqual(new TypeError("transaction.inputs must be an array"));
        });
    });
});

describe("openSdkChannel", () => {
    it("opens, has the host sign a copy of the frozen tx, unbound, and submits what it signed", async () => {
        const h = harness();
        const received: { tx: Transaction; receiver: unknown }[] = [];
        const sign = async function (this: unknown, tx: Transaction): Promise<Transaction> {
            received.push({ tx: structuredClone(tx), receiver: this });
            return SIGNED_TX;
        };
        h.node.result(OPEN_ANSWER).result(SUBMIT_ANSWER);
        await expect(openSdkChannel(h.options, AMOUNT, USER_LOCK, sign)).resolves.toBe(CHANNEL_ID);
        expect(received).toStrictEqual([{ tx: UNSIGNED_TX, receiver: undefined }]);
        expect(h.node.calls()).toEqual([openCall(), SUBMIT_CALL]);
    });

    it("refuses what the host signed after writing to the tx it was handed: the cell is pinned by its hash", async () => {
        const h = harness();
        const sign = async (tx: Transaction): Promise<Transaction> => {
            const output = tx.outputs[1];
            if (output === undefined) throw new Error("no change output");
            output.capacityShannons += 1n;
            return { ...tx, witnesses: SIGNED_TX.witnesses };
        };
        h.node.result(OPEN_ANSWER);
        expect(await rejection(openSdkChannel(h.options, AMOUNT, USER_LOCK, sign))).toMatchObject({ code: "funding_tx_altered" });
        expect(h.node.calls()).toEqual([openCall()]);
        expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
    });

    it("lets the host's refusal through, keeping the opening for a retry that resumes it", async () => {
        const h = harness();
        const declined = new Error("the user declined");
        h.node.result(OPEN_ANSWER);
        expect(await rejection(openSdkChannel(h.options, AMOUNT, USER_LOCK, () => Promise.reject(declined)))).toBe(declined);
        expect(h.node.calls()).toEqual([openCall()]);
        expect(storedAt(h.storage, OPENING_KEY)).toEqual(pendingOf(INDEX, CHANNEL_ID));
        h.node
            .result({ channels: [{ channel_id: CHANNEL_ID, state: OPENING_STATE }] })
            .result(OPEN_ANSWER)
            .result(SUBMIT_ANSWER);
        await expect(openSdkChannel(h.options, AMOUNT, USER_LOCK, async () => SIGNED_TX)).resolves.toBe(CHANNEL_ID);
        expect(h.node.calls()).toEqual([openCall(), ONLY_PENDING_CALL, openCall(), SUBMIT_CALL]);
    });

    it("refuses what the host's signer hands back when it is not a transaction, submitting nothing", async () => {
        const h = harness();
        h.node.result(OPEN_ANSWER);
        const thrown = await rejection(openSdkChannel(h.options, AMOUNT, USER_LOCK, async () => undefined as unknown as Transaction));
        expect(thrown).toEqual(new TypeError("signedTx must be an object"));
        expect(h.node.calls()).toEqual([openCall()]);
    });

    it.each<[string, unknown, unknown, unknown, unknown, Error]>([
        ["no signer", AMOUNT, USER_LOCK, undefined, undefined, new TypeError("signFundingInputs must be a function")],
        [
            "a signer that is an object",
            AMOUNT,
            USER_LOCK,
            { sign: async () => SIGNED_TX },
            undefined,
            new TypeError("signFundingInputs must be a function"),
        ],
        ["a signer in a string", AMOUNT, USER_LOCK, "sign", undefined, new TypeError("signFundingInputs must be a function")],
        [
            "no amount, before the signer",
            undefined,
            USER_LOCK,
            undefined,
            undefined,
            new TypeError("amountShannons must be an amount in decimal shannons"),
        ],
        ["no lock, before the signer", AMOUNT, undefined, undefined, undefined, new TypeError("userLock must be an object")],
        [
            "an amount below the device's reserve",
            "9899999999",
            USER_LOCK,
            async () => SIGNED_TX,
            undefined,
            new RangeError("fundedShannons 9899999999 is below the 9900000000 the device's reserve takes over that close script"),
        ],
        [
            "cell deps that are not a list",
            AMOUNT,
            USER_LOCK,
            async () => SIGNED_TX,
            CELL_DEPS[0],
            new TypeError("userLockCellDeps must be an array"),
        ],
        [
            "a cell dep that is not an object",
            AMOUNT,
            USER_LOCK,
            async () => SIGNED_TX,
            [CELL_DEPS[0], "dep"],
            new TypeError("userLockCellDeps[1] must be an object"),
        ],
        [
            "a cell dep with a dep type in camel case",
            AMOUNT,
            USER_LOCK,
            async () => SIGNED_TX,
            [{ outPoint: { txHash: new Uint8Array(32), index: 2 }, depType: "depGroup" }],
            new TypeError("userLockCellDeps[0].depType must be one of code, dep_group"),
        ],
        [
            "no signer and cell deps that are not a list, the signer named first",
            AMOUNT,
            USER_LOCK,
            undefined,
            CELL_DEPS[0],
            new TypeError("signFundingInputs must be a function"),
        ],
    ])("refuses %s, writing and sending nothing", async (_, amount, lock, sign, deps, error) => {
        const h = harness();
        const thrown = await rejection(
            openSdkChannel(h.options, amount as string, lock as Script, sign as () => Promise<Transaction>, deps as CellDep[]),
        );
        expect(thrown).toEqual(error);
        expect(thrown).toBeInstanceOf(error.constructor);
        expect(h.storage.ops).toEqual([]);
        expect(h.node.calls()).toEqual([]);
    });
});
