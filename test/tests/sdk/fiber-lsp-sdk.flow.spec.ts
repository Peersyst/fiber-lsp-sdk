import { hexToBytes } from "@noble/hashes/utils.js";
import type { Transaction } from "../../../src/common";
import type { RegisterTenantResult } from "../../../src/rpc";
import { FiberRpcClient, RpcError } from "../../../src/rpc";
import type { SdkEvent, SdkSignFundingInputs } from "../../../src/sdk";
import { FiberLspSdk } from "../../../src/sdk";
import { TimerMock } from "../../mocks/common";
import { InMemorySignerStorage } from "../../mocks/policy";
import { flush } from "../../utils/flush";
import { rejection } from "../../utils/rejection";
import { loadSigningVectors } from "../../utils/signing-vectors";
import { CHANNEL, FUNDED, LSP_PUBKEY, TENANT_NODE_URL, tenantNode, tick } from "../../utils/tenant-flow";
import type { InMemoryTenantNode } from "../../utils/tenant-node";

const vectors = loadSigningVectors();

const MASTER_SEED = hexToBytes(vectors.device.master_seed);

// Past the allocation floor: the opening takes channel index 1_791_367_200.
const NOW_MS = 1_791_367_200_000;

const OPENING_INDEX = 1_791_367_200;

const OPENING_CHANNEL_ID = "0x5df11183f0223c41ea85677270eeaf085d3d2fa00f4a35b1b870b7af25b0287f";

// The RootSigner of the vectors' master seed, and the tenant id fiber derives from it.
const ROOT_SIGNER_PUBKEY = hexToBytes("038dd0502b955500a40aa41114374cdc96ed2c34e85e1473f23ae80cddb0afcb26");

const TENANT_ID = "a42a2ad2f6b771aceed7f964eb25469a8cd292d7f430a918745d7a5a7822fd8f";

// The tenant's own node key, which the LSP generated.
const INVOICE_PUBKEY = hexToBytes("02637f0a756f0eec76becaa6bb6908f0ce642be07ff07471a00bc8ca8a2e0bd215");

const REQUEST_ID = new Uint8Array(32).fill(0x51);

const OTHER_REQUEST_ID = new Uint8Array(32).fill(0x52);

const THIRD_REQUEST_ID = new Uint8Array(32).fill(0x53);

// Fiber's window around its clock (`fiber-types/src/hosted_lsp.rs:16-20`).
const MAX_AGE_MS = 300_000n;

const MAX_FUTURE_SKEW_MS = 30_000n;

// A `WitnessArgs` whose 65-byte lock stands for the user's signature.
const SIGNED_WITNESS = hexToBytes(`5500000010000000550000005500000041000000${"5a".repeat(65)}`);

type RegistrationFlow = {
    node: InMemoryTenantNode;
    sdk: FiberLspSdk;
    // The host's client under the operator's token, which the double does not check.
    operator: FiberRpcClient;
    timer: TimerMock;
    clock: { nowMs: number };
    events: SdkEvent[];
};

function flow(lspPubkey = LSP_PUBKEY): RegistrationFlow {
    const clock = { nowMs: NOW_MS };
    const now = (): number => clock.nowMs;
    const node = tenantNode([OPENING_INDEX], now);
    const timer = new TimerMock();
    const sdk = new FiberLspSdk(MASTER_SEED, {
        network: "testnet",
        storage: new InMemorySignerStorage(),
        rpcUrl: TENANT_NODE_URL,
        lspPubkey,
        fetch: node.fetch,
        timer,
        now,
        nonceReuse: "allow",
    });
    const events: SdkEvent[] = [];
    sdk.onEvent((event) => events.push(event));
    return { node, sdk, operator: new FiberRpcClient({ url: TENANT_NODE_URL, fetch: node.fetch }), timer, clock, events };
}

function register(h: RegistrationFlow, requestId: Uint8Array, signedAtMs: bigint): Promise<RegisterTenantResult> {
    return h.operator.registerTenant(h.sdk.signTenantRegistration({ requestId, signedAtMs }));
}

const signFundingInputs: SdkSignFundingInputs = (unsigned: Transaction) =>
    Promise.resolve({ ...unsigned, witnesses: unsigned.witnesses.map(() => SIGNED_WITNESS) });

describe("the tenant registration over the tenant node", () => {
    it("registers the RootSigner the device signs for, its runtime cold and no channel bound", async () => {
        const h = flow();
        expect(await register(h, REQUEST_ID, BigInt(NOW_MS))).toEqual({
            tenant: {
                tenantId: TENANT_ID,
                rootSignerPubkey: ROOT_SIGNER_PUBKEY,
                invoicePubkey: INVOICE_PUBKEY,
                channels: [],
                createdAtMs: BigInt(NOW_MS),
                runtimeStatus: "cold",
            },
            accessToken: "tenant node token 1",
        });
        expect(h.sdk.tenantId).toBe(TENANT_ID);
        expect(h.node.calls.map((call) => call.method)).toEqual(["lsp_register_tenant"]);
    });

    it("refreshes the tenant under a fresh request id once its channel is ready, the channel bound and online", async () => {
        const h = flow();
        await register(h, REQUEST_ID, BigInt(NOW_MS));
        h.sdk.connect();
        await flush();
        expect(await h.sdk.openChannel(FUNDED, CHANNEL.localCloseScript, signFundingInputs)).toBe(OPENING_CHANNEL_ID);
        await tick(h, 3);
        expect(h.events.map((event) => event.type)).toEqual(["SIGNING", "SIGNING", "CHANNEL_READY"]);
        h.clock.nowMs += 60_000;
        expect(await register(h, OTHER_REQUEST_ID, BigInt(h.clock.nowMs))).toEqual({
            tenant: {
                tenantId: TENANT_ID,
                rootSignerPubkey: ROOT_SIGNER_PUBKEY,
                invoicePubkey: INVOICE_PUBKEY,
                channels: [{ channelId: OPENING_CHANNEL_ID, fundingUdtTypeScript: null, online: true }],
                createdAtMs: BigInt(NOW_MS),
                runtimeStatus: "active",
            },
            accessToken: "tenant node token 2",
        });
    });

    it("refreshes the tenant still cold after signing-status reads alone, and active once a call starts its runtime", async () => {
        const h = flow();
        // Before the registration the call is the operator's, which starts no tenant's runtime.
        expect(await h.operator.listChannels()).toEqual([]);
        expect((await register(h, REQUEST_ID, BigInt(NOW_MS))).tenant.runtimeStatus).toBe("cold");
        expect(await rejection(h.operator.getChannelSigningStatus({ channelId: OPENING_CHANNEL_ID }))).toBeInstanceOf(RpcError);
        expect(await rejection(h.operator.getWatchtowerSigningStatus({ channelId: OPENING_CHANNEL_ID }))).toBeInstanceOf(RpcError);
        expect(
            await rejection(
                h.operator.submitWatchtowerSignature({
                    channelId: OPENING_CHANNEL_ID,
                    requestId: new Uint8Array(32).fill(0x61),
                    signature: new Uint8Array(65).fill(0x62),
                }),
            ),
        ).toBeInstanceOf(RpcError);
        expect((await register(h, OTHER_REQUEST_ID, BigInt(NOW_MS))).tenant.runtimeStatus).toBe("cold");
        expect(await h.operator.listChannels()).toEqual([]);
        expect((await register(h, THIRD_REQUEST_ID, BigInt(NOW_MS))).tenant.runtimeStatus).toBe("active");
        expect(h.node.calls.map((call) => call.method)).toEqual([
            "list_channels",
            "lsp_register_tenant",
            "get_channel_signing_status",
            "get_watchtower_signing_status",
            "submit_watchtower_signature",
            "lsp_register_tenant",
            "list_channels",
            "lsp_register_tenant",
        ]);
    });

    it("is refused a request id the node consumed, whatever the signing time", async () => {
        const h = flow();
        await register(h, REQUEST_ID, BigInt(NOW_MS));
        const replayed = await rejection(register(h, REQUEST_ID, BigInt(NOW_MS) + 1n));
        expect(replayed).toBeInstanceOf(RpcError);
        expect(replayed).toMatchObject({
            method: "lsp_register_tenant",
            code: -32000,
            message: "tenant registration request was already consumed",
        });
        expect((await register(h, OTHER_REQUEST_ID, BigInt(NOW_MS) + 1n)).accessToken).toBe("tenant node token 2");
    });

    it.each([
        ["five minutes old", BigInt(NOW_MS) - MAX_AGE_MS],
        ["thirty seconds ahead", BigInt(NOW_MS) + MAX_FUTURE_SKEW_MS],
    ])("is accepted signed %s, the bounds of the node's window", async (_, signedAtMs) => {
        expect((await register(flow(), REQUEST_ID, signedAtMs)).tenant.tenantId).toBe(TENANT_ID);
    });

    it.each([
        ["a millisecond more than five minutes old", BigInt(NOW_MS) - MAX_AGE_MS - 1n, "too old"],
        ["a millisecond more than thirty seconds ahead", BigInt(NOW_MS) + MAX_FUTURE_SKEW_MS + 1n, "too far in the future"],
        ["at the epoch", 0n, "too old"],
        ["at u64's maximum", (1n << 64n) - 1n, "too far in the future"],
    ])("is refused signed %s, which the device signs without judging, consuming nothing", async (_, signedAtMs, why) => {
        const h = flow();
        const refused = await rejection(register(h, REQUEST_ID, signedAtMs));
        expect(refused).toBeInstanceOf(RpcError);
        expect(refused).toMatchObject({
            method: "lsp_register_tenant",
            code: -32000,
            message: `invalid RootSigner registration proof: tenant registration signed_at is ${why}`,
        });
        expect((await register(h, REQUEST_ID, BigInt(NOW_MS))).tenant.tenantId).toBe(TENANT_ID);
    });

    it("is refused when the device names another LSP than the node: the signature is over another payload", async () => {
        const h = flow(hexToBytes(vectors.peer.funding_pubkey));
        const refused = await rejection(register(h, REQUEST_ID, BigInt(NOW_MS)));
        expect(refused).toBeInstanceOf(RpcError);
        expect(refused).toMatchObject({
            method: "lsp_register_tenant",
            code: -32000,
            message: "invalid RootSigner registration proof: signature failed verification",
        });
    });
});
