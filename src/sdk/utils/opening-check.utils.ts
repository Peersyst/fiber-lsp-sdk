import { equalBytes } from "@noble/curves/utils.js";
import type { Script } from "../../common";
import { UINT64_MAX, copyScript, isCompressedPoint, moleculeScript } from "../../common";
import { COMMITMENT_LOCK_LAYOUTS, fundingLockArgs, tenantChannelId } from "../../digest";
import { reservedCkbShannons } from "../../policy";
import type { OpenTenantChannelResult, TenantChannelOpeningContext } from "../../rpc";
import { FUNDING_OUTPUT_INDEX } from "../sdk.constants";
import { SdkError } from "../sdk.error";
import type { SdkOpeningPins, SdkOpeningRequest } from "../sdk.types";

type OpeningReserves = { local: bigint; remote: bigint };

const FUNDING_OUTPUT = `unsignedFundingTx.outputs[${FUNDING_OUTPUT_INDEX}]`;

const FUNDING_OUTPUT_DATA = `unsignedFundingTx.outputsData[${FUNDING_OUTPUT_INDEX}]`;

/**
 * Checks the node's answer to `open_tenant_channel` against what was asked, before anything of it is pinned.
 * @param request What the device asked, with its own keys and the network's funding lock.
 * @param answer The node's answer.
 * @returns The terms and the funding cell's capacity the policy pins; a failed check throws `opening_rejected`.
 */
export function checkTenantOpening(request: SdkOpeningRequest, answer: OpenTenantChannelResult): SdkOpeningPins {
    const context = answer.openingContext;
    checkTenantChannelId(request, answer);
    if (context.commitmentDelayEpoch !== request.commitmentDelayEpoch) {
        rejectOpening(
            "openingContext.commitmentDelayEpoch",
            `is ${context.commitmentDelayEpoch}, not the ${request.commitmentDelayEpoch} asked`,
        );
    }
    if (context.commitmentFeeRate !== request.commitmentFeeRate) {
        rejectOpening("openingContext.commitmentFeeRate", `is ${context.commitmentFeeRate}, not the ${request.commitmentFeeRate} asked`);
    }
    const local = BigInt(context.localAmountShannons);
    if (local !== BigInt(request.fundedShannons)) {
        rejectOpening("openingContext.localAmountShannons", `is ${local}, not the ${request.fundedShannons} funded`);
    }
    const reserves = checkOpeningReserves(request.userLock, context);
    if (local < reserves.local) {
        rejectOpening("openingContext.localAmountShannons", `${local} is below the device's reserve ${reserves.local}`);
    }
    const remote = BigInt(context.remoteAmountShannons);
    if (remote < reserves.remote) {
        rejectOpening("openingContext.remoteAmountShannons", `${remote} is below the peer's reserve ${reserves.remote}`);
    }
    const capacity = local + remote;
    checkFundingOutput(request, answer, capacity);
    return {
        terms: {
            commitmentFeeRate: context.commitmentFeeRate,
            remoteReservedCkbShannons: reserves.remote.toString(),
            liquidCapacityShannons: (capacity - reserves.local - reserves.remote).toString(),
            remoteCloseScript: copyScript(context.remoteShutdownScript),
            remoteFundingPubkey: Uint8Array.from(context.remoteFundingKey),
            remoteTlcBasePubkey: Uint8Array.from(context.remoteSettlementKey),
            commitmentDelayEpoch: context.commitmentDelayEpoch,
        },
        fundingCapacityShannons: capacity.toString(),
    };
}

/**
 * Checks that the channel id is fiber's id of the two TLC base keys, the peer's being `remote_settlement_key`.
 * @param request What the device asked.
 * @param answer The node's answer.
 */
function checkTenantChannelId(request: SdkOpeningRequest, answer: OpenTenantChannelResult): void {
    const settlementKey = answer.openingContext.remoteSettlementKey;
    checkRemoteKey("openingContext.remoteSettlementKey", settlementKey, request.tlcBasePubkey, "TLC base");
    const expected = tenantChannelId(request.tlcBasePubkey, settlementKey);
    if (answer.channelId !== expected) {
        rejectOpening("channelId", `${answer.channelId} is not ${expected}, the id of the two TLC base keys`);
    }
}

/**
 * Checks that both reserves are fiber's over their close scripts, under one lock layout, whichever.
 * @param userLock The device's close script.
 * @param context The node's opening context.
 * @returns The two reserves.
 */
function checkOpeningReserves(userLock: Script, context: TenantChannelOpeningContext): OpeningReserves {
    const local = BigInt(context.localReservedCkbShannons);
    const layouts = COMMITMENT_LOCK_LAYOUTS.filter((layout) => reservedCkbShannons(userLock, layout) === local);
    if (layouts.length === 0) {
        rejectOpening("openingContext.localReservedCkbShannons", `${local} is not the device's reserve over its lock under either layout`);
    }
    const remote = BigInt(context.remoteReservedCkbShannons);
    if (!layouts.some((layout) => reservedCkbShannons(context.remoteShutdownScript, layout) === remote)) {
        rejectOpening(
            "openingContext.remoteReservedCkbShannons",
            `${remote} is not the peer's reserve over its shutdown script under the device's layout`,
        );
    }
    return { local, remote };
}

/**
 * Checks the funding cell: no type, no data, the channel's funding lock, and the two amounts as its capacity.
 * @param request What the device asked.
 * @param answer The node's answer.
 * @param capacity The local and remote amounts, added.
 */
function checkFundingOutput(request: SdkOpeningRequest, answer: OpenTenantChannelResult, capacity: bigint): void {
    const tx = answer.unsignedFundingTx;
    const output = tx.outputs[FUNDING_OUTPUT_INDEX];
    if (output === undefined) rejectOpening(FUNDING_OUTPUT, "is missing");
    if (output.type !== null) rejectOpening(`${FUNDING_OUTPUT}.type`, "is not null");
    const data = tx.outputsData[FUNDING_OUTPUT_INDEX];
    if (data === undefined) rejectOpening(FUNDING_OUTPUT_DATA, "is missing");
    if (data.length !== 0) rejectOpening(FUNDING_OUTPUT_DATA, "is not empty");
    const remoteFundingKey = answer.openingContext.remoteFundingKey;
    checkRemoteKey("openingContext.remoteFundingKey", remoteFundingKey, request.fundingPubkey, "funding");
    const lock = { ...request.fundingLock, args: fundingLockArgs(request.fundingPubkey, remoteFundingKey) };
    if (!equalBytes(moleculeScript(output.lock, `${FUNDING_OUTPUT}.lock`), moleculeScript(lock))) {
        rejectOpening(`${FUNDING_OUTPUT}.lock`, "is not the network's funding lock over the two funding keys");
    }
    if (capacity > UINT64_MAX) {
        rejectOpening("openingContext.remoteAmountShannons", `takes the two amounts to ${capacity}, past a cell's u64`);
    }
    if (output.capacityShannons !== capacity) {
        rejectOpening(`${FUNDING_OUTPUT}.capacityShannons`, `is ${output.capacityShannons}, not the ${capacity} of the two amounts`);
    }
}

/**
 * Checks that a key the peer states is a point on the curve and not the device's own.
 * @param field The key's path, for the refusal.
 * @param key The peer's key.
 * @param deviceKey The device's key of the same role.
 * @param role The role, for the refusal.
 */
function checkRemoteKey(field: string, key: Uint8Array, deviceKey: Uint8Array, role: string): void {
    if (!isCompressedPoint(key)) rejectOpening(field, "is not a compressed point on secp256k1");
    if (equalBytes(key, deviceKey)) rejectOpening(field, `is the device's own ${role} key`);
}

/**
 * Refuses the node's answer, naming what failed.
 * @param field The answer's field that failed.
 * @param detail What is wrong with it.
 */
function rejectOpening(field: string, detail: string): never {
    throw new SdkError("opening_rejected", `the node's opening is refused: ${field} ${detail}`);
}
