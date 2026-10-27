import { MILLISECONDS_PER_SECOND, UINT64_MAX, assertUnsignedBigInt } from "../common";
import { POLICY_VIEWS } from "./policy.constants";
import { HoldInvoiceError } from "./policy.error";
import type {
    ChannelPins,
    HoldInvoicePolicyRecord,
    HoldInvoiceReleaseChannel,
    HoldInvoiceReleaseReading,
    PolicyViewSnapshot,
    PolicyViewTlc,
} from "./policy.types";
import { boundPaymentHashOf, isTlcOfPaymentRecord } from "./utils";

/**
 * Lists the TLCs of a hold invoice a view shows.
 * @param snapshot The view.
 * @param invoice The invoice.
 * @returns The TLCs, in the view's order.
 */
export function listHoldInvoiceTlcs(snapshot: Pick<PolicyViewSnapshot, "tlcs">, invoice: HoldInvoicePolicyRecord): PolicyViewTlc[] {
    const key = boundPaymentHashOf(invoice.paymentHash);
    // Received only: no intent can take this hash. A twin under the full-hash layout is not the invoice's.
    return snapshot.tlcs.filter((tlc) => tlc.boundPaymentHash === key && isTlcOfPaymentRecord(tlc, invoice));
}

/**
 * Throws a {@link HoldInvoiceError} unless a hold invoice's preimage may be released.
 * @param invoice The invoice, not released.
 * @param channels The invoice's channels, keyed by index.
 * @param timing The clock reading and the release margin.
 */
export function judgeHoldInvoiceRelease(
    invoice: HoldInvoicePolicyRecord,
    channels: ReadonlyMap<number, HoldInvoiceReleaseChannel>,
    timing: HoldInvoiceReleaseReading,
): void {
    const { paymentHash } = invoice;
    const held: HeldChannel[] = [];
    for (const [index, { pins, views }] of channels) {
        const listed = { remote: listHoldInvoiceTlcs(views.remote, invoice), local: listHoldInvoiceTlcs(views.local, invoice) };
        const tlcs = POLICY_VIEWS.flatMap((view) => listed[view]);
        // The preimage does not open a TLC under another algorithm.
        if (tlcs.some((tlc) => tlc.hashAlgorithm !== invoice.hashAlgorithm)) {
            throw new HoldInvoiceError(
                "algorithm_mismatch",
                `channel index ${index} lists a TLC under ${paymentHash} locked with another algorithm than the invoice's`,
            );
        }
        // An offered TLC failing beside a released held one could pass for both being paid.
        if (tlcs.length > 0 && POLICY_VIEWS.some((view) => views[view].tlcs.some((tlc) => tlc.direction === "offered"))) {
            throw new HoldInvoiceError(
                "offered_in_flight",
                `channel index ${index} lists an offered TLC, so the preimage of ${paymentHash} is not released yet`,
            );
        }
        const [remote, local] = [sumAmounts(listed.remote), sumAmounts(listed.local)];
        held.push({ index, pins, tlcs, amount: remote < local ? remote : local });
    }

    // The node may broadcast either view of each channel, so each channel counts at the view holding less.
    const amount = held.reduce((sum, channel) => sum + channel.amount, 0n);
    if (amount < BigInt(invoice.amountShannons)) {
        throw new HoldInvoiceError(
            "not_held",
            `the channels hold ${amount} shannons under ${paymentHash}, each at its view holding less, short of the invoice's ${invoice.amountShannons}`,
        );
    }

    for (const { index, pins, tlcs } of held) {
        if (tlcs.length === 0) continue;
        const deadline = BigInt(timing.nowMs) + releaseMargin(index, pins, timing);
        for (const tlc of tlcs) {
            // The witness binds whole seconds, the ms expiry cut down: never later than the TLC's own.
            const expiryMs = BigInt(tlc.expirySeconds) * MILLISECONDS_PER_SECOND;
            if (expiryMs <= deadline) {
                throw new HoldInvoiceError(
                    "expiry_too_close",
                    `channel index ${index} holds a TLC under ${paymentHash} expiring at ${expiryMs}, not after ${deadline}`,
                );
            }
        }
    }
}

type HeldChannel = {
    index: number;
    pins: Pick<ChannelPins, "commitmentDelayEpoch">;
    // Both views'.
    tlcs: PolicyViewTlc[];
    amount: bigint;
};

/**
 * Computes the margin a channel's held TLCs must clear, from the delay the channel pinned.
 * @param index The channel's index.
 * @param pins The channel's pins.
 * @param timing Holds the margin's function.
 * @returns The margin, in milliseconds.
 */
function releaseMargin(index: number, pins: Pick<ChannelPins, "commitmentDelayEpoch">, timing: HoldInvoiceReleaseReading): bigint {
    const delay = pins.commitmentDelayEpoch;
    // A signed commitment pins its delay, so a view listing a TLC without one is a broken record.
    if (delay === undefined) throw new TypeError(`channel index ${index} lists a TLC of a hold invoice but pins no commitment delay`);
    const margin = timing.releaseMarginMs(BigInt(delay));
    assertUnsignedBigInt("the release margin", margin, UINT64_MAX);
    return margin;
}

/**
 * Sums the amounts of TLCs.
 * @param tlcs The TLCs.
 * @returns The sum, in shannons.
 */
function sumAmounts(tlcs: readonly PolicyViewTlc[]): bigint {
    return tlcs.reduce((sum, tlc) => sum + BigInt(tlc.amountShannons), 0n);
}
