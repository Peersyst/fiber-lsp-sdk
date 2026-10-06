import { bytesToHex } from "@noble/hashes/utils.js";
import { MILLISECONDS_PER_SECOND, truncatePaymentHash } from "../common";
import type { SettlementTlc } from "../digest";
import { MAX_EXACT_CHARGE_TLCS, POLICY_VIEWS } from "./policy.constants";
import { refusePolicyRequest } from "./policy.error";
import type { BalanceRuleCommitment, BalanceRuleContext, PolicyView, PolicyViewSnapshot, PolicyViewTlc } from "./policy.types";

/**
 * Reduces a commitment's TLCs to what its settlement witness binds.
 * @param tlcs The TLCs the node attached to the commitment.
 * @returns One entry per TLC, sorted.
 */
export function toPolicyViewTlcs(tlcs: readonly SettlementTlc[]): PolicyViewTlc[] {
    return tlcs
        .map((tlc) => ({
            direction: tlc.direction,
            hashAlgorithm: tlc.hashAlgorithm,
            boundPaymentHash: bytesToHex(truncatePaymentHash(tlc.paymentHash)),
            amountShannons: tlc.amountShannons.toString(),
            expirySeconds: (tlc.expiryMs / MILLISECONDS_PER_SECOND).toString(),
        }))
        .sort((a, b) => compareStrings(tlcKey(a), tlcKey(b)));
}

/**
 * Judges a commitment against its view's previous message.
 * @param view The commitment's view.
 * @param views The channel's two snapshots.
 * @param next What the commitment states.
 * @param context The device-wide records the rule reads.
 * @returns The view's snapshot once the commitment is signed.
 */
export function judgeCommitment(
    view: PolicyView,
    views: Record<PolicyView, PolicyViewSnapshot>,
    next: BalanceRuleCommitment,
    context: BalanceRuleContext,
): PolicyViewSnapshot {
    const previous = views[view];
    const left = multisetDifference(previous.tlcs, next.tlcs);

    const creditedShannons = { ...previous.creditedShannons };
    let credit = 0n;
    let uncreditedReceived = 0n;
    for (const [boundPaymentHash, amount] of sumByHash(left, "received")) {
        const invoice = context.invoices.get(boundPaymentHash);
        const owed = invoice?.released === true ? BigInt(invoice.amountShannons) - creditedAcross(previous, context, boundPaymentHash) : 0n;
        const credited = min(amount, max(owed, 0n));
        if (credited > 0n)
            creditedShannons[boundPaymentHash] = (readAmount(previous.creditedShannons, boundPaymentHash) + credited).toString();
        credit += credited;
        // Unreleased, a held TLC can only have failed.
        if (invoice?.released !== false) uncreditedReceived += amount - credited;
    }

    const shortfall = holdings(BigInt(previous.exposureShannons), previous.tlcs) + credit - holdings(next.exposureShannons, next.tlcs);
    const chargedShannons = { ...previous.chargedShannons };
    const chargedNow = chargedTlcs(view, left, shortfall, uncreditedReceived);
    for (const tlc of chargedNow) {
        chargedShannons[tlc.boundPaymentHash] = (readAmount(chargedShannons, tlc.boundPaymentHash) + BigInt(tlc.amountShannons)).toString();
    }

    // A view draws what it shows plus what it charged, so only a hash shown now can draw more.
    const otherView = views[view === "remote" ? "local" : "remote"];
    const drawnBefore = drawnBy(previous);
    const drawnAfter = drawnBy({ tlcs: next.tlcs, chargedShannons });
    const drawnOtherView = drawnBy(otherView);
    const drawnOtherChannels = context.otherChannels.map((other) => [drawnBy(other.remote), drawnBy(other.local)] as const);
    for (const boundPaymentHash of sumByHash(next.tlcs, "offered").keys()) {
        const drawnHere = drawnAfter(boundPaymentHash);
        // A view catching up with the other draws nothing new, even under a closed intent.
        if (drawnHere <= max(drawnBefore(boundPaymentHash), drawnOtherView(boundPaymentHash))) continue;
        const intent = context.intents.get(boundPaymentHash);
        if (intent === undefined) {
            refusePolicyRequest(
                "policy_refusal",
                `the ${view} commitment offers a TLC under ${boundPaymentHash}, which no debit intent covers`,
            );
        }
        if (!intent.open) {
            refusePolicyRequest(
                "policy_refusal",
                `the ${view} commitment draws more under ${boundPaymentHash}, whose debit intent is closed`,
            );
        }
        // The node may broadcast either commitment, so each other channel counts at its worst view.
        let drawn = drawnHere;
        for (const [remote, local] of drawnOtherChannels) drawn += max(remote(boundPaymentHash), local(boundPaymentHash));
        if (drawn > BigInt(intent.maxShannons)) {
            refusePolicyRequest(
                "policy_refusal",
                `the ${view} view draws ${drawn} shannons under ${boundPaymentHash}, above its debit intent of ${intent.maxShannons}`,
            );
        }
    }

    // A released held TLC failing beside an offered one of its amount reads as both paid: a channel showing both may only shrink.
    const grows = mixesReleasedHeld([multisetDifference(next.tlcs, previous.tlcs)], context, "either");
    const before = mixesReleasedHeld([previous.tlcs, otherView.tlcs], context, "both");
    if (mixesReleasedHeld([next.tlcs, otherView.tlcs], context, "both") && (!before || grows)) {
        refusePolicyRequest(
            "policy_refusal",
            `the ${view} commitment would show an offered TLC beside a held TLC whose preimage was released`,
        );
    }

    // The preimage does not open a TLC under another algorithm.
    for (const tlc of multisetDifference(next.tlcs, previous.tlcs)) {
        const invoice = context.invoices.get(tlc.boundPaymentHash);
        if (tlc.direction === "received" && invoice?.released === true && tlc.hashAlgorithm !== invoice.hashAlgorithm) {
            refusePolicyRequest(
                "policy_refusal",
                `the ${view} commitment adds a TLC under ${tlc.boundPaymentHash} locked with another algorithm than its released invoice`,
            );
        }
    }

    return { exposureShannons: next.exposureShannons.toString(), tlcs: next.tlcs, chargedShannons, creditedShannons };
}

/**
 * Tells whether lists of TLCs show offered TLCs and received TLCs of a released invoice: both kinds, or either.
 * @param lists The TLCs to look at, across a channel's views.
 * @param context Holds the invoices.
 * @param kinds `both` asks for the two kinds at once, `either` for one of them at least.
 * @returns Whether the lists show what was asked.
 */
function mixesReleasedHeld(lists: readonly (readonly PolicyViewTlc[])[], context: BalanceRuleContext, kinds: "both" | "either"): boolean {
    const tlcs = lists.flat();
    const offered = tlcs.some((tlc) => tlc.direction === "offered");
    const releasedHeld = tlcs.some((tlc) => tlc.direction === "received" && context.invoices.get(tlc.boundPaymentHash)?.released === true);
    return kinds === "both" ? offered && releasedHeld : offered || releasedHeld;
}

/**
 * Judges a cooperative close: no TLC left, and at least what both views last showed.
 * @param views The channel's two snapshots.
 * @param toLocalShannons What the close pays the device, before the reserve and the fee.
 */
export function judgeShutdown(views: Record<PolicyView, PolicyViewSnapshot>, toLocalShannons: bigint): void {
    for (const view of POLICY_VIEWS) {
        const snapshot = views[view];
        if (snapshot.tlcs.length > 0) {
            refusePolicyRequest("policy_refusal", `a cooperative close while the ${view} commitment still lists TLCs`);
        }
        if (toLocalShannons < BigInt(snapshot.exposureShannons)) {
            refusePolicyRequest(
                "policy_refusal",
                `the close pays the device ${toLocalShannons} shannons, below the ${snapshot.exposureShannons} of the ${view} commitment`,
            );
        }
    }
}

/**
 * Picks the offered TLCs that left a view and could have taken a fall in holdings with them, each one charged in full.
 * @param view The commitment's view, named in refusals.
 * @param left TLCs the previous message listed and the commitment does not.
 * @param shortfall What the holdings fell by, past the credit owed.
 * @param uncreditedReceived What received TLCs that left could have raised the holdings by, unasked.
 * @returns The TLCs to charge, none when no set of them fits what may have been paid.
 */
function chargedTlcs(view: PolicyView, left: readonly PolicyViewTlc[], shortfall: bigint, uncreditedReceived: bigint): PolicyViewTlc[] {
    const offered = left.filter((tlc) => tlc.direction === "offered");
    const total = offered.reduce((sum, tlc) => sum + BigInt(tlc.amountShannons), 0n);
    if (total < shortfall) {
        refusePolicyRequest(
            "policy_refusal",
            `the ${view} commitment lowers the holdings by ${shortfall} shannons, which no offered TLC took`,
        );
    }
    // The paid offered TLCs took at least the fall, at most the fall plus what departed received TLCs added unasked.
    const lowest = max(shortfall, 0n);
    const highest = shortfall + uncreditedReceived;
    if (offered.length === 0 || highest <= 0n) return [];
    if (offered.length > MAX_EXACT_CHARGE_TLCS) return offered;

    const amounts = offered.map((tlc) => BigInt(tlc.amountShannons));
    const charged = new Set<number>();
    for (let subset = 1; subset < 1 << offered.length; subset++) {
        let sum = 0n;
        for (const [index, amount] of amounts.entries()) {
            if ((subset & (1 << index)) !== 0) sum += amount;
        }
        if (sum < lowest || sum > highest) continue;
        for (const index of offered.keys()) {
            if ((subset & (1 << index)) !== 0) charged.add(index);
        }
    }
    if (charged.size === 0 && shortfall > 0n) {
        refusePolicyRequest(
            "policy_refusal",
            `the ${view} commitment lowers the holdings by ${shortfall} shannons, which no set of the offered TLCs that left accounts for`,
        );
    }
    return offered.filter((_, index) => charged.has(index));
}

/**
 * Computes what the device holds in a view if every offered TLC comes back.
 * @param exposure The view's settlement amount.
 * @param tlcs The TLCs it lists.
 * @returns The exposure plus every offered amount.
 */
function holdings(exposure: bigint, tlcs: readonly PolicyViewTlc[]): bigint {
    return tlcs.reduce((sum, tlc) => (tlc.direction === "offered" ? sum + BigInt(tlc.amountShannons) : sum), exposure);
}

/**
 * Sums what an invoice is surely paid: this view's credit, and each other channel's at its less paid view.
 * @param previous This channel's snapshot of the view.
 * @param context Holds both views of the other channels.
 * @param boundPaymentHash Bound payment hash of the invoice.
 * @returns The credited total.
 */
function creditedAcross(previous: PolicyViewSnapshot, context: BalanceRuleContext, boundPaymentHash: string): bigint {
    return context.otherChannels.reduce(
        (sum, other) =>
            sum +
            min(readAmount(other.remote.creditedShannons, boundPaymentHash), readAmount(other.local.creditedShannons, boundPaymentHash)),
        readAmount(previous.creditedShannons, boundPaymentHash),
    );
}

/**
 * Reads what a view draws on each payment's budget: the offered TLCs it shows under a hash and what it charged to it.
 * @param snapshot What the view lists and what it charged.
 * @returns A reader of the amount drawn under a bound payment hash.
 */
function drawnBy(snapshot: Pick<PolicyViewSnapshot, "tlcs" | "chargedShannons">): (boundPaymentHash: string) => bigint {
    const shown = sumByHash(snapshot.tlcs, "offered");
    return (boundPaymentHash) => (shown.get(boundPaymentHash) ?? 0n) + readAmount(snapshot.chargedShannons, boundPaymentHash);
}

/**
 * Sums the TLCs of one direction per bound payment hash.
 * @param tlcs TLCs to sum.
 * @param direction Direction to keep.
 * @returns The sum per hash, holding only hashes with a TLC of that direction.
 */
function sumByHash(tlcs: readonly PolicyViewTlc[], direction: PolicyViewTlc["direction"]): Map<string, bigint> {
    const sums = new Map<string, bigint>();
    for (const tlc of tlcs) {
        if (tlc.direction !== direction) continue;
        sums.set(tlc.boundPaymentHash, (sums.get(tlc.boundPaymentHash) ?? 0n) + BigInt(tlc.amountShannons));
    }
    return sums;
}

/**
 * Removes from one multiset of TLCs every entry another one holds, counting repeats.
 * @param from The TLCs to remove from.
 * @param remove The TLCs to remove.
 * @returns What `from` lists beyond `remove`.
 */
function multisetDifference(from: readonly PolicyViewTlc[], remove: readonly PolicyViewTlc[]): PolicyViewTlc[] {
    const remaining = new Map<string, number>();
    for (const tlc of remove) remaining.set(tlcKey(tlc), (remaining.get(tlcKey(tlc)) ?? 0) + 1);
    return from.filter((tlc) => {
        const count = remaining.get(tlcKey(tlc)) ?? 0;
        if (count === 0) return true;
        remaining.set(tlcKey(tlc), count - 1);
        return false;
    });
}

/**
 * Names a TLC by everything the witness binds of it.
 * @param tlc TLC to name.
 * @returns A key two TLCs share when the witness cannot tell them apart.
 */
function tlcKey(tlc: PolicyViewTlc): string {
    return `${tlc.direction}:${tlc.hashAlgorithm}:${tlc.boundPaymentHash}:${tlc.amountShannons}:${tlc.expirySeconds}`;
}

/**
 * Reads an amount out of a per-hash map, absent meaning zero.
 * @param amounts Map of decimal shannons by bound payment hash.
 * @param boundPaymentHash Hash to read.
 * @returns The amount.
 */
function readAmount(amounts: Readonly<Record<string, string>>, boundPaymentHash: string): bigint {
    return BigInt(amounts[boundPaymentHash] ?? "0");
}

/**
 * Orders two strings by code unit.
 * @param a First string.
 * @param b Second string.
 * @returns Negative, zero or positive, as `a` sorts before, with or after `b`.
 */
function compareStrings(a: string, b: string): number {
    if (a === b) return 0;
    return a < b ? -1 : 1;
}

/**
 * Picks the smaller of two amounts.
 * @param a First amount.
 * @param b Second amount.
 * @returns The smaller one.
 */
function min(a: bigint, b: bigint): bigint {
    return a < b ? a : b;
}

/**
 * Picks the larger of two amounts.
 * @param a First amount.
 * @param b Second amount.
 * @returns The larger one.
 */
function max(a: bigint, b: bigint): bigint {
    return a > b ? a : b;
}
