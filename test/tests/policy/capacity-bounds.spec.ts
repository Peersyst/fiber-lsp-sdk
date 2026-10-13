import { PolicyRefusalError } from "../../../src/policy";
import { judgeCapacityBounds } from "../../../src/policy/capacity-bounds";
import { toChannelAnnouncementInput, toCommitmentTxInput, toRevocationInput, toShutdownTxInput } from "../../utils/digest-inputs";
import { caseOf, loadInteropVectors } from "../../utils/interop-vectors";

const digest = loadInteropVectors().digest;

// Its mock commitment tx is 456 bytes, and its mock close 540.
const COMMITMENT = toCommitmentTxInput(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote"), digest.remote);
const THREE_TLCS = toCommitmentTxInput(caseOf(digest.commitment_cases, "ckb, three tlcs, for remote"), digest.remote);
const REVOCATION = toRevocationInput(caseOf(digest.revocation_cases, "ckb, send side"), digest.remote);
const SHUTDOWN = toShutdownTxInput(caseOf(digest.shutdown_cases, "ckb"), digest.remote);

function refusalOf(judge: () => unknown): PolicyRefusalError {
    try {
        judge();
    } catch (error) {
        if (error instanceof PolicyRefusalError) return error;
        throw error;
    }
    throw new Error("expected a policy refusal");
}

describe("judgeCapacityBounds", () => {
    it.each([
        ["a commitment", { kind: "commitment_tx" as const, input: COMMITMENT }],
        ["a commitment with TLCs", { kind: "commitment_tx" as const, input: THREE_TLCS }],
        ["a revocation", { kind: "revocation" as const, input: REVOCATION }],
        ["a close", { kind: "shutdown_tx" as const, input: SHUTDOWN }],
        [
            "an announcement",
            {
                kind: "channel_announcement" as const,
                input: toChannelAnnouncementInput(caseOf(digest.announcement_cases, "ckb"), digest.remote),
            },
        ],
    ])("passes %s fiber built at its default rates", (_, operation) => {
        expect(() => judgeCapacityBounds(operation)).not.toThrow();
    });

    describe("the commitment fee", () => {
        it.each([
            ["a commitment", (rate: bigint) => ({ kind: "commitment_tx" as const, input: { ...COMMITMENT, commitmentFeeRate: rate } })],
            ["a revocation", (rate: bigint) => ({ kind: "revocation" as const, input: { ...REVOCATION, commitmentFeeRate: rate } })],
        ])("passes %s whose fee is exactly half the reserve's margin, and refuses one shannon more", (_, operation) => {
            expect(() => judgeCapacityBounds(operation(109_649_124n))).not.toThrow();
            const refusal = refusalOf(() => judgeCapacityBounds(operation(109_649_125n)));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("the commitment fee is 50000001 shannons, above the 50000000 the reserve keeps for it");
        });

        it("sizes the fee over the cell deps the request states", () => {
            const operation = {
                kind: "commitment_tx" as const,
                input: { ...COMMITMENT, commitmentFeeRate: 109_649_124n, cellDepsCount: 3 },
            };
            expect(refusalOf(() => judgeCapacityBounds(operation)).message).toBe(
                "the commitment fee is 54057018 shannons, above the 50000000 the reserve keeps for it",
            );
        });
    });

    describe("the close fee", () => {
        it("passes a local fee of exactly the reserve's margin, and refuses one shannon more", () => {
            expect(() => judgeCapacityBounds({ kind: "shutdown_tx", input: { ...SHUTDOWN, localFeeRate: 185_185_187n } })).not.toThrow();
            const refusal = refusalOf(() =>
                judgeCapacityBounds({ kind: "shutdown_tx", input: { ...SHUTDOWN, localFeeRate: 185_185_188n } }),
            );
            expect(refusal.message).toBe("the close takes a local fee of 100000001 shannons, above the 100000000 the reserve keeps for it");
        });

        it("leaves the peer's fee to the peer", () => {
            expect(() => judgeCapacityBounds({ kind: "shutdown_tx", input: { ...SHUTDOWN, remoteFeeRate: 10n ** 12n } })).not.toThrow();
        });
    });

    describe("what a commitment pays out", () => {
        it("passes a settlement and TLCs that sum to exactly the liquid capacity", () => {
            expect(THREE_TLCS.settlementLocalShannons + THREE_TLCS.settlementRemoteShannons + 4_500_000_000n).toBe(
                THREE_TLCS.toLocalShannons + THREE_TLCS.toRemoteShannons,
            );
            expect(() => judgeCapacityBounds({ kind: "commitment_tx", input: THREE_TLCS })).not.toThrow();
        });

        it.each([
            ["the device's settlement", { settlementLocalShannons: THREE_TLCS.settlementLocalShannons + 1n }],
            ["the peer's settlement", { settlementRemoteShannons: THREE_TLCS.settlementRemoteShannons + 1n }],
            [
                "a TLC",
                { tlcs: THREE_TLCS.tlcs.map((tlc, index) => (index === 0 ? { ...tlc, amountShannons: tlc.amountShannons + 1n } : tlc)) },
            ],
        ])("refuses one shannon more in %s than the liquid capacity holds", (_, override) => {
            const refusal = refusalOf(() => judgeCapacityBounds({ kind: "commitment_tx", input: { ...THREE_TLCS, ...override } }));
            expect(refusal.message).toBe(
                "the commitment's settlement pays 80500000001 shannons with its TLCs, above the channel's liquid capacity of 80500000000",
            );
        });

        // Fiber's own view while a removal awaits its ack: the TLC is unlisted but still deducted.
        it("passes a commitment that pays out less", () => {
            const input = { ...THREE_TLCS, tlcs: THREE_TLCS.tlcs.slice(1) };
            expect(() => judgeCapacityBounds({ kind: "commitment_tx", input })).not.toThrow();
        });

        it("refuses raw balances that hold less than the settlement pays", () => {
            const input = { ...COMMITMENT, toLocalShannons: 0n, toRemoteShannons: 0n };
            expect(refusalOf(() => judgeCapacityBounds({ kind: "commitment_tx", input })).message).toBe(
                "the commitment's settlement pays 80500000000 shannons with its TLCs, above the channel's liquid capacity of 0",
            );
        });
    });
});
