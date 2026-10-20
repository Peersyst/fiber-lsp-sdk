import { calculateCommitmentTxFee } from "../digest";
import { MAX_COMMITMENT_FEE_SHANNONS } from "./policy.constants";
import { refusePolicyRequest } from "./policy.error";
import type { SignOperation } from "./policy.types";

/**
 * Judges what an operation takes out of the funding cell beyond the amounts it states: the fees, and what its witness pays.
 * @param operation The operation, whose digest already matched.
 */
export function judgeCapacityBounds(operation: SignOperation): void {
    switch (operation.kind) {
        case "commitment_tx": {
            const { input } = operation;
            assertCommitmentFee(calculateCommitmentTxFee(input));
            // Not an equality: fiber's own view pays less while a removal awaits its ack.
            const paid = input.tlcs.reduce(
                (sum, tlc) => sum + tlc.amountShannons,
                input.settlementLocalShannons + input.settlementRemoteShannons,
            );
            const liquid = input.liquidCapacityShannons;
            if (paid > liquid) {
                refusePolicyRequest(
                    "policy_refusal",
                    `the commitment's settlement pays ${paid} shannons with its TLCs, above the channel's liquid capacity of ${liquid}`,
                );
            }
            return;
        }
        case "revocation":
            assertCommitmentFee(calculateCommitmentTxFee(operation.input));
            return;
        // A close states no fee rate: the balance rule bounds its fee on the payout.
        case "closing_tx":
        case "channel_announcement":
            return;
    }
}

/**
 * Refuses a commitment fee past the reserve's margin.
 * @param fee The fee, in shannons.
 */
function assertCommitmentFee(fee: bigint): void {
    if (fee > MAX_COMMITMENT_FEE_SHANNONS) {
        refusePolicyRequest(
            "policy_refusal",
            `the commitment fee is ${fee} shannons, above the ${MAX_COMMITMENT_FEE_SHANNONS} the reserve keeps for it`,
        );
    }
}
