import type { CommitmentCaseVector } from "./interop-vectors";

// Reserve included: what the opening commitment pays the device.
export function fundedShannonsOf(kase: CommitmentCaseVector): string {
    return (BigInt(kase.to_local) + BigInt(kase.local_reserved)).toString();
}
