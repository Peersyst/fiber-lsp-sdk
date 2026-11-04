import { readFileSync } from "node:fs";
import { messageOf } from "./agent.utils";
import { readCkbTxJson } from "./ckb-tx";
import { liveCellLockResolver, signSighashAllInputs } from "./sighash-signer";

// The key goes in the environment, never in the arguments a process listing shows.
const PRIVATE_KEY_VARIABLE = "CKB_SIGNER_PRIVATE_KEY";

const CKB_RPC_VARIABLE = "CKB_RPC_URL";

/**
 * Reads a required environment variable, an empty one counting as unset.
 * @param name The variable.
 * @returns Its value.
 */
function requireVariable(name: string): string {
    const value = process.env[name];
    if (value === undefined || value === "") throw new Error(`${name} must be set`);
    return value;
}

/**
 * Signs the transaction in CKB's JSON on stdin with the key's default lock and writes it to stdout.
 */
async function main(): Promise<void> {
    const privateKey = requireVariable(PRIVATE_KEY_VARIABLE);
    const resolveLock = liveCellLockResolver(requireVariable(CKB_RPC_VARIABLE), fetch);
    let input: unknown;
    try {
        input = JSON.parse(readFileSync(0, "utf8"));
    } catch {
        throw new Error("stdin is not JSON");
    }
    const signed = await signSighashAllInputs(readCkbTxJson(input, "tx"), privateKey, resolveLock);
    process.stdout.write(`${JSON.stringify(signed)}\n`);
}

main().catch((error: unknown) => {
    process.stderr.write(`sign-tx: ${messageOf(error)}\n`);
    process.exit(1);
});
