import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ScriptTemplate, SdkNetworkConfig } from "@peersyst/fiber-lsp-sdk";
import { ckbBlake2b } from "./ckb-hash";

// A dev chain's genesis deploys the funding lock with the auth library as its second cell dep, and the nodes' config
// overrides neither.
const DEVNET_FUNDING_LOCK_CELL_DEPS_COUNT = 2;

// Fiber's `MILLI_SECONDS_PER_EPOCH` in a debug build, the one the devnet's nodes run.
const DEBUG_MILLISECONDS_PER_EPOCH = 2000;

/**
 * Reads a contract binary into the script that runs it by its data hash, as a dev chain's genesis deploys it.
 * @param contractsDir The folder of the devnet's contract binaries.
 * @param name The binary's file name.
 * @returns The script's code hash and hash type.
 */
function dataScript(contractsDir: string, name: string): ScriptTemplate {
    return { codeHash: ckbBlake2b(readFileSync(join(contractsDir, name))), hashType: "data2" };
}

/**
 * Builds the SDK's network for fiber's devnet from the contract binaries it deploys, the LSP's word left out.
 * @param contractsDir The folder holding `funding-lock` and `commitment-lock`.
 * @returns The network.
 */
export function devnetNetwork(contractsDir: string): SdkNetworkConfig {
    return {
        commitmentLock: dataScript(contractsDir, "commitment-lock"),
        fundingLock: dataScript(contractsDir, "funding-lock"),
        invoiceCurrency: "Fibd",
        fundingLockCellDepsCount: DEVNET_FUNDING_LOCK_CELL_DEPS_COUNT,
        millisecondsPerEpoch: DEBUG_MILLISECONDS_PER_EPOCH,
    };
}
