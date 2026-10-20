import { assertOneOf, assertPositiveInteger, assertScriptTemplate, isPlainObject } from "../../common";
import { MAX_CELL_DEPS_COUNT } from "../../digest";
import { INVOICE_CURRENCIES } from "../../invoice";
import { SDK_NETWORK_NAMES, SDK_NETWORK_PRESETS } from "../sdk.constants";
import type { SdkNetwork, SdkNetworkConfig } from "../sdk.types";

/**
 * Resolves the network option to a preset by name, or copies a development chain's constants.
 * @param network The host's option.
 * @returns The network's constants.
 */
export function resolveSdkNetwork(network: SdkNetwork): SdkNetworkConfig {
    if (typeof network === "string") {
        assertOneOf("network", network, SDK_NETWORK_NAMES);
        return SDK_NETWORK_PRESETS[network];
    }
    if (!isPlainObject(network)) throw new TypeError("network must be a network name or an object");
    assertScriptTemplate("network.commitmentLock", network.commitmentLock);
    assertOneOf("network.invoiceCurrency", network.invoiceCurrency, INVOICE_CURRENCIES);
    const count: unknown = network.fundingLockCellDepsCount;
    assertPositiveInteger("network.fundingLockCellDepsCount", count, MAX_CELL_DEPS_COUNT);
    return {
        commitmentLock: { codeHash: Uint8Array.from(network.commitmentLock.codeHash), hashType: network.commitmentLock.hashType },
        invoiceCurrency: network.invoiceCurrency,
        fundingLockCellDepsCount: count,
    };
}
