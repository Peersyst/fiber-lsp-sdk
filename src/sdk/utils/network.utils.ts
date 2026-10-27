import { assertOneOf, assertPositiveInteger, assertScriptTemplate, copyScriptTemplate, isPlainObject } from "../../common";
import { MAX_CELL_DEPS_COUNT } from "../../digest";
import { INVOICE_CURRENCIES } from "../../invoice";
import { MAX_MILLISECONDS_PER_EPOCH } from "../../signer";
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
    assertScriptTemplate("network.fundingLock", network.fundingLock);
    assertOneOf("network.invoiceCurrency", network.invoiceCurrency, INVOICE_CURRENCIES);
    const count: unknown = network.fundingLockCellDepsCount;
    assertPositiveInteger("network.fundingLockCellDepsCount", count, MAX_CELL_DEPS_COUNT);
    const millisecondsPerEpoch: unknown = network.millisecondsPerEpoch;
    assertPositiveInteger("network.millisecondsPerEpoch", millisecondsPerEpoch, MAX_MILLISECONDS_PER_EPOCH);
    return {
        commitmentLock: copyScriptTemplate(network.commitmentLock),
        fundingLock: copyScriptTemplate(network.fundingLock),
        invoiceCurrency: network.invoiceCurrency,
        fundingLockCellDepsCount: count,
        millisecondsPerEpoch,
    };
}
