import { assertOneOf, assertScriptTemplate, isPlainObject } from "../../common";
import { INVOICE_CURRENCIES } from "../../invoice";
import { SDK_NETWORK_NAMES, SDK_NETWORK_PRESETS } from "../sdk.constants";
import type { SdkNetwork, SdkNetworkConfig } from "../sdk.types";

/**
 * Resolves the network option to its two constants: a preset by name, or a development chain's own, copied.
 * @param network The option as the host passed it.
 * @returns The commitment lock and the invoice currency.
 */
export function resolveSdkNetwork(network: SdkNetwork): SdkNetworkConfig {
    if (typeof network === "string") {
        assertOneOf("network", network, SDK_NETWORK_NAMES);
        return SDK_NETWORK_PRESETS[network];
    }
    if (!isPlainObject(network)) throw new TypeError("network must be a network name or an object");
    assertScriptTemplate("network.commitmentLock", network.commitmentLock);
    assertOneOf("network.invoiceCurrency", network.invoiceCurrency, INVOICE_CURRENCIES);
    return {
        commitmentLock: { codeHash: Uint8Array.from(network.commitmentLock.codeHash), hashType: network.commitmentLock.hashType },
        invoiceCurrency: network.invoiceCurrency,
    };
}
