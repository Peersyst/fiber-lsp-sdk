import type { CellDep, FiberLspSdk, FiberLspSdkOptions, Script } from "@peersyst/fiber-lsp-sdk";

/**
 * Kept as the driver sent it, so it can be compared and sent back.
 */
export type ScriptJson = {
    code_hash: string;
    hash_type: string;
    args: string;
};

export type AgentControlAddr = {
    host: string;
    port: number;
};

export type AgentConfig = {
    rpcUrl: string;
    storeDir: string;
    statusFile: string | null;
    controlAddr: AgentControlAddr | null;
    operatorToken: string;
    /**
     * Bare lowercase hex.
     */
    lspNodeId: string;
    intervalMs: number;
    contractsDir: string;
    nonceCapBypass: boolean;
};

export type AgentHashAlgorithm = "ckb_hash" | "sha256";

/**
 * Fiber's `PaymentAuthorization` without its direction, numbers as decimal strings.
 */
export type AgentPaymentTerms = {
    paymentHash: string;
    hashAlgorithm: AgentHashAlgorithm;
    /**
     * Exact; a `Payment`'s carries the routing fee budget.
     */
    amountShannons: string;
    expiresAtMs: string;
    minTlcExpiryDeltaMs: string;
    maxTlcExpiryMs: string;
};

export type InvoiceAuthorization = { type: "Invoice"; channelId: string; preimage: string } & AgentPaymentTerms;

export type PaymentAuthorization = { type: "Payment"; channelId: string } & AgentPaymentTerms;

export type FulfillmentAuthorization = {
    type: "Fulfillment";
    channelId: string;
    paymentHash: string;
    preimage: string;
};

export type ReleasePreimageAuthorization = {
    type: "ReleasePreimage";
    channelId: string;
    paymentHash: string;
    preimage: string;
    target: "Invoice" | "Watchtower";
};

export type CloseAuthorization = {
    type: "Close";
    channelId: string;
    localScript: ScriptJson;
    remoteScript: ScriptJson;
    localFeeRate: string;
    remoteFeeRate: string;
};

export type WatchtowerAuthorization = {
    type: "Watchtower";
    channelId: string;
    destination: ScriptJson;
    maxFeeShannons: string;
};

export type AgentAuthorization =
    | InvoiceAuthorization
    | PaymentAuthorization
    | FulfillmentAuthorization
    | ReleasePreimageAuthorization
    | CloseAuthorization
    | WatchtowerAuthorization;

/**
 * The two close scripts a `Close` authorization must name.
 */
export type AgentChannel = {
    localScript: ScriptJson;
    remoteScript: ScriptJson;
};

/**
 * Kept in `agent.json`; hex ids are `0x`-prefixed lowercase.
 */
export type AgentState = {
    tenantToken: string | null;
    channels: Record<string, AgentChannel>;
    invoices: Record<string, InvoiceAuthorization>;
    payments: Record<string, PaymentAuthorization>;
    closes: Record<string, CloseAuthorization>;
    watchtower: WatchtowerAuthorization | null;
};

export type OpenChannelRequest = {
    amountShannons: string;
    userLock: Script;
    userLockCellDeps: CellDep[] | undefined;
    userLockJson: ScriptJson;
};

/**
 * The SDK's fetch plus the abort signal the agent's own calls carry; global `fetch` is one.
 */
export type AgentNodeFetch = (
    url: string,
    init: { method: "POST"; headers: Record<string, string>; body: string; signal?: AbortSignal },
) => Promise<{ status: number; text(): Promise<string> }>;

export type AgentSdkFactory = (masterSeed: Uint8Array, options: FiberLspSdkOptions) => FiberLspSdk;

export type AgentEffects = {
    fetch: AgentNodeFetch;
    /**
     * Milliseconds since the epoch.
     */
    now: () => number;
    randomBytes: (length: number) => Uint8Array;
    sleep: (ms: number) => Promise<void>;
    exit: (code: number) => void;
    /**
     * One log line, without its newline.
     */
    log: (line: string) => void;
    createSdk: AgentSdkFactory;
};
