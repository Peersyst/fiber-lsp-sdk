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
    intervalMs: number;
    contractsDir: string;
};

export type AgentHashAlgorithm = "ckb_hash" | "sha256";

export type InvoiceAuthorization = {
    type: "Invoice";
    channelId: string;
    preimage: string;
    paymentHash: string;
    hashAlgorithm: AgentHashAlgorithm;
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

export type AgentAuthorization = InvoiceAuthorization | ReleasePreimageAuthorization | CloseAuthorization | WatchtowerAuthorization;

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
    /**
     * Hex without `0x`, as fiber's `node_info` writes it.
     */
    lspPubkey: string | null;
    channels: Record<string, AgentChannel>;
    invoices: Record<string, InvoiceAuthorization>;
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
 * Shared by the SDK and the agent's own calls, which carry an abort signal; global `fetch` is one.
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
    sleep: (ms: number) => Promise<void>;
    exit: (code: number) => void;
    /**
     * One log line, without its newline.
     */
    log: (line: string) => void;
    createSdk: AgentSdkFactory;
};
