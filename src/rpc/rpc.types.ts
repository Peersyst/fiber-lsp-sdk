import type { Script, TlcHashAlgorithm, Transaction } from "../common";
import type { InvoiceCurrency } from "../invoice";
import type { BareHexWire, HexWire, ScriptWire, TlcHashAlgorithmWire, TransactionWire, UintHexWire, WireField } from "../wire";
import type { IFetchLike } from "./interfaces";
import type {
    JSON_RPC_VERSION,
    LIST_CHANNELS_FILTERS,
    RPC_CHANNEL_STATE_FLAGS,
    RPC_CHANNEL_STATE_NAMES,
    RPC_INVOICE_STATUSES,
    RPC_METHODS,
    RPC_PAYMENT_STATUSES,
    RPC_SUBMISSION_RESULTS,
    RPC_TENANT_RUNTIME_STATUSES,
} from "./rpc.constants";

export type RpcMethod = (typeof RPC_METHODS)[number];

export type RpcParamsWire = Record<string, unknown>;

export type RpcRequestWire = { jsonrpc: typeof JSON_RPC_VERSION; id: number; method: RpcMethod; params: [RpcParamsWire] };

export type RpcErrorObjectWire = { code: number; message: string };

export type RpcResponseWire = { jsonrpc: string; id: number | null; result: unknown; error: RpcErrorObjectWire };

export type RpcResponse = { result: WireField } | { error: RpcErrorObjectWire };

export type RpcResultDecoder<Result> = (field: WireField) => Result;

export type FiberRpcClientOptions = {
    url: string;
    /**
     * Biscuit token, base64; omitted when the node's RPC has no auth.
     */
    token?: string;
    /**
     * Defaults to the runtime's global `fetch`, which Node, the browsers and React Native all have.
     */
    fetch?: IFetchLike;
};

export type OpenChannelWithExternalFundingParamsWire = {
    pubkey: BareHexWire;
    funding_amount: UintHexWire;
    public: boolean;
    shutdown_script: ScriptWire;
    funding_lock_script: ScriptWire;
};

export type OpenChannelWithExternalFundingResultWire = { channel_id: HexWire; unsigned_funding_tx: TransactionWire };

export type SubmitSignedFundingTxParamsWire = { channel_id: HexWire; signed_funding_tx: TransactionWire };

export type SubmitSignedFundingTxResultWire = { channel_id: HexWire; funding_tx_hash: HexWire };

export type RpcChannelIdParamsWire = { channel_id: HexWire };

export type ListChannelsParamsWire = { include_closed?: true; only_pending?: true };

export type RpcChannelStateName = (typeof RPC_CHANNEL_STATE_NAMES)[number];

/**
 * Absent on the two states without flags.
 */
export type RpcChannelStateWire = { state_name: RpcChannelStateName; state_flags?: string };

/**
 * The members the client reads; fiber writes more.
 */
export type RpcChannelWire = {
    channel_id: HexWire;
    pubkey: BareHexWire;
    funding_udt_type_script: ScriptWire | null;
    state: RpcChannelStateWire;
    local_balance: UintHexWire;
    offered_tlc_balance: UintHexWire;
    remote_balance: UintHexWire;
    received_tlc_balance: UintHexWire;
    created_at: UintHexWire;
    shutdown_transaction_hash: HexWire | null;
    failure_detail: string | null;
};

export type ListChannelsResultWire = { channels: RpcChannelWire[] };

export type RpcInvoiceStatus = (typeof RPC_INVOICE_STATUSES)[number];

export type RpcPaymentStatus = (typeof RPC_PAYMENT_STATUSES)[number];

export type NewInvoiceParamsWire = {
    amount: UintHexWire;
    description?: string;
    currency: InvoiceCurrency;
    payment_hash: HexWire;
    expiry: UintHexWire;
    hash_algorithm: TlcHashAlgorithmWire;
};

export type NewInvoiceResultWire = { invoice_address: string };

export type RpcPaymentHashParamsWire = { payment_hash: HexWire };

export type RpcInvoiceWire = NewInvoiceResultWire & { status: RpcInvoiceStatus };

export type SettleInvoiceParamsWire = { payment_hash: HexWire; payment_preimage: HexWire };

export type SendPaymentParamsWire = { invoice: string; max_fee_amount: UintHexWire; dry_run: boolean };

/**
 * The members the client reads; fiber writes more.
 */
export type RpcPaymentWire = {
    payment_hash: HexWire;
    status: RpcPaymentStatus;
    created_at: UintHexWire;
    last_updated_at: UintHexWire;
    failed_error: string | null;
    fee: UintHexWire;
};

export type ChannelOpenSignerMaterialWire = {
    base_public_keys: { funding_pubkey: BareHexWire; tlc_base_key: BareHexWire };
    first_commitment_point: BareHexWire;
    second_commitment_point: BareHexWire;
    commitment_nonce: HexWire;
    next_commitment_nonce: HexWire;
    revocation_nonce: HexWire;
    channel_announcement_nonce?: HexWire;
};

export type OpenTenantChannelParamsWire = OpenChannelWithExternalFundingParamsWire & {
    public: false;
    commitment_delay_epoch?: UintHexWire;
    commitment_fee_rate?: UintHexWire;
    external_channel_signer: ChannelOpenSignerMaterialWire;
};

export type TenantChannelOpeningContextWire = {
    remote_funding_key: BareHexWire;
    remote_settlement_key: BareHexWire;
    remote_shutdown_script: ScriptWire;
    commitment_delay_epoch: UintHexWire;
    commitment_fee_rate: UintHexWire;
    local_amount: UintHexWire;
    remote_amount: UintHexWire;
    local_reserved_ckb_amount: UintHexWire;
    remote_reserved_ckb_amount: UintHexWire;
};

export type OpenTenantChannelResultWire = OpenChannelWithExternalFundingResultWire & { opening_context: TenantChannelOpeningContextWire };

export type ShutdownChannelParamsWire = { channel_id: HexWire; close_script?: ScriptWire; fee_rate?: UintHexWire; force?: boolean };

export type RpcSigningStatusResultWire = { channel_id: HexWire; status: unknown };

export type NextChannelSignerMaterialWire = {
    next_commitment_point: BareHexWire;
    next_commitment_nonce: HexWire;
    next_revocation_nonce: HexWire;
};

export type SubmitChannelSignatureParamsWire = {
    channel_id: HexWire;
    request_id: HexWire;
    partial_signature: HexWire;
    next_material?: NextChannelSignerMaterialWire;
};

export type RpcSubmissionResult = (typeof RPC_SUBMISSION_RESULTS)[number];

export type RpcSubmissionResultWire = { type: RpcSubmissionResult };

export type SubmitWatchtowerSignatureParamsWire = { channel_id: HexWire; request_id: HexWire; signature: HexWire };

export type GetTenantRegistryNonceParamsWire = { root_signer_pubkey: BareHexWire };

export type GetTenantRegistryNonceResultWire = { lsp_node_id: BareHexWire; root_signer_pubkey: BareHexWire; nonce: HexWire };

export type RegisterTenantParamsWire = { root_signer_pubkey: BareHexWire; nonce: HexWire; signature: BareHexWire };

export type RpcTenantRuntimeStatus = (typeof RPC_TENANT_RUNTIME_STATUSES)[number];

export type LspTenantStatusWire = {
    tenant_id: string;
    root_signer_pubkey: BareHexWire | null;
    invoice_pubkey: BareHexWire;
    private_channel_id: HexWire | null;
    created_at: UintHexWire;
    runtime_status: RpcTenantRuntimeStatus;
    channel_online: boolean;
};

export type RegisterTenantResultWire = { tenant: LspTenantStatusWire; access_token: string };

export type RpcParamsWireByMethod = {
    open_channel_with_external_funding: OpenChannelWithExternalFundingParamsWire;
    submit_signed_funding_tx: SubmitSignedFundingTxParamsWire;
    abandon_channel: RpcChannelIdParamsWire;
    list_channels: ListChannelsParamsWire;
    new_invoice: NewInvoiceParamsWire;
    get_invoice: RpcPaymentHashParamsWire;
    settle_invoice: SettleInvoiceParamsWire;
    cancel_invoice: RpcPaymentHashParamsWire;
    send_payment: SendPaymentParamsWire;
    get_payment: RpcPaymentHashParamsWire;
    open_tenant_channel: OpenTenantChannelParamsWire;
    shutdown_channel: ShutdownChannelParamsWire;
    get_channel_signing_status: RpcChannelIdParamsWire;
    submit_channel_signature: SubmitChannelSignatureParamsWire;
    get_watchtower_signing_status: RpcChannelIdParamsWire;
    submit_watchtower_signature: SubmitWatchtowerSignatureParamsWire;
    lsp_get_tenant_registry_nonce: GetTenantRegistryNonceParamsWire;
    lsp_register_tenant: RegisterTenantParamsWire;
};

export type OpenChannelWithExternalFundingParams = {
    peerPubkey: Uint8Array;
    /**
     * The total, reserved CKB included.
     */
    fundingAmountShannons: string;
    public: boolean;
    shutdownScript: Script;
    fundingLockScript: Script;
};

export type OpenChannelWithExternalFundingResult = {
    /**
     * The final id, not the temporary one.
     */
    channelId: string;
    /**
     * The only copy of it: no other method returns it.
     */
    unsignedFundingTx: Transaction;
};

export type SubmitSignedFundingTxParams = { channelId: string; signedFundingTx: Transaction };

export type SubmitSignedFundingTxResult = { channelId: string; fundingTxHash: Uint8Array };

export type RpcChannelIdParams = { channelId: string };

export type AbandonChannelParams = RpcChannelIdParams;

export type ListChannelsFilter = (typeof LIST_CHANNELS_FILTERS)[number];

export type ListChannelsParams = { filter?: ListChannelsFilter };

export type RpcChannelStateFlag<Name extends RpcChannelStateName> = (typeof RPC_CHANNEL_STATE_FLAGS)[Name][number];

export type RpcChannelState = { [Name in RpcChannelStateName]: { name: Name; flags: RpcChannelStateFlag<Name>[] } }[RpcChannelStateName];

export type RpcChannel = {
    /**
     * Wire hex: the key the policy's channel alias is stored under.
     */
    channelId: string;
    peerPubkey: Uint8Array;
    fundingUdtTypeScript: Script | null;
    state: RpcChannelState;
    localBalanceShannons: string;
    remoteBalanceShannons: string;
    offeredTlcBalanceShannons: string;
    receivedTlcBalanceShannons: string;
    createdAtMs: bigint;
    /**
     * Set only once the closing transaction confirmed.
     */
    shutdownTransactionHash: Uint8Array | null;
    /**
     * Fiber's free text on a failed opening, the only thing telling an abandon from a timeout.
     */
    failureDetail: string | null;
};

export type NewInvoiceParams = {
    amountShannons: string;
    currency: InvoiceCurrency;
    paymentHash: Uint8Array;
    hashAlgorithm: TlcHashAlgorithm;
    /**
     * Required: an invoice created without one never expires.
     */
    expirySeconds: bigint;
    description?: string;
};

export type NewInvoiceResult = { invoiceAddress: string };

export type RpcPaymentHashParams = { paymentHash: Uint8Array };

export type RpcInvoice = NewInvoiceResult & { status: RpcInvoiceStatus };

export type SettleInvoiceParams = { paymentHash: Uint8Array; paymentPreimage: Uint8Array };

export type SendPaymentParams = {
    invoice: string;
    maxFeeAmountShannons: string;
    dryRun: boolean;
};

export type RpcPayment = {
    paymentHash: Uint8Array;
    status: RpcPaymentStatus;
    createdAtMs: bigint;
    lastUpdatedAtMs: bigint;
    failedError: string | null;
    /**
     * Planned until the payment succeeds.
     */
    feeShannons: string;
};

export type ChannelOpenSignerMaterial = {
    fundingPubkey: Uint8Array;
    tlcBaseKey: Uint8Array;
    firstCommitmentPoint: Uint8Array;
    secondCommitmentPoint: Uint8Array;
    commitmentNonce: Uint8Array;
    nextCommitmentNonce: Uint8Array;
    revocationNonce: Uint8Array;
    /**
     * `null` for a private channel, which every tenant channel is; fiber refuses one on it.
     */
    channelAnnouncementNonce: Uint8Array | null;
};

export type OpenTenantChannelParams = {
    peerPubkey: Uint8Array;
    /**
     * The total, reserved CKB included.
     */
    fundingAmountShannons: string;
    shutdownScript: Script;
    fundingLockScript: Script;
    /**
     * The full `EpochNumberWithFraction` value; the node's default when absent.
     */
    commitmentDelayEpoch?: bigint;
    commitmentFeeRate?: bigint;
    signerMaterial: ChannelOpenSignerMaterial;
};

/**
 * The terms the node froze for the channel, seen from the tenant's side.
 */
export type TenantChannelOpeningContext = {
    remoteFundingKey: Uint8Array;
    remoteSettlementKey: Uint8Array;
    remoteShutdownScript: Script;
    commitmentDelayEpoch: bigint;
    commitmentFeeRate: bigint;
    localAmountShannons: string;
    remoteAmountShannons: string;
    localReservedCkbShannons: string;
    remoteReservedCkbShannons: string;
};

export type OpenTenantChannelResult = OpenChannelWithExternalFundingResult & { openingContext: TenantChannelOpeningContext };

export type ShutdownChannelParams = {
    channelId: string;
    closeScript?: Script;
    feeRate?: bigint;
    /**
     * A force close ignores the script and the fee rate for the ones fixed at the open.
     */
    force?: boolean;
};

export type RpcSigningStatusResult = {
    channelId: string;
    /**
     * The signing protocol's status, as the field it arrived in: `protocol` reads it.
     */
    status: WireField;
};

export type NextChannelSignerMaterial = {
    nextCommitmentPoint: Uint8Array;
    nextCommitmentNonce: Uint8Array;
    nextRevocationNonce: Uint8Array;
};

export type SubmitChannelSignatureParams = {
    channelId: string;
    requestId: Uint8Array;
    partialSignature: Uint8Array;
    nextMaterial: NextChannelSignerMaterial | null;
};

export type SubmitWatchtowerSignatureParams = {
    channelId: string;
    requestId: Uint8Array;
    /**
     * Recoverable ECDSA, 65 bytes.
     */
    signature: Uint8Array;
};

export type GetTenantRegistryNonceParams = { rootSignerPubkey: Uint8Array };

export type GetTenantRegistryNonceResult = { lspNodeId: Uint8Array; rootSignerPubkey: Uint8Array; nonce: Uint8Array };

export type RegisterTenantParams = {
    rootSignerPubkey: Uint8Array;
    nonce: Uint8Array;
    /**
     * Compact ECDSA, 64 bytes, over fiber's registry payload.
     */
    signature: Uint8Array;
};

export type LspTenantStatus = {
    /**
     * Fiber's hex of the 32-byte digest of the root signer's key, kept as the string the operator sees.
     */
    tenantId: string;
    rootSignerPubkey: Uint8Array | null;
    invoicePubkey: Uint8Array;
    privateChannelId: string | null;
    createdAtMs: bigint;
    runtimeStatus: RpcTenantRuntimeStatus;
    channelOnline: boolean;
};

export type RegisterTenantResult = { tenant: LspTenantStatus; accessToken: string };
