import type { SignerErrorCode, TlcDirection } from "../common";
import type { BasePublicKeys } from "../derivation";
import type { PolicySignRequest } from "../policy";
import type { HexWire, OutPointWire, ScriptWire, TlcHashAlgorithmWire, UintHexWire } from "../wire";
import type { SIGNER_METHODS } from "./protocol.constants";

export type SignerMethod = (typeof SIGNER_METHODS)[number];

export type SignatureMethod = Extract<SignerMethod, `partial_sign_${string}`>;

export type SignSessionWire = { ordered_pubkeys: [HexWire, HexWire]; aggregated_nonce: HexWire; message: HexWire };

export type SettlementTlcWire = {
    id: UintHexWire;
    direction: TlcDirection;
    hash_algorithm: TlcHashAlgorithmWire;
    amount: UintHexWire;
    payment_hash: HexWire;
    expiry_ms: UintHexWire;
    created_at_remote_commitment_number: UintHexWire;
    remote_commitment_point: HexWire;
};

export type CommitmentTxWire = {
    for_remote: boolean;
    funding_out_point: OutPointWire;
    remote_funding_pubkey: HexWire;
    remote_tlc_base_pubkey: HexWire;
    commitment_number: UintHexWire;
    commitment_delay_epoch: UintHexWire;
    commitment_fee_rate: UintHexWire;
    cell_deps_count: UintHexWire;
    udt_type_script: ScriptWire | null;
    to_local: UintHexWire;
    to_remote: UintHexWire;
    settlement_local: UintHexWire;
    settlement_remote: UintHexWire;
    local_reserved: UintHexWire;
    remote_reserved: UintHexWire;
    tlcs: SettlementTlcWire[];
};

export type ShutdownTxWire = {
    funding_out_point: OutPointWire;
    remote_funding_pubkey: HexWire;
    local_close_script: ScriptWire;
    remote_close_script: ScriptWire;
    local_fee_rate: UintHexWire;
    remote_fee_rate: UintHexWire;
    cell_deps_count: UintHexWire;
    udt_type_script: ScriptWire | null;
    to_local: UintHexWire;
    to_remote: UintHexWire;
    local_reserved: UintHexWire;
    remote_reserved: UintHexWire;
};

export type RevocationWire = {
    for_remote: boolean;
    revoked_commitment_number: UintHexWire;
    payout_script: ScriptWire;
    remote_funding_pubkey: HexWire;
    commitment_delay_epoch: UintHexWire;
    commitment_fee_rate: UintHexWire;
    cell_deps_count: UintHexWire;
    udt_type_script: ScriptWire | null;
    to_local: UintHexWire;
    to_remote: UintHexWire;
    local_reserved: UintHexWire;
    remote_reserved: UintHexWire;
};

export type ChannelAnnouncementWire = {
    chain_hash: HexWire;
    funding_out_point: OutPointWire;
    node_ids: [HexWire, HexWire];
    remote_funding_pubkey: HexWire;
    capacity: UintHexWire;
    udt_type_script: ScriptWire | null;
};

export type EmptyParamsWire = Record<string, never>;

export type CommitmentNumberParamsWire = { commitment_number: UintHexWire };

export type PartialSignParamsWire = { session: SignSessionWire; nonce_commitment_number: UintHexWire };

export type PartialSignCommitmentTxParamsWire = PartialSignParamsWire & { commitment_tx: CommitmentTxWire };

export type PartialSignClosingTxParamsWire = PartialSignParamsWire & { shutdown_tx: ShutdownTxWire };

export type PartialSignRevocationParamsWire = PartialSignParamsWire & { revocation: RevocationWire };

/**
 * No nonce number: the announcement slot is fixed.
 */
export type PartialSignChannelAnnouncementParamsWire = { session: SignSessionWire; channel_announcement: ChannelAnnouncementWire };

export type SignParamsWireByMethod = {
    get_base_public_keys: EmptyParamsWire;
    get_commitment_point: CommitmentNumberParamsWire;
    get_commitment_pub_nonce: CommitmentNumberParamsWire;
    get_revocation_pub_nonce: CommitmentNumberParamsWire;
    get_channel_announcement_pub_nonce: EmptyParamsWire;
    get_settlement_keys: CommitmentNumberParamsWire;
    partial_sign_commitment_tx: PartialSignCommitmentTxParamsWire;
    partial_sign_closing_tx: PartialSignClosingTxParamsWire;
    partial_sign_revocation: PartialSignRevocationParamsWire;
    partial_sign_channel_announcement: PartialSignChannelAnnouncementParamsWire;
};

export type SignMethodParamsWire = { [Method in SignerMethod]: { method: Method; params: SignParamsWireByMethod[Method] } }[SignerMethod];

export type SignRequestWire = {
    type: "sign_request";
    request_id: string;
    channel_id: HexWire;
    state_version: UintHexWire;
} & SignMethodParamsWire;

export type SignResultWire =
    | { funding_pubkey: HexWire; tlc_base_pubkey: HexWire }
    | { commitment_point: HexWire }
    | { pub_nonce: HexWire }
    | { local_settlement_key: HexWire; tlc_key: HexWire }
    | { partial_signature: HexWire };

export type SignError = { code: SignerErrorCode; message: string };

export type SignResponseWire = { type: "sign_response"; request_id: string } & ({ result: SignResultWire } | { error: SignError });

export type ChallengeWire = { type: "challenge"; challenge: HexWire };

export type SessionEstablishedWire = { type: "session_established"; protocol_version: number; pending_requests: number };

export type PingWire = { type: "ping" };

export type PongWire = { type: "pong" };

export type ChannelRegisteredWire = { type: "channel_registered"; request_id: string; channel_id: HexWire };

/**
 * The codes are the bridge's own, not the device's four.
 */
export type ErrorWire = { type: "error"; request_id: string; code: string; message: string };

export type SignedChallengeWire = { type: "signed_challenge"; protocol_version: number; public_key: HexWire; signature: HexWire };

export type RegisterChannelWire = {
    type: "register_channel";
    request_id: string;
    funding_pubkey: HexWire;
    tlc_base_pubkey: HexWire;
    local_settlement_key: HexWire;
};

export type InboundFrameWire =
    ChallengeWire | SessionEstablishedWire | PingWire | PongWire | ChannelRegisteredWire | ErrorWire | SignRequestWire;

export type OutboundFrameWire = SignedChallengeWire | PingWire | PongWire | RegisterChannelWire | SignResponseWire;

export type SignRequest = {
    requestId: string;
    /**
     * Kept in the wire form, lowercase `0x` hex: the name the policy record is aliased by.
     */
    channelId: string;
    method: SignerMethod;
    params: Record<string, unknown>;
    stateVersion: number;
};

export type SignParams =
    | { method: "get_base_public_keys" | "get_channel_announcement_pub_nonce" }
    | {
          method: "get_commitment_point" | "get_commitment_pub_nonce" | "get_revocation_pub_nonce" | "get_settlement_keys";
          commitmentNumber: number;
      }
    | { method: SignatureMethod; request: PolicySignRequest };

export type SignResult =
    | ({ kind: "base_public_keys" } & BasePublicKeys)
    | { kind: "commitment_point"; commitmentPoint: Uint8Array }
    | { kind: "pub_nonce"; pubNonce: Uint8Array }
    | { kind: "settlement_keys"; localSettlementKey: Uint8Array; tlcKey: Uint8Array }
    | { kind: "partial_signature"; partialSignature: Uint8Array };

export type ChannelRegistration = BasePublicKeys & { localSettlementKey: Uint8Array };

export type InboundFrame =
    | { type: "challenge"; challenge: Uint8Array }
    | { type: "session_established"; protocolVersion: number; pendingRequests: number }
    | { type: "ping" }
    | { type: "pong" }
    | { type: "channel_registered"; requestId: string; channelId: string }
    | { type: "error"; requestId: string; code: string; message: string }
    | { type: "sign_request"; request: SignRequest };

export type OutboundFrame =
    | { type: "signed_challenge"; publicKey: Uint8Array; signature: Uint8Array }
    | { type: "ping" }
    | { type: "pong" }
    | { type: "register_channel"; requestId: string; registration: ChannelRegistration }
    | { type: "sign_response"; requestId: string; result: SignResult }
    | { type: "sign_response"; requestId: string; error: SignError };
