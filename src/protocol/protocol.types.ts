import type { CellOutput, Transaction } from "../common";
import type { NonceContext } from "../derivation";
import type { SigningSettlement } from "../digest";
import type { NonceCounter, SignSlotRef } from "../policy";
import type { BareHexWire, HexWire, TlcHashAlgorithmWire, TransactionWire, UintHexWire } from "../wire";
import type {
    CHANNEL_SIGNING_CONTENT_KINDS,
    CHANNEL_SIGNING_TRANSITIONS,
    COMMITMENT_COUNTERS,
    NONCE_PURPOSE_CONTEXTS,
    SIGNABLE_CONTENT_KINDS,
} from "./protocol.constants";

export type ChannelSigningTransition = (typeof CHANNEL_SIGNING_TRANSITIONS)[number];

export type ChannelSigningContentKind = (typeof CHANNEL_SIGNING_CONTENT_KINDS)[number];

export type NoncePurposeWire = keyof typeof NONCE_PURPOSE_CONTEXTS;

export type CommitmentCounterWire = keyof typeof COMMITMENT_COUNTERS;

export type SignableContentTypeWire = keyof typeof SIGNABLE_CONTENT_KINDS;

export type NonceSlotWire = { purpose: NoncePurposeWire; commitment_number: UintHexWire };

export type SignableContentWire =
    | { type: "CommitmentTransaction"; transaction: TransactionWire }
    | { type: "CooperativeCloseTransaction"; transaction: TransactionWire }
    | {
          type: "Revocation";
          /**
           * A `CellOutput` in molecule bytes, fiber's `EntityHex`.
           */
          output: HexWire;
          output_data: HexWire;
          commitment_lock_script_args: HexWire;
      }
    | { type: "ChannelAnnouncement"; unsigned_announcement: HexWire };

export type Musig2SigningContentWire = {
    slot: NonceSlotWire;
    commitment_counter: CommitmentCounterWire | null;
    key_agg_ctx: HexWire;
    agg_nonce: HexWire;
    content: SignableContentWire;
};

export type SigningSessionEvidenceWire = { peer_public_nonce: HexWire; peer_partial_signature: HexWire | null };

export type SigningSettlementTlcWire = {
    tlc_id: UintHexWire;
    local_key_commitment_number: UintHexWire;
    inbound: boolean;
    payment_hash: HexWire;
    payment_amount: UintHexWire;
    hash_algorithm: TlcHashAlgorithmWire;
    expiry: UintHexWire;
    local_key_pubkey: BareHexWire;
    remote_key: BareHexWire;
};

export type SigningSettlementWire = {
    local_amount: UintHexWire;
    remote_amount: UintHexWire;
    local_settlement_pubkey: BareHexWire;
    remote_settlement_pubkey: BareHexWire;
    for_remote: boolean;
    tlcs: SigningSettlementTlcWire[];
};

export type ChannelSigningStatusWire =
    | { type: "NoSignatureRequired" }
    | {
          type: "SignatureRequired";
          request_id: HexWire;
          transition: ChannelSigningTransition;
          content: Musig2SigningContentWire;
          session_evidence: SigningSessionEvidenceWire;
          /**
           * Fiber reads it with `serde(default)`, so absent is `null`; it writes `null`.
           */
          settlement?: SigningSettlementWire | null;
      };

export type ChannelSigningRule = {
    context: NonceContext;
    counter: NonceCounter | null;
    contentKind: ChannelSigningContentKind;
    /**
     * The `for_remote` the settlement must carry, or `null` where the request carries none.
     */
    settlementForRemote: boolean | null;
    peerPartialSignature: boolean;
    /**
     * Whether the answer carries the material of the next commitment number.
     */
    nextMaterial: boolean;
};

export type ChannelSigningContent =
    | { kind: "commitmentTx"; transaction: Transaction }
    | { kind: "closingTx"; transaction: Transaction }
    | {
          kind: "revocation";
          /**
           * Read from molecule hex by a canonical decoder, so writing it back yields the bytes the node hashed.
           */
          output: CellOutput;
          /**
           * The molecule `Bytes` as fiber hashes it, its 4-byte length header included.
           */
          outputData: Uint8Array;
          /**
           * The first 36 bytes of the revoked commitment's lock args.
           */
          commitmentLockArgs: Uint8Array;
      }
    | {
          kind: "announcement";
          /**
           * Molecule bytes with the signatures zeroed.
           */
          unsignedAnnouncement: Uint8Array;
      };

export type SigningSessionEvidence = {
    peerPublicNonce: Uint8Array;
    /**
     * Present exactly on the two `CompleteReceived*` transitions.
     */
    peerPartialSignature: Uint8Array | null;
};

export type ChannelSigningRequest = {
    kind: "required";
    requestId: Uint8Array;
    transition: ChannelSigningTransition;
    slot: SignSlotRef;
    /**
     * `null` only for the announcement.
     */
    counter: NonceCounter | null;
    /**
     * In the order `key_agg_ctx` aggregated them.
     */
    keyAggregation: [Uint8Array, Uint8Array];
    /**
     * Either half may be infinity, written as 33 zero bytes.
     */
    aggNonce: Uint8Array;
    content: ChannelSigningContent;
    evidence: SigningSessionEvidence;
    /**
     * Present on the two commitment transitions.
     */
    settlement: SigningSettlement | null;
};

export type ChannelSigningStatus = { kind: "none" } | ChannelSigningRequest;
