use std::collections::{BTreeSet, HashMap};

use ckb_jsonrpc_types::{CellDep as JsonCellDep, Script as JsonScript, Transaction as JsonTransaction};
use ckb_types::core::{Capacity, EpochNumberWithFraction, FeeRate, TransactionBuilder};
use ckb_types::packed::{
    Byte, BytesOpt, CellDep, CellInput, CellOutput, OutPoint as PackedOutPoint, Script as PackedScript, Transaction,
    WitnessArgs,
};
use ckb_types::prelude::*;
use fiber_json_types::{
    ChannelSigningStatus, ChannelSigningTransition, GetChannelSigningStatusResult, Hash256 as JsonHash256,
    OnchainKeyPurpose as JsonOnchainKeyPurpose, SigningSessionEvidence, SigningSettlement, SigningSettlementTlc,
};
use fiber_lsp_sdk::json::{musig2_from_rpc, musig2_to_rpc, settlement_from_rpc};
use fiber_lsp_sdk::{
    CommitmentReference, OnchainSpendAuthorization, OwnedSettlementBinding, RecoveryRecord, SignerError, VerifiedCell,
};
use fiber_types::{
    compute_tx_message, settlement_data_to_witness, settlement_matches_commitment_tx, settlement_tlc_to_witness, ChannelData,
    ChannelSigningContent, CommitmentContractFeatures, CommitmentCounter, Hash256, InMemorySigner, Musig2Context,
    Musig2SignableContent, Musig2SigningContent, NoncePurpose, NonceSlot, OnchainKeyPurpose, OnchainSigningContent,
    SettlementData, TLCId,
};
use musig2::secp256k1::{PublicKey as MusigPublicKey, SecretKey as MusigSecretKey};
use musig2::{
    aggregate_partial_signatures, sign_partial, verify_partial, verify_single, AggNonce, CompactSignature, KeyAggContext,
    PartialSignature, PubNonce, SecNonce, SecNonceBuilder,
};
use secp030::ecdsa::{RecoverableSignature, RecoveryId};
use secp030::{Message, SECP256K1};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    blake160, blake2b_256, build_announcement, build_commitment, build_revocation, build_shutdown, channel_seed, ckb_blake2b,
    derive_public_key, derived_channel_id, fiber_pubkey, lock_layout_features, nonce_seed, packed_script, pubkey_of, reserved_capacity,
    AnnouncementCaseVector, CommitmentCaseVector, FiberSigner, OutPointVector, RevocationCaseVector, ScriptVector,
    ShutdownCaseVector, TlcVector, COMMITMENT_LOCK_TESTNET_CODE_HASH, DEFAULT_DELAY_EPOCH, FIBER_REF, MASTER_SEED,
    REMOTE_SIGNER_SEED, SINCE_RELATIVE_EPOCH_FLAGS,
};

/// An index as the SDK allocates one, the open's time in seconds: well past the small indices.
const DEVICE_CHANNEL_INDEX: u64 = 1_760_572_800;
/// The funding lock's cell deps on the presets, which fiber sizes the commitment fee with (crates/fiber-lib/src/fiber/fee.rs:27-35).
const FUNDING_LOCK_CELL_DEPS_COUNT: u32 = 2;
pub(crate) const DEVICE: &str = "device";
pub(crate) const PEER: &str = "peer";

// --- the vector file ---

#[derive(Serialize, Deserialize)]
struct SigningVectors {
    fiber_ref: String,
    device: DeviceVector,
    peer: PeerVector,
    channel: SigningChannelVector,
    cases: Vec<SigningCase>,
    variants: Vec<SigningVariant>,
    watchtower: WatchtowerVectors,
}

/// The SDK's master seed and channel index, so a TS signer derives these keys itself.
#[derive(Serialize, Deserialize)]
pub(crate) struct DeviceVector {
    master_seed: String,
    channel_index: u64,
    pub(crate) funding_pubkey: String,
    pub(crate) tlc_base_pubkey: String,
}

/// The node's end of the channel, a fiber `InMemorySigner`.
#[derive(Serialize, Deserialize)]
pub(crate) struct PeerVector {
    seed: String,
    pub(crate) funding_pubkey: String,
    pub(crate) tlc_base_pubkey: String,
}

/// The channel of every case: the terms a signer pins and the builds' inputs.
#[derive(Serialize, Deserialize, Clone)]
struct SigningChannelVector {
    channel_id: String,
    funding_out_point: OutPointVector,
    lock_layout: String,
    commitment_lock: ScriptVector,
    funding_lock_cell_deps_count: u32,
    delay_epoch: String,
    commitment_fee_rate: String,
    udt_type_script: Option<ScriptVector>,
    to_local: String,
    to_remote: String,
    local_reserved: String,
    remote_reserved: String,
    local_close_script: ScriptVector,
    remote_close_script: ScriptVector,
    local_shutdown_fee_rate: String,
    remote_shutdown_fee_rate: String,
    /// The TLCs both commitment cases carry, every one pending.
    tlcs: Vec<TlcVector>,
}

#[derive(Serialize, Deserialize)]
struct SigningCase {
    name: String,
    transition: String,
    /// `get_channel_signing_status`'s result as `fiber-json-types` writes it.
    result: Value,
    expected: SigningExpected,
}

#[derive(Serialize, Deserialize)]
struct SigningExpected {
    /// Whose key is first and whose second in the case's `key_agg_ctx`.
    key_order: [String; 2],
    message: String,
    public_nonce: String,
    partial_signature: String,
    next_material: Option<NextMaterialVector>,
    /// The aggregated Schnorr signature, on the one transition whose evidence the device keeps.
    signature: Option<String>,
}

/// The device's public material for the slot's number plus one.
#[derive(Serialize, Deserialize)]
struct NextMaterialVector {
    next_commitment_point: String,
    next_commitment_nonce: String,
    next_revocation_nonce: String,
}

/// One case's result with a field malformed, and what fiber's own client codec makes of it.
#[derive(Serialize, Deserialize)]
struct SigningVariant {
    name: String,
    case: String,
    result: Value,
    verdict: Verdict,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Verdict {
    accepted: bool,
    message: Option<String>,
}

/// The watchtower's spends of the two commitments a force close can put on chain, built over the channel's keys.
#[derive(Serialize, Deserialize)]
struct WatchtowerVectors {
    funding_cell_deps: Vec<JsonCellDep>,
    settlement_cell_deps: Vec<JsonCellDep>,
    destination: JsonScript,
    /// The device's bound on what a spend may leave unpaid, decimal shannons.
    max_fee: String,
    /// The TLCs both commitments carry, in place of the channel's: these come with a preimage to claim by.
    tlcs: Vec<TlcVector>,
    views: Vec<WatchtowerViewVector>,
    variants: Vec<WatchtowerVariant>,
}

#[derive(Serialize, Deserialize)]
struct WatchtowerViewVector {
    for_remote: bool,
    commitment: BroadcastCommitmentVector,
    /// The device's spends only: the watchtower's chain, then those of the history where the peer spends first.
    spends: Vec<WatchtowerSpendVector>,
    /// The peer's own spends of that history, which the device's spends after them start from.
    peer_spends: Vec<PeerSpendVector>,
}

/// A spend of the peer's own: no request reaches the device, so it carries no signature of the device's.
#[derive(Serialize, Deserialize)]
struct PeerSpendVector {
    name: String,
    /// As the peer's watchtower builds it, its unlock's signature 65 zero bytes: the signatures leave the hash unchanged.
    transaction: JsonTransaction,
    tx_hash: String,
}

#[derive(Serialize, Deserialize)]
struct BroadcastCommitmentVector {
    /// The signed commitment with the funding lock's cell deps, as fiber broadcasts it.
    transaction: JsonTransaction,
    onchain_tx_hash: String,
    message: String,
    settlement_witness: String,
}

#[derive(Serialize, Deserialize)]
struct WatchtowerSpendVector {
    name: String,
    key_purpose: JsonOnchainKeyPurpose,
    /// The spend as the watchtower hands it over: the unlock's signature 65 zero bytes.
    transaction: JsonTransaction,
    request_id: String,
    message: String,
    tx_hash: String,
    released_shannons: String,
    signer_pubkey: String,
    signature: String,
}

/// One spend with a part changed, and the verdict of fiber-lsp-sdk's `validate` on it.
#[derive(Serialize, Deserialize)]
struct WatchtowerVariant {
    name: String,
    view_for_remote: bool,
    spend: String,
    transaction: JsonTransaction,
    key_purpose: JsonOnchainKeyPurpose,
    request_id: String,
    fiber_error: String,
}

// --- the two signers ---

struct Signers {
    device: FiberSigner,
    peer: FiberSigner,
    /// The device's on-chain keys come from fiber's own signer, the key material fiber-lsp-sdk signs a spend with.
    device_native: InMemorySigner,
    /// The peer's nonces come from fiber's own signer, as a node derives them.
    peer_native: InMemorySigner,
}

impl Signers {
    fn new(peer_seed: &[u8]) -> Self {
        let device_seed = channel_seed(&MASTER_SEED, DEVICE_CHANNEL_INDEX);
        let device = FiberSigner::generate_from_seed(&device_seed);
        let peer = FiberSigner::generate_from_seed(peer_seed);
        let device_native = InMemorySigner::generate_from_seed(&device_seed);
        let peer_native = InMemorySigner::generate_from_seed(peer_seed);
        assert_eq!(
            device_native.tlc_base_key.pubkey().serialize(),
            pubkey_of(&device.tlc_base_key).serialize(),
            "the harness's port and fiber's signer derive one device"
        );
        assert_eq!(
            peer_native.funding_key.pubkey().serialize(),
            pubkey_of(&peer.funding_key).serialize(),
            "the harness's port and fiber's signer derive one peer"
        );
        Signers { device, peer, device_native, peer_native }
    }

    fn device_pubkey(&self) -> MusigPublicKey {
        musig_pubkey(&pubkey_of(&self.device.funding_key).serialize())
    }

    fn peer_pubkey(&self) -> MusigPublicKey {
        musig_pubkey(&pubkey_of(&self.peer.funding_key).serialize())
    }

    /// BIP-327 `NonceGen` as the SDK calls it: the slot's seed, the funding key and its public key, and an empty
    /// extra input whose length is still hashed.
    fn device_secnonce(&self, number: u64, context: &str) -> SecNonce {
        SecNonceBuilder::new(nonce_seed(&self.device, number, context))
            .with_seckey(musig_seckey(&self.device.funding_key.secret_bytes()))
            .with_pubkey(self.device_pubkey())
            .with_extra_input(b"")
            .build()
    }

    /// As a fiber node derives it: `derive_musig2_nonce` (crates/fiber-types/src/channel.rs:1343-1350), or the salted
    /// base nonce for the announcement (crates/fiber-lib/src/fiber/channel.rs:8457-8467).
    fn peer_secnonce(&self, slot: NonceSlot) -> SecNonce {
        match slot.purpose {
            NoncePurpose::Commitment => self.peer_native.derive_musig2_nonce(slot.commitment_number, Musig2Context::Commitment),
            NoncePurpose::Revocation => self.peer_native.derive_musig2_nonce(slot.commitment_number, Musig2Context::Revoke),
            NoncePurpose::ChannelAnnouncement => SecNonce::build(fiber_types::blake2b_hash_with_salt(
                self.peer_native.musig2_base_nonce.as_ref(),
                b"channel_announcement",
            ))
            .build(),
        }
    }

    fn peer_seckey(&self) -> MusigSecretKey {
        self.peer_native.funding_key.0
    }
}

fn musig_pubkey(bytes: &[u8]) -> MusigPublicKey {
    MusigPublicKey::from_slice(bytes).unwrap()
}

fn musig_seckey(bytes: &[u8]) -> MusigSecretKey {
    MusigSecretKey::from_slice(bytes).unwrap()
}

fn nonce_context(purpose: NoncePurpose) -> &'static str {
    match purpose {
        NoncePurpose::Commitment => "COMMITMENT",
        NoncePurpose::Revocation => "REVOKE",
        NoncePurpose::ChannelAnnouncement => "ANNOUNCEMENT",
    }
}

/// Funding-cell spends sort the keys (crates/fiber-lib/src/fiber/channel.rs:11029-11042); a revocation keeps the
/// revoked lock's role order (:11120-11129), `[remote, local]` sent and `[local, remote]` received.
#[derive(Clone, Copy)]
enum KeyOrder {
    Sorted,
    PeerFirst,
    DeviceFirst,
}

impl KeyOrder {
    fn device_first(self, signers: &Signers) -> bool {
        match self {
            KeyOrder::Sorted => signers.device_pubkey().serialize() <= signers.peer_pubkey().serialize(),
            KeyOrder::PeerFirst => false,
            KeyOrder::DeviceFirst => true,
        }
    }
}

/// fiber `to_rpc_signing_settlement` (crates/fiber-lib/src/rpc/channel.rs:913-945), ported: fiber-lib keeps it private.
pub(crate) fn to_rpc_signing_settlement(
    settlement: &SettlementData,
    local_settlement_key: fiber_types::Pubkey,
    remote_settlement_key: fiber_types::Pubkey,
    for_remote: bool,
) -> SigningSettlement {
    SigningSettlement {
        local_amount: settlement.local_amount,
        remote_amount: settlement.remote_amount,
        local_settlement_pubkey: local_settlement_key.into(),
        remote_settlement_pubkey: remote_settlement_key.into(),
        for_remote,
        tlcs: settlement
            .tlcs
            .iter()
            .map(|tlc| SigningSettlementTlc {
                tlc_id: u64::from(tlc.tlc_id),
                local_key_commitment_number: tlc.local_key_commitment_number.expect("missing TLC key derivation index"),
                inbound: matches!(tlc.tlc_id, TLCId::Received(_)) == for_remote,
                payment_hash: tlc.payment_hash.into(),
                payment_amount: tlc.payment_amount,
                hash_algorithm: tlc.hash_algorithm.into(),
                expiry: tlc.expiry,
                local_key_pubkey: tlc.local_pubkey().into(),
                remote_key: tlc.remote_key.into(),
            })
            .collect(),
    }
}

// --- the cases ---

/// One request as fiber's channel actor shapes it.
struct Request {
    name: &'static str,
    transition: ChannelSigningTransition,
    slot: NonceSlot,
    counter: Option<CommitmentCounter>,
    order: KeyOrder,
    signable: Musig2SignableContent,
    /// The harness builders' digest, which fiber's `signing_message` must equal.
    digest: [u8; 32],
    /// The peer signs first on `CompleteReceived*` (crates/fiber-lib/src/fiber/channel.rs:11054-11079).
    peer_signed: bool,
    settlement: Option<SigningSettlement>,
    /// Only the transitions that advance a commitment (crates/fiber-types/src/channel_signer.rs:380-388).
    next_material: bool,
    keeps_signature: bool,
}

fn request_id(name: &str) -> JsonHash256 {
    JsonHash256(blake2b_256(format!("signing request {name}").as_bytes()))
}

fn transition_name(transition: ChannelSigningTransition) -> String {
    serde_json::to_value(transition).unwrap().as_str().unwrap().to_string()
}

/// One musig2 session of the device and the peer on a slot, both halves verified and aggregated into a valid signature.
struct MusigSession {
    key_agg_ctx: KeyAggContext,
    agg_nonce: AggNonce,
    peer_nonce: PubNonce,
    device_nonce: PubNonce,
    device_partial: PartialSignature,
    peer_partial: PartialSignature,
    signature: CompactSignature,
    aggregated: MusigPublicKey,
}

fn musig_session(signers: &Signers, device_first: bool, slot: NonceSlot, message: [u8; 32]) -> MusigSession {
    let (device_pubkey, peer_pubkey) = (signers.device_pubkey(), signers.peer_pubkey());
    let keys = if device_first { vec![device_pubkey, peer_pubkey] } else { vec![peer_pubkey, device_pubkey] };
    let key_agg_ctx = KeyAggContext::new(keys).unwrap();

    let device_secnonce = signers.device_secnonce(slot.commitment_number, nonce_context(slot.purpose));
    let peer_secnonce = signers.peer_secnonce(slot);
    let (device_nonce, peer_nonce) = (device_secnonce.public_nonce(), peer_secnonce.public_nonce());
    let agg_nonce = AggNonce::sum(if device_first {
        [device_nonce.clone(), peer_nonce.clone()]
    } else {
        [peer_nonce.clone(), device_nonce.clone()]
    });

    let device_partial: PartialSignature =
        sign_partial(&key_agg_ctx, musig_seckey(&signers.device.funding_key.secret_bytes()), device_secnonce, &agg_nonce, message)
            .unwrap();
    let peer_partial: PartialSignature =
        sign_partial(&key_agg_ctx, signers.peer_seckey(), peer_secnonce, &agg_nonce, message).unwrap();
    verify_partial(&key_agg_ctx, device_partial, &agg_nonce, device_pubkey, &device_nonce, message).unwrap();
    verify_partial(&key_agg_ctx, peer_partial, &agg_nonce, peer_pubkey, &peer_nonce, message).unwrap();
    let signature: CompactSignature =
        aggregate_partial_signatures(&key_agg_ctx, &agg_nonce, [device_partial, peer_partial], message).unwrap();
    let aggregated: MusigPublicKey = key_agg_ctx.aggregated_pubkey();
    verify_single(aggregated, signature, message).unwrap();
    MusigSession { key_agg_ctx, agg_nonce, peer_nonce, device_nonce, device_partial, peer_partial, signature, aggregated }
}

fn signing_case(signers: &Signers, channel: &SigningChannelVector, request: Request) -> SigningCase {
    let device_first = request.order.device_first(signers);
    let key_order = if device_first { [DEVICE, PEER] } else { [PEER, DEVICE] }.map(str::to_string);
    let message = request.signable.signing_message();
    assert_eq!(message, request.digest, "{}: fiber's signing_message is not the harness's digest", request.name);
    let session = musig_session(signers, device_first, request.slot, message);
    let content = Musig2SigningContent {
        slot: request.slot,
        commitment_counter: request.counter,
        key_agg_ctx: session.key_agg_ctx.clone(),
        agg_nonce: session.agg_nonce.clone(),
        content: request.signable,
    };
    assert_aggregated_key(request.name, &content.content, &session.aggregated);
    let MusigSession { peer_nonce, device_nonce, device_partial, peer_partial, signature, .. } = session;

    let status = ChannelSigningStatus::SignatureRequired {
        request_id: request_id(&transition_name(request.transition)),
        transition: request.transition,
        content: musig2_to_rpc(&content),
        session_evidence: SigningSessionEvidence {
            peer_public_nonce: peer_nonce.serialize().to_vec(),
            peer_partial_signature: request.peer_signed.then(|| peer_partial.serialize().to_vec()),
        },
        settlement: request.settlement,
    };
    let result = serde_json::to_value(GetChannelSigningStatusResult {
        channel_id: JsonHash256(bytes_of(channel.channel_id.trim_start_matches("0x"))),
        status,
    })
    .unwrap();
    assert_round_trip(request.name, &result, &content, message);

    let next = request.slot.commitment_number + 1;
    SigningCase {
        name: request.name.to_string(),
        transition: transition_name(request.transition),
        result,
        expected: SigningExpected {
            key_order,
            message: hex::encode(message),
            public_nonce: hex::encode(device_nonce.serialize()),
            partial_signature: hex::encode(device_partial.serialize()),
            next_material: request.next_material.then(|| NextMaterialVector {
                next_commitment_point: hex::encode(signers.device.get_commitment_point(next).serialize()),
                next_commitment_nonce: hex::encode(signers.device_secnonce(next, "COMMITMENT").public_nonce().serialize()),
                next_revocation_nonce: hex::encode(signers.device_secnonce(next, "REVOKE").public_nonce().serialize()),
            }),
            signature: request.keeps_signature.then(|| hex::encode(signature.serialize())),
        },
    }
}

/// The aggregated key must be the revoked lock's for a revocation, the announced one for an announcement.
fn assert_aggregated_key(name: &str, content: &Musig2SignableContent, aggregated: &MusigPublicKey) {
    let xonly = aggregated.x_only_public_key().0.serialize();
    match content {
        Musig2SignableContent::Revocation { commitment_lock_script_args, .. } => {
            assert_eq!(&commitment_lock_script_args[0..20], &blake2b_256(&xonly)[0..20], "{name}: not the revoked lock's key")
        }
        Musig2SignableContent::ChannelAnnouncement(announcement) => {
            assert_eq!(announcement.ckb_key.serialize(), xonly, "{name}: not the announced key")
        }
        _ => {}
    }
}

/// fiber's client codec reads the written result back into the request it was written from.
fn assert_round_trip(name: &str, result: &Value, content: &Musig2SigningContent, message: [u8; 32]) {
    let parsed: GetChannelSigningStatusResult = serde_json::from_value(result.clone()).unwrap();
    let ChannelSigningStatus::SignatureRequired { content: written, session_evidence, settlement, .. } = parsed.status else {
        panic!("{name}: not a SignatureRequired status");
    };
    let restored = musig2_from_rpc(written).unwrap_or_else(|error| panic!("{name}: fiber's codec refuses it: {error}"));
    assert_eq!(restored.slot, content.slot, "{name}: slot");
    assert_eq!(restored.commitment_counter, content.commitment_counter, "{name}: counter");
    assert_eq!(restored.key_agg_ctx.serialize(), content.key_agg_ctx.serialize(), "{name}: key_agg_ctx");
    assert_eq!(restored.agg_nonce.serialize(), content.agg_nonce.serialize(), "{name}: agg_nonce");
    assert_eq!(restored.content.signing_message(), message, "{name}: message");
    fiber_lsp_sdk::json::session_evidence_from_rpc(session_evidence)
        .unwrap_or_else(|error| panic!("{name}: fiber's codec refuses the evidence: {error}"));
    if let Some(settlement) = settlement {
        let (data, local_key, remote_key, for_remote) = settlement_from_rpc(&settlement)
            .unwrap_or_else(|error| panic!("{name}: fiber's codec refuses the settlement: {error}"));
        let Musig2SignableContent::CommitmentTransaction(tx) = &restored.content else {
            panic!("{name}: a settlement beside a content that is no commitment");
        };
        assert!(
            settlement_matches_commitment_tx(tx, &data, local_key, remote_key, Some(for_remote)),
            "{name}: fiber does not read the snapshot in the commitment lock args"
        );
    }
}

fn bytes_of<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

/// id, direction, hash algorithm, amount, payment hash, expiry, and created_at as (local, remote).
type TlcFixture = (u64, &'static str, &'static str, &'static str, [u8; 32], &'static str, (u64, u64));

/// created_at as fiber keeps it, (local, remote): the device's key at the remote number, the peer's at the local one.
fn tlc_vector(
    signers: &Signers,
    (id, direction, hash_algorithm, amount, payment_hash, expiry_ms, created_at): TlcFixture,
) -> TlcVector {
    let peer_tlc_base = pubkey_of(&signers.peer.tlc_base_key);
    TlcVector {
        id,
        direction: direction.to_string(),
        hash_algorithm: hash_algorithm.to_string(),
        amount: amount.to_string(),
        payment_hash: hex::encode(payment_hash),
        expiry_ms: expiry_ms.to_string(),
        local_key_commitment_number: created_at.1,
        remote_tlc_pubkey: hex::encode(
            derive_public_key(&peer_tlc_base, &signers.peer.get_commitment_point(created_at.0)).serialize(),
        ),
    }
}

fn signing_channel(signers: &Signers) -> SigningChannelVector {
    let features = lock_layout_features("full_payment_hash");
    let close_script = |label: &str| ScriptVector {
        code_hash: hex::encode(blake2b_256(format!("{label} lock").as_bytes())),
        hash_type: "type".to_string(),
        args: hex::encode(blake160(label.as_bytes())),
    };
    let local_close_script = close_script("device close");
    let remote_close_script = close_script("peer close");
    SigningChannelVector {
        channel_id: derived_channel_id([
            pubkey_of(&signers.device.tlc_base_key).serialize(),
            pubkey_of(&signers.peer.tlc_base_key).serialize(),
        ]),
        funding_out_point: OutPointVector { tx_hash: hex::encode(blake2b_256(b"signing funding tx")), index: 0 },
        lock_layout: "full_payment_hash".to_string(),
        commitment_lock: ScriptVector {
            code_hash: COMMITMENT_LOCK_TESTNET_CODE_HASH.to_string(),
            hash_type: "type".to_string(),
            args: String::new(),
        },
        funding_lock_cell_deps_count: FUNDING_LOCK_CELL_DEPS_COUNT,
        delay_epoch: DEFAULT_DELAY_EPOCH.to_string(),
        commitment_fee_rate: "1000".to_string(),
        udt_type_script: None,
        to_local: "62000000000".to_string(),
        to_remote: "18500000000".to_string(),
        local_reserved: reserved_capacity(&local_close_script, features).to_string(),
        // The node, the acceptor, sizes its reserve over its own close script under the channel's layout
        // (`get_funding_and_reserved_amount`, crates/fiber-lib/src/fiber/network.rs:7586-7593, channel.rs:5811-5850).
        remote_reserved: reserved_capacity(&remote_close_script, features).to_string(),
        local_close_script,
        remote_close_script,
        local_shutdown_fee_rate: "1000".to_string(),
        remote_shutdown_fee_rate: "1200".to_string(),
        tlcs: [
            (0, "offered", "ckb-hash", "1500000000", blake2b_256(b"signing payment one"), "1760576400000", (1, 1)),
            (0, "received", "sha256", "2250000000", blake2b_256(b"signing payment two"), "1760580000000", (2, 2)),
            (1, "offered", "sha256", "750000000", blake2b_256(b"signing payment three"), "1760583600000", (3, 2)),
        ]
        .into_iter()
        .map(|fixture| tlc_vector(signers, fixture))
        .collect(),
    }
}

/// fiber's `build_settlement_data` with every TLC pending (crates/fiber-lib/src/fiber/channel.rs:11409-11530).
fn pending_amount(tlcs: &[TlcVector], direction: &str) -> u128 {
    tlcs.iter().filter(|tlc| tlc.direction == direction).map(|tlc| tlc.amount.parse::<u128>().unwrap()).sum()
}

/// The commitment at `version` of one view, over the channel's terms and TLCs.
fn commitment_case(channel: &SigningChannelVector, name: &str, for_remote: bool, version: u64) -> CommitmentCaseVector {
    let to_local: u128 = channel.to_local.parse().unwrap();
    let to_remote: u128 = channel.to_remote.parse().unwrap();
    CommitmentCaseVector {
        name: name.to_string(),
        for_remote,
        lock_layout: channel.lock_layout.clone(),
        funding_out_point: channel.funding_out_point.clone(),
        commitment_number: version,
        delay_epoch: channel.delay_epoch.clone(),
        fee_rate: channel.commitment_fee_rate.clone(),
        cell_deps_count: channel.funding_lock_cell_deps_count,
        udt_type_script: channel.udt_type_script.clone(),
        to_local: channel.to_local.clone(),
        to_remote: channel.to_remote.clone(),
        settlement_local: (to_local - pending_amount(&channel.tlcs, "offered")).to_string(),
        settlement_remote: (to_remote - pending_amount(&channel.tlcs, "received")).to_string(),
        local_reserved: channel.local_reserved.clone(),
        remote_reserved: channel.remote_reserved.clone(),
        tlcs: channel.tlcs.clone(),
        settlement_witness: String::new(),
        lock_args: String::new(),
        tx_size: 0,
        fee: String::new(),
        transaction: JsonTransaction::default(),
        settlement: None,
        digest: String::new(),
    }
}

fn commitment_request(
    signers: &Signers,
    channel: &SigningChannelVector,
    name: &'static str,
    transition: ChannelSigningTransition,
    slot_number: u64,
    version: u64,
) -> Request {
    let for_remote = matches!(transition, ChannelSigningTransition::SendCommitmentSigned);
    let case = commitment_case(channel, name, for_remote, version);
    let built = build_commitment(&signers.device, &signers.peer, &channel.commitment_lock, &case);
    let peer_signed = !for_remote;
    Request {
        name,
        transition,
        slot: NonceSlot { purpose: NoncePurpose::Commitment, commitment_number: slot_number },
        counter: Some(CommitmentCounter::Local),
        order: KeyOrder::Sorted,
        digest: fiber_types::compute_tx_message(&built.tx),
        signable: Musig2SignableContent::CommitmentTransaction(built.tx),
        peer_signed,
        settlement: Some(to_rpc_signing_settlement(
            &built.settlement,
            built.local_settlement_key,
            built.remote_settlement_key,
            for_remote,
        )),
        next_material: true,
        keeps_signature: false,
    }
}

fn revocation_request(
    signers: &Signers,
    channel: &SigningChannelVector,
    name: &'static str,
    transition: ChannelSigningTransition,
    slot_number: u64,
) -> Request {
    // Received, the revocation pays the device's close script under [local, remote]; sent, the peer's under [remote, local].
    let received = matches!(transition, ChannelSigningTransition::CompleteReceivedRevokeAndAck);
    let case = RevocationCaseVector {
        name: name.to_string(),
        for_remote: received,
        lock_layout: channel.lock_layout.clone(),
        revoked_commitment_number: slot_number - 1,
        payout_script: if received { channel.local_close_script.clone() } else { channel.remote_close_script.clone() },
        delay_epoch: channel.delay_epoch.clone(),
        fee_rate: channel.commitment_fee_rate.clone(),
        cell_deps_count: channel.funding_lock_cell_deps_count,
        udt_type_script: channel.udt_type_script.clone(),
        to_local: channel.to_local.clone(),
        to_remote: channel.to_remote.clone(),
        local_reserved: channel.local_reserved.clone(),
        remote_reserved: channel.remote_reserved.clone(),
        fee: String::new(),
        output: String::new(),
        output_data: String::new(),
        commitment_lock_script_args: String::new(),
        digest: String::new(),
    };
    let built = build_revocation(&signers.device, &signers.peer, &channel.commitment_lock, &case);
    let digest = ckb_blake2b(&[built.output.as_slice(), &built.output_data, &built.args]);
    Request {
        name,
        transition,
        slot: NonceSlot { purpose: NoncePurpose::Revocation, commitment_number: slot_number },
        counter: Some(if received { CommitmentCounter::Local } else { CommitmentCounter::Remote }),
        order: if received { KeyOrder::DeviceFirst } else { KeyOrder::PeerFirst },
        digest,
        signable: Musig2SignableContent::Revocation {
            output: built.output,
            output_data: built.output_data,
            commitment_lock_script_args: built.args,
        },
        peer_signed: received,
        settlement: None,
        next_material: true,
        keeps_signature: received,
    }
}

fn closing_request(signers: &Signers, channel: &SigningChannelVector, name: &'static str, slot_number: u64) -> Request {
    let case = ShutdownCaseVector {
        name: name.to_string(),
        funding_out_point: channel.funding_out_point.clone(),
        local_close_script: channel.local_close_script.clone(),
        remote_close_script: channel.remote_close_script.clone(),
        local_fee_rate: channel.local_shutdown_fee_rate.clone(),
        remote_fee_rate: channel.remote_shutdown_fee_rate.clone(),
        cell_deps_count: channel.funding_lock_cell_deps_count,
        udt_type_script: channel.udt_type_script.clone(),
        to_local: channel.to_local.clone(),
        to_remote: channel.to_remote.clone(),
        local_reserved: channel.local_reserved.clone(),
        remote_reserved: channel.remote_reserved.clone(),
        tx_size: 0,
        local_fee: String::new(),
        remote_fee: String::new(),
        transaction: JsonTransaction::default(),
        digest: String::new(),
    };
    let built = build_shutdown(&signers.device, &signers.peer, &case);
    Request {
        name,
        transition: ChannelSigningTransition::SendClosingSigned,
        slot: NonceSlot { purpose: NoncePurpose::Commitment, commitment_number: slot_number },
        counter: Some(CommitmentCounter::Local),
        order: KeyOrder::Sorted,
        digest: fiber_types::compute_tx_message(&built.tx),
        signable: Musig2SignableContent::CooperativeCloseTransaction(built.tx),
        peer_signed: false,
        settlement: None,
        next_material: false,
        keeps_signature: false,
    }
}

fn announcement_request(signers: &Signers, channel: &SigningChannelVector, name: &'static str) -> Request {
    let node_id = |label: &str| {
        let key = secp256k1::SecretKey::from_slice(&blake2b_256(label.as_bytes())).unwrap();
        hex::encode(pubkey_of(&key).serialize())
    };
    let capacity = [&channel.to_local, &channel.to_remote, &channel.local_reserved, &channel.remote_reserved]
        .iter()
        .map(|amount| amount.parse::<u128>().unwrap())
        .sum::<u128>();
    let case = AnnouncementCaseVector {
        name: name.to_string(),
        chain_hash: hex::encode(blake2b_256(b"chain hash")),
        funding_out_point: channel.funding_out_point.clone(),
        node_ids: [node_id("lsp node"), node_id("peer node")],
        capacity: capacity.to_string(),
        udt_type_script: channel.udt_type_script.clone(),
        digest: String::new(),
    };
    let announcement = build_announcement(&signers.device, &signers.peer, &case);
    Request {
        name,
        transition: ChannelSigningTransition::SignChannelAnnouncement,
        // fiber's one announcement slot, number zero and no counter (crates/fiber-lib/src/fiber/channel.rs:7767-7786).
        slot: NonceSlot { purpose: NoncePurpose::ChannelAnnouncement, commitment_number: 0 },
        counter: None,
        order: KeyOrder::Sorted,
        digest: announcement.message_to_sign(),
        signable: Musig2SignableContent::ChannelAnnouncement(announcement),
        peer_signed: false,
        settlement: None,
        next_material: false,
        keeps_signature: false,
    }
}

// --- the variants ---

/// A compressed key whose x has no point on the curve, the first such of a fixed sequence.
fn off_curve_key() -> [u8; 33] {
    (0u32..)
        .map(|counter| {
            let mut key = [0x02u8; 33];
            key[1..].copy_from_slice(&blake2b_256(format!("off curve {counter}").as_bytes()));
            key
        })
        .find(|key| MusigPublicKey::from_slice(key).is_err())
        .unwrap()
}

/// fiber's verdict on a result: its serde reads it, and its client codec decodes the content or says why not.
fn verdict_of(result: &Value) -> Verdict {
    let parsed: GetChannelSigningStatusResult = serde_json::from_value(result.clone()).expect("a variant fiber's serde reads");
    let ChannelSigningStatus::SignatureRequired { content, .. } = parsed.status else {
        panic!("a variant of a SignatureRequired status");
    };
    match musig2_from_rpc(content) {
        Ok(_) => Verdict { accepted: true, message: None },
        Err(message) => Verdict { accepted: false, message: Some(message) },
    }
}

fn signing_variants(base: &SigningCase) -> Vec<SigningVariant> {
    let pointer = |field: &str| format!("/status/content/{field}");
    let written = |field: &str| {
        let text = base.result.pointer(&pointer(field)).unwrap().as_str().unwrap();
        hex::decode(text.trim_start_matches("0x")).unwrap()
    };
    let ctx = written("key_agg_ctx");
    let agg_nonce = written("agg_nonce");
    assert_eq!(ctx.len(), 71, "the base context is two keys untweaked");
    let (count, keys) = (&ctx[1..5], &ctx[5..]);
    let third_key = pubkey_of(&secp256k1::SecretKey::from_slice(&blake2b_256(b"third key")).unwrap()).serialize();
    let tweak = blake2b_256(b"key agg tweak");
    let three = 3u32.to_be_bytes();

    let mutations: Vec<(&str, &str, Vec<u8>)> = vec![
        ("key_agg_ctx with the parity header bit", "key_agg_ctx", [&[0x01], count, keys].concat()),
        ("key_agg_ctx with the tweak header bit and no tweak", "key_agg_ctx", [&[0x02], count, keys].concat()),
        ("key_agg_ctx with the tweak header bit and its tweak", "key_agg_ctx", [&[0x02][..], &tweak, count, keys].concat()),
        ("key_agg_ctx with a count of 3 and three keys", "key_agg_ctx", [&[0x00][..], &three, keys, &third_key].concat()),
        ("key_agg_ctx with a count of 3 and two keys", "key_agg_ctx", [&[0x00][..], &three, keys].concat()),
        ("key_agg_ctx with an off-curve key", "key_agg_ctx", [&[0x00], count, &keys[..33], &off_curve_key()].concat()),
        ("agg_nonce of 65 bytes", "agg_nonce", agg_nonce[..65].to_vec()),
    ];
    mutations
        .into_iter()
        .map(|(name, field, bytes)| {
            let mut result = base.result.clone();
            *result.pointer_mut(&pointer(field)).unwrap() = Value::String(format!("0x{}", hex::encode(bytes)));
            let verdict = verdict_of(&result);
            SigningVariant { name: name.to_string(), case: base.name.clone(), result, verdict }
        })
        .collect()
}

// --- the watchtower ---

/// fiber's `XUDT_COMPATIBLE_WITNESS` (crates/fiber-lib/src/fiber/channel.rs:11961), an empty `WitnessArgs`.
const XUDT_COMPATIBLE_WITNESS: [u8; 16] = [16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0];
/// The watchtower's fee rate, a literal there (crates/fiber-lib/src/watchtower/actor.rs:1746).
const WATCHTOWER_FEE_RATE: u64 = 1000;
const SECP256K1_BLAKE160_CODE_HASH: &str = "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
const SINCE_VALUE_MASK: u64 = 0x00ff_ffff_ffff_ffff;
const SINCE_RELATIVE_EPOCH_FLAG: u64 = 0xa0;
const SINCE_ABSOLUTE_TIMESTAMP_FLAG: u64 = 0x40;
const SIGNATURE_PLACEHOLDER: [u8; 65] = [0; 65];
const SHANNONS_PER_CKB: u64 = 100_000_000;
/// The two commitments' numbers and their broadcasts' musig2 slots, which no signing case takes.
const REMOTE_BROADCAST_VERSION: u64 = 7;
const LOCAL_BROADCAST_VERSION: u64 = 6;
const MAX_FEE_SHANNONS: u64 = 100_000;
/// The chain's clock: past the outbound TLC's expiry and short of the inbound one's.
const CHAIN_MEDIAN_TIME_MS: u64 = 1_760_600_000_000;
/// The clock of the history where the peer spends first: past both expiries, so the peer times the inbound TLC out.
const PEER_FIRST_MEDIAN_TIME_MS: u64 = 1_760_612_400_000;

fn hex_0x(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn bytes32(hash: &ckb_types::packed::Byte32) -> [u8; 32] {
    hash.as_slice().try_into().unwrap()
}

fn shannons(output: &CellOutput) -> u64 {
    output.capacity().unpack()
}

/// The commitment's epoch, a sponsor's, and the tip, by when every delay of the lock has matured.
fn commitment_epoch() -> EpochNumberWithFraction {
    EpochNumberWithFraction::new(4000, 0, 1800)
}

fn sponsor_epoch() -> EpochNumberWithFraction {
    EpochNumberWithFraction::new(3990, 0, 1800)
}

fn tip_epoch() -> EpochNumberWithFraction {
    EpochNumberWithFraction::new(4002, 0, 1800)
}

fn relative_epoch_since(epoch: EpochNumberWithFraction) -> u64 {
    SINCE_RELATIVE_EPOCH_FLAGS | epoch.full_value()
}

/// fiber's `mul` (crates/fiber-lib/src/watchtower/actor.rs:2493-2522), its overflow checks dropped: a fraction of a delay,
/// the epoch length normalized to at most 1800.
fn mul(delay: EpochNumberWithFraction, numerator: u64, denominator: u64) -> EpochNumberWithFraction {
    let full_numerator = numerator * (delay.number() * delay.length() + delay.index());
    let new_denominator = denominator * delay.length();
    let scale_factor = if new_denominator > 1800 { new_denominator / 1800 + 1 } else { 1 };
    EpochNumberWithFraction::new(
        full_numerator / new_denominator,
        (full_numerator % new_denominator) / scale_factor,
        new_denominator / scale_factor,
    )
}

/// The devnet's deps (crates/fiber-lib/src/ckb/contracts.rs:186-232): genesis cells of ckb-auth, the two locks and the
/// secp256k1 dep group, at fixed out points.
fn devnet_dep(label: &str, index: u32, dep_type: ckb_types::core::DepType) -> CellDep {
    CellDep::new_builder()
        .out_point(PackedOutPoint::new(blake2b_256(label.as_bytes()).pack(), index))
        .dep_type(Byte::new(dep_type as u8))
        .build()
}

fn funding_cell_deps() -> Vec<CellDep> {
    use ckb_types::core::DepType::Code;
    vec![devnet_dep("devnet genesis tx", 6, Code), devnet_dep("devnet genesis tx", 5, Code)]
}

fn settlement_cell_deps() -> Vec<CellDep> {
    use ckb_types::core::DepType::{Code, DepGroup};
    vec![
        devnet_dep("devnet genesis tx", 7, Code),
        devnet_dep("devnet genesis tx", 5, Code),
        devnet_dep("devnet genesis dep group tx", 0, DepGroup),
    ]
}

/// The watchtower's secp256k1 lock, which it pays every spend to (crates/fiber-lib/src/watchtower/actor.rs:1303-1306).
fn watchtower_lock(label: &str) -> PackedScript {
    let key = secp256k1::SecretKey::from_slice(&blake2b_256(label.as_bytes())).unwrap();
    packed_script(&ScriptVector {
        code_hash: SECP256K1_BLAKE160_CODE_HASH.to_string(),
        hash_type: "type".to_string(),
        args: hex::encode(blake160(&pubkey_of(&key).serialize())),
    })
}

/// One TLC each way: the outbound past its expiry, claimable by timeout; the inbound short of it, with a preimage the device
/// holds.
fn watchtower_tlcs(signers: &Signers, preimage: [u8; 32]) -> Vec<TlcVector> {
    let inbound_hash = fiber_types::HashAlgorithm::Sha256.hash(preimage);
    [
        (2, "offered", "ckb-hash", "1500000000", blake2b_256(b"watchtower payment one"), "1760590800000", (5, 5)),
        (1, "received", "sha256", "2250000000", inbound_hash, "1760608800000", (6, 6)),
    ]
    .into_iter()
    .map(|fixture| tlc_vector(signers, fixture))
    .collect()
}

/// fiber's `create_witness_for_funding_cell` (crates/fiber-lib/src/fiber/channel.rs:11979-11990).
fn funding_witness(session: &MusigSession) -> Vec<u8> {
    let xonly = session.aggregated.x_only_public_key().0.serialize();
    [XUDT_COMPATIBLE_WITNESS.as_slice(), &xonly, &session.signature.serialize()].concat()
}

/// fiber-lsp-sdk's `invalid` (crates/fiber-lsp-sdk/src/commitment.rs:186-188).
fn invalid(message: &str) -> SignerError {
    SignerError::InvalidContent(format!("commitment validation: {message}"))
}

fn chain_error(reason: &str) -> SignerError {
    SignerError::Store(format!("harness chain: {reason}"))
}

#[derive(Clone)]
struct ChainCell {
    output: CellOutput,
    data: Vec<u8>,
    epoch: EpochNumberWithFraction,
}

/// The trusted chain fiber-lsp-sdk reads through a `ChainVerifier` (crates/fiber-lsp-sdk/src/onchain.rs:24-38), served from
/// the transactions the generator confirms; its four methods are the trait's, synchronous.
#[derive(Clone)]
struct HarnessChain {
    live: HashMap<Vec<u8>, ChainCell>,
    /// Per confirmed spend, the cell its first input spends.
    parents: HashMap<[u8; 32], PackedOutPoint>,
    /// Per commitment a record names by its raw hash, the hash of the transaction fiber broadcast.
    broadcasts: HashMap<[u8; 32], [u8; 32]>,
    tip: EpochNumberWithFraction,
    median_time_ms: u64,
}

impl HarnessChain {
    fn new(median_time_ms: u64) -> Self {
        HarnessChain {
            live: HashMap::new(),
            parents: HashMap::new(),
            broadcasts: HashMap::new(),
            tip: tip_epoch(),
            median_time_ms,
        }
    }

    fn live_cell(&self, out_point: &PackedOutPoint) -> Result<VerifiedCell, SignerError> {
        let cell = self.live.get(out_point.as_slice()).ok_or_else(|| chain_error("not a live cell"))?;
        Ok(VerifiedCell { output: cell.output.clone(), data: cell.data.clone() })
    }

    fn verify_commitment_lineage(&self, source: Hash256, out_point: &PackedOutPoint) -> Result<(), SignerError> {
        let source: [u8; 32] = source.into();
        let broadcast = self.broadcasts.get(&source).ok_or_else(|| chain_error("the source commitment was never broadcast"))?;
        let mut cursor = out_point.clone();
        loop {
            let index: u32 = cursor.index().unpack();
            let tx_hash = bytes32(&cursor.tx_hash());
            if index != 0 {
                return Err(chain_error("not a commitment lock output"));
            }
            if tx_hash == *broadcast {
                return Ok(());
            }
            cursor = self.parents.get(&tx_hash).cloned().ok_or_else(|| chain_error("not a descendant of the source"))?;
        }
    }

    fn verify_maturity(&self, inputs: &[CellInput]) -> Result<(), SignerError> {
        for input in inputs {
            let since: u64 = input.since().unpack();
            if since == 0 {
                continue;
            }
            let value = since & SINCE_VALUE_MASK;
            match since >> 56 {
                SINCE_RELATIVE_EPOCH_FLAG => {
                    let cell =
                        self.live.get(input.previous_output().as_slice()).ok_or_else(|| chain_error("not a live cell"))?;
                    let delay = EpochNumberWithFraction::from_full_value(value);
                    if cell.epoch.to_rational() + delay.to_rational() > self.tip.to_rational() {
                        return Err(chain_error("a relative epoch since not yet mature"));
                    }
                }
                SINCE_ABSOLUTE_TIMESTAMP_FLAG => {
                    if self.median_time_ms / 1000 < value {
                        return Err(chain_error("an absolute timestamp since not yet mature"));
                    }
                }
                _ => return Err(chain_error("a since the harness does not serve")),
            }
        }
        Ok(())
    }

    fn median_time_ms(&self) -> Result<u64, SignerError> {
        Ok(self.median_time_ms)
    }

    fn add_cell(&mut self, out_point: PackedOutPoint, output: CellOutput, data: Vec<u8>, epoch: EpochNumberWithFraction) {
        self.live.insert(out_point.as_slice().to_vec(), ChainCell { output, data, epoch });
    }

    fn confirm(&mut self, tx: &Transaction) {
        let raw = tx.raw();
        for input in raw.inputs() {
            assert!(self.live.remove(input.previous_output().as_slice()).is_some(), "a spend of a cell that is not live");
        }
        let hash = tx.calc_tx_hash();
        for (index, output) in raw.outputs().into_iter().enumerate() {
            let data = raw.outputs_data().get(index).unwrap().raw_data().to_vec();
            self.add_cell(PackedOutPoint::new(hash.clone(), index as u32), output, data, self.tip);
        }
        self.parents.insert(bytes32(&hash), raw.inputs().get(0).unwrap().previous_output());
    }
}

/// fiber-lsp-sdk's `validate` (crates/fiber-lsp-sdk/src/onchain.rs:61-372), ported verbatim but for the `.await`s: the crate
/// keeps it private, and its public callers, `ChannelSigner::prepare_onchain` and `sign_onchain`, need a signer whose keys
/// fiber-lsp-sdk derives itself, never the SDK's.
fn validate_onchain(
    content: &OnchainSigningContent,
    authorization: &OnchainSpendAuthorization,
    record: &RecoveryRecord,
    chain: &HarnessChain,
) -> Result<(), SignerError> {
    let tx = &content.transaction;
    let raw = tx.raw();
    if raw.version() != 0u32.pack()
        || !raw.header_deps().is_empty()
        || raw.cell_deps().into_iter().collect::<Vec<_>>() != authorization.cell_deps
        || raw.inputs().len() != authorization.additional_inputs.len() + 1
        || raw.outputs().len() != raw.outputs_data().len()
    {
        return Err(invalid("invalid on-chain transaction structure or dependencies"));
    }
    let inputs: Vec<_> = raw.inputs().into_iter().collect();
    let first = inputs.first().ok_or_else(|| invalid("missing commitment input"))?;
    chain.verify_commitment_lineage(authorization.source.tx_hash, &first.previous_output())?;
    chain.verify_maturity(&inputs)?;
    let source = chain.live_cell(&first.previous_output())?;
    let original = record.transaction.raw().outputs().get(0).ok_or_else(|| invalid("missing original output"))?;
    if source.output.type_().to_opt().is_none() && !source.data.is_empty() {
        return Err(invalid("unexpected plain CKB input data"));
    }
    let source_lock = source.output.lock();
    let args = source_lock.args().raw_data();
    let original_args = original.lock().args().raw_data();
    let features = CommitmentContractFeatures::from_lock_args(&original_args).map_err(|e| invalid(&e))?;
    let tlc_len = 65 + features.payment_hash_len();
    if args.len() != original_args.len()
        || args[57..] != original_args[57..]
        || args[..36] != original_args[..36]
        || source_lock.code_hash() != original.lock().code_hash()
        || source_lock.hash_type() != original.lock().hash_type()
        || source.output.type_() != original.type_()
        || args[56] > 1
    {
        return Err(invalid("on-chain source differs from verified commitment"));
    }
    let witness = tx.witnesses().get(0).ok_or_else(|| invalid("missing settlement witness"))?.raw_data();
    const PREFIX: [u8; 16] = [16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0];
    if witness.len() < 18 || witness[..16] != PREFIX || witness[16] != 1 {
        return Err(invalid("expected exactly one settlement unlock"));
    }
    let count = usize::from(witness[17]);
    let body_len = 1 + count * tlc_len + 72;
    let body = witness.get(17..17 + body_len).ok_or_else(|| invalid("truncated settlement witness"))?;
    if fiber_types::blake2b_hash_with_salt(body, &[])[..20] != args[36..56] {
        return Err(invalid("settlement witness is not committed by live input"));
    }
    let initial = settlement_data_to_witness(
        &record.settlement.data,
        record.reference.for_remote,
        features,
        record.settlement.local_settlement_key,
        record.settlement.remote_settlement_key,
    );
    // Every remaining TLC must be an unchanged member of the original signed snapshot.
    let original_tlcs: Vec<_> = initial[1..1 + usize::from(initial[0]) * tlc_len].chunks_exact(tlc_len).collect();
    let remaining: Vec<_> = body[1..1 + count * tlc_len].chunks_exact(tlc_len).collect();
    for (i, entry) in remaining.iter().enumerate() {
        if !original_tlcs.contains(entry) || remaining[..i].contains(entry) {
            return Err(invalid("unexpected or duplicate remaining TLC"));
        }
    }
    let balances = &body[1 + count * tlc_len..];
    let initial_balances = &initial[1 + usize::from(initial[0]) * tlc_len..];
    for offset in [0, 36] {
        if balances[offset..offset + 36] != initial_balances[offset..offset + 36] && balances[offset..offset + 36] != [0; 36] {
            return Err(invalid("on-chain settlement balance differs from signed snapshot"));
        }
    }
    let unlock = &witness[17 + body_len..];
    if unlock.len() != 67 && unlock.len() != 99 {
        return Err(invalid("invalid unlock length"));
    }
    if unlock[1] > 1 || (unlock[1] == 1) != (unlock.len() == 99) || unlock[2..67] != [0; 65] {
        return Err(invalid("invalid unsigned unlock template"));
    }
    let now = chain.median_time_ms()?;
    let local_offset = if record.reference.for_remote { 36 } else { 0 };
    let mut next = body.to_vec();
    let (amount, fraction) = if unlock[0] >= 0xfe {
        let expected = if record.reference.for_remote { 0xff } else { 0xfe };
        if content.key_purpose != OnchainKeyPurpose::Settlement
            || unlock[0] != expected
            || unlock[1] != 0
            || balances[local_offset..local_offset + 20] == [0; 20]
        {
            return Err(invalid("settlement unlock does not belong to signer"));
        }
        if remaining.iter().any(|t| {
            let expiry = u64::from_le_bytes(t[tlc_len - 8..tlc_len].try_into().unwrap()) & 0x00ff_ffff_ffff_ffff;
            now / 1000 <= expiry
        }) {
            return Err(invalid("settlement attempted with unexpired TLCs"));
        }
        let amount = u128::from_le_bytes(balances[local_offset + 20..local_offset + 36].try_into().unwrap());
        next[1 + count * tlc_len + local_offset..1 + count * tlc_len + local_offset + 36].fill(0);
        (amount, 3u128)
    } else {
        let index = usize::from(unlock[0]);
        let entry = remaining.get(index).ok_or_else(|| invalid("invalid TLC unlock index"))?;
        let original_index = original_tlcs.iter().position(|t| t == entry).ok_or_else(|| invalid("untracked TLC"))?;
        let tlc = &record.settlement.data.tlcs[original_index];
        let inbound = tlc.tlc_id.is_received() == record.reference.for_remote;
        let derivation = tlc.local_key_commitment_number.ok_or_else(|| invalid("missing TLC derivation"))?;
        if content.key_purpose != (OnchainKeyPurpose::Tlc { commitment_number: derivation }) {
            return Err(invalid("wrong TLC signing key"));
        }
        if inbound {
            if unlock[1] != 1 || tlc.hash_algorithm.hash(&unlock[67..99]) != *tlc.payment_hash.as_ref() {
                return Err(invalid("invalid TLC fulfillment preimage"));
            }
        } else if unlock[1] != 0 || now / 1000 <= tlc.expiry / 1000 {
            return Err(invalid("TLC timeout has not matured"));
        } else if !inputs.iter().any(|input| {
            let since: u64 = input.since().unpack();
            since >> 56 == 0x40 && (since & 0x00ff_ffff_ffff_ffff) >= tlc.expiry / 1000
        }) {
            return Err(invalid("TLC timeout requires an absolute timestamp input"));
        }
        next.drain(1 + index * tlc_len..1 + (index + 1) * tlc_len);
        next[0] -= 1;
        (tlc.payment_amount, if inbound { 1u128 } else { 2u128 })
    };
    if args[56] == 0 {
        let required = u64::from_le_bytes(args[20..28].try_into().unwrap());
        let actual: u64 = first.since().unpack();
        if !epoch_at_least(actual, required, fraction, 3) {
            return Err(invalid("insufficient on-chain recovery delay"));
        }
    } else if first.since() != 0u64.pack() {
        return Err(invalid("unexpected descendant since"));
    }
    let mut total_capacity: u64 = source.output.capacity().unpack();
    for (input, approved) in inputs.iter().skip(1).zip(&authorization.additional_inputs) {
        if input.previous_output() != *approved
            || *approved == first.previous_output()
            || authorization.additional_inputs.iter().filter(|p| *p == approved).count() != 1
        {
            return Err(invalid("unexpected or duplicate fee input"));
        }
        let cell = chain.live_cell(approved)?;
        if cell.output.type_().to_opt().is_some() || !cell.data.is_empty() || cell.output.lock() != authorization.destination {
            return Err(invalid("fee input is not approved plain CKB"));
        }
        let capacity: u64 = cell.output.capacity().unpack();
        total_capacity = total_capacity.checked_add(capacity).ok_or_else(|| invalid("capacity overflow"))?;
    }
    let udt = source.output.type_().to_opt().is_some();
    let source_capacity: u64 = source.output.capacity().unpack();
    let remote_offset = 36 - local_offset;
    let final_party = unlock[0] >= 0xfe && balances[remote_offset..remote_offset + 20] == [0; 20];
    let source_tokens = if udt {
        u128::from_le_bytes(source.data.as_slice().try_into().map_err(|_| invalid("invalid token data"))?)
    } else {
        u128::from(source_capacity)
    };
    let payout = if final_party { source_tokens } else { amount.min(source_tokens) };
    if !final_party && payout != amount {
        return Err(invalid("claim exceeds live cell balance"));
    }
    let mut expected_remaining = source.output.clone();
    let mut next_args = args[..36].to_vec();
    next_args.extend_from_slice(&fiber_types::blake2b_hash_with_salt(&next, &[])[..20]);
    next_args.push(1);
    next_args.extend_from_slice(&args[57..]);
    expected_remaining = expected_remaining
        .as_builder()
        .lock(source_lock.as_builder().args(next_args.pack()).build())
        .capacity(if udt {
            if unlock[0] >= 0xfe {
                source
                    .output
                    .occupied_capacity(Capacity::bytes(16).map_err(|_| invalid("capacity overflow"))?)
                    .map_err(|_| invalid("capacity overflow"))?
                    .as_u64()
            } else {
                source_capacity
            }
        } else {
            source_capacity
                .checked_sub(u64::try_from(payout).map_err(|_| invalid("payout overflow"))?)
                .ok_or_else(|| invalid("negative remaining capacity"))?
        })
        .build();
    let remainder_data = if udt {
        source_tokens.checked_sub(payout).ok_or_else(|| invalid("negative token remainder"))?.to_le_bytes().to_vec()
    } else {
        vec![]
    };
    let mut remainder_seen = final_party;
    let mut destination_tokens = 0u128;
    let mut output_capacity = 0u64;
    let mut destinations = 0;
    for (i, output) in raw.outputs().into_iter().enumerate() {
        let data = raw.outputs_data().get(i).ok_or_else(|| invalid("missing output data"))?.raw_data();
        let capacity: u64 = output.capacity().unpack();
        output_capacity = output_capacity.checked_add(capacity).ok_or_else(|| invalid("output overflow"))?;
        if !remainder_seen && output == expected_remaining && data.as_ref() == remainder_data {
            remainder_seen = true;
            continue;
        }
        if output.lock() != authorization.destination {
            return Err(invalid("unapproved on-chain destination"));
        }
        destinations += 1;
        if udt && output.type_() == source.output.type_() {
            destination_tokens = destination_tokens
                .checked_add(u128::from_le_bytes(data.as_ref().try_into().map_err(|_| invalid("invalid payout data"))?))
                .ok_or_else(|| invalid("token overflow"))?;
        } else if output.type_().to_opt().is_some() || !data.is_empty() {
            return Err(invalid("unexpected output asset"));
        }
    }
    if !remainder_seen
        || destinations == 0
        || destinations > 2
        || total_capacity.checked_sub(output_capacity) != Some(authorization.fee)
        || (udt && destination_tokens != payout)
    {
        return Err(invalid("on-chain outputs do not conserve authorized funds and fee"));
    }
    Ok(())
}

/// fiber-lsp-sdk's `epoch_at_least` (crates/fiber-lsp-sdk/src/onchain.rs:374-395), verbatim.
fn epoch_at_least(actual: u64, required: u64, numerator: u128, denominator: u128) -> bool {
    if actual >> 56 != 0xa0 || required >> 56 != 0xa0 {
        return false;
    }
    let parts = |value| {
        let e = EpochNumberWithFraction::from_full_value(value & 0x00ff_ffff_ffff_ffff);
        if e.length() == 0 || e.index() >= e.length() {
            None
        } else {
            Some((u128::from(e.number()) * u128::from(e.length()) + u128::from(e.index()), u128::from(e.length())))
        }
    };
    match (parts(actual), parts(required)) {
        (Some((a, b)), Some((c, d))) => a * d * denominator >= c * b * numerator,
        _ => false,
    }
}

/// fiber's `Unlock` (crates/fiber-lib/src/watchtower/actor.rs:2353-2403), with the signature it is handed over without.
struct Unlock {
    unlock_type: u8,
    preimage: Option<[u8; 32]>,
}

impl Unlock {
    fn to_witness(&self) -> Vec<u8> {
        let mut witness = vec![self.unlock_type, u8::from(self.preimage.is_some())];
        witness.extend(SIGNATURE_PLACEHOLDER);
        witness.extend(self.preimage.iter().flatten());
        witness
    }
}

/// What the watchtower settles on a cell, the first input's since and the sponsors' (actor.rs:1637-1652) with it.
struct Pick {
    kind: &'static str,
    unlock: Unlock,
    amount: u128,
    purpose: OnchainKeyPurpose,
    since: u64,
    sponsor_since: u64,
    two_parties_all_settled: bool,
}

/// A commitment lock cell the watchtower spends, with the settlement body its lock args commit.
struct SpendSource {
    out_point: PackedOutPoint,
    output: CellOutput,
    body: Vec<u8>,
    first: bool,
}

/// The settlement body's TLC records and its two balance records.
fn body_parts(body: &[u8], tlc_len: usize) -> (Vec<&[u8]>, &[u8]) {
    let count = usize::from(body[0]);
    (body[1..1 + count * tlc_len].chunks_exact(tlc_len).collect(), &body[1 + count * tlc_len..])
}

/// fiber's `SettlementWitness::update` of one unlock (crates/fiber-lib/src/watchtower/actor.rs:2447-2476): a TLC leaves the
/// body, `0xFF` zeroes the second balance and `0xFE` the first.
fn next_settlement_body(body: &[u8], unlock_type: u8, tlc_len: usize) -> Vec<u8> {
    let balances = 1 + usize::from(body[0]) * tlc_len;
    let mut next = body.to_vec();
    match unlock_type {
        0xff => next[balances + 36..balances + 72].fill(0),
        0xfe => next[balances..balances + 36].fill(0),
        index => {
            let index = usize::from(index);
            assert!(index < usize::from(body[0]), "an unlock of a TLC the body does not hold");
            next.drain(1 + index * tlc_len..1 + (index + 1) * tlc_len);
            next[0] -= 1;
        }
    }
    next
}

/// One view's watch: the commitment fiber broadcast, the device's record of it, and the chain it lands on.
struct WatchedCommitment {
    for_remote: bool,
    label: &'static str,
    built: crate::CommitmentBuild,
    broadcast: Transaction,
    record: RecoveryRecord,
}

struct WatchtowerFixture {
    channel: SigningChannelVector,
    features: CommitmentContractFeatures,
    destination: PackedScript,
    funding_cell_deps: Vec<CellDep>,
    settlement_cell_deps: Vec<CellDep>,
    preimages: Vec<[u8; 32]>,
}

impl WatchtowerFixture {
    fn tlc_len(&self) -> usize {
        65 + self.features.payment_hash_len()
    }
}

/// One side of a force close as its watchtower acts: its view of the commitment, its settlement key, its preimages.
struct Party<'a> {
    for_remote: bool,
    settlement_key: fiber_types::Pubkey,
    preimages: &'a [[u8; 32]],
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Side {
    Device,
    Peer,
}

impl Side {
    fn party<'a>(self, fixture: &'a WatchtowerFixture, watched: &WatchedCommitment) -> Party<'a> {
        match self {
            Side::Device => Party {
                for_remote: watched.for_remote,
                settlement_key: watched.built.local_settlement_key,
                preimages: &fixture.preimages,
            },
            // The peer holds no preimage: its inbound TLC is the device's outbound one, whose preimage the payee keeps.
            Side::Peer => {
                Party { for_remote: !watched.for_remote, settlement_key: watched.built.remote_settlement_key, preimages: &[] }
            }
        }
    }
}

/// fiber's `verified_watch_preimage` (crates/fiber-lib/src/watchtower/actor.rs:1212-1231).
fn preimage_in(preimages: &[[u8; 32]], tlc: &fiber_types::SettlementTlc) -> Option<[u8; 32]> {
    preimages.iter().copied().find(|preimage| tlc.hash_algorithm.hash(preimage) == *tlc.payment_hash.as_ref())
}

/// The TLC a witness record stands for, by fiber's identity mapping (crates/fiber-lib/src/watchtower/actor.rs:822-866).
fn tlc_of<'a>(fixture: &WatchtowerFixture, watched: &'a WatchedCommitment, entry: &[u8]) -> &'a fiber_types::SettlementTlc {
    let tlcs = &watched.built.settlement.tlcs;
    tlcs.iter()
        .find(|tlc| settlement_tlc_to_witness(tlc, watched.for_remote, fixture.features) == entry)
        .expect("a witness record of the snapshot's")
}

fn tlc_pick(index: usize, tlc: &fiber_types::SettlementTlc, preimage: Option<[u8; 32]>, since: u64) -> Pick {
    Pick {
        kind: if preimage.is_some() { "inbound TLC by preimage" } else { "outbound TLC by timeout" },
        unlock: Unlock { unlock_type: u8::try_from(index).unwrap(), preimage },
        amount: tlc.payment_amount,
        purpose: OnchainKeyPurpose::Tlc { commitment_number: tlc.local_key_commitment_number.unwrap() },
        since,
        sponsor_since: if preimage.is_some() { 0 } else { fiber_types::watchtower::settlement_timestamp_since(tlc.expiry) },
        two_parties_all_settled: false,
    }
}

fn settlement_pick(for_remote: bool, amount: u128, since: u64, two_parties_all_settled: bool) -> Pick {
    Pick {
        kind: if two_parties_all_settled { "settlement as the last party" } else { "settlement" },
        unlock: Unlock { unlock_type: if for_remote { 0xff } else { 0xfe }, preimage: None },
        amount,
        purpose: OnchainKeyPurpose::Settlement,
        since,
        sponsor_since: 0,
        two_parties_all_settled,
    }
}

/// The unlock fiber's `build_settlement_tx` picks on a cell for one side (crates/fiber-lib/src/watchtower/actor.rs:1310-1621):
/// its descendant arm on a remainder, its first arm on the commitment, at a tip past every delay, so only the clock and the
/// preimages choose. The witness flag of a TLC is the device's id, so the side's view decides which TLCs time out.
fn pick_unlock(
    fixture: &WatchtowerFixture,
    watched: &WatchedCommitment,
    party: &Party,
    source: &SpendSource,
    now_ms: u64,
) -> Option<Pick> {
    let for_remote = party.for_remote;
    let (own, other) = if for_remote { (36, 0) } else { (0, 36) };
    let args = source.output.lock().args().raw_data();
    let delay_since = u64::from_le_bytes(args[20..28].try_into().unwrap());
    assert_eq!(delay_since >> 56, SINCE_RELATIVE_EPOCH_FLAG, "the lock's delay is a relative epoch");
    let delay = EpochNumberWithFraction::from_full_value(delay_since & SINCE_VALUE_MASK);
    if source.first {
        let settlement = &watched.built.settlement;
        let mut pending = settlement.tlcs.len();
        for (index, tlc) in settlement.tlcs.iter().enumerate() {
            if tlc.tlc_id.is_offered() == for_remote {
                if now_ms > tlc.expiry {
                    return Some(tlc_pick(index, tlc, None, relative_epoch_since(mul(delay, 2, 3))));
                }
            } else if let Some(preimage) = preimage_in(party.preimages, tlc) {
                return Some(tlc_pick(index, tlc, Some(preimage), relative_epoch_since(mul(delay, 1, 3))));
            } else if now_ms > tlc.expiry {
                pending -= 1;
            }
        }
        // The side's own amount of the snapshot, which its balance record in the body states.
        let balances = body_parts(&source.body, fixture.tlc_len()).1;
        let own_amount = u128::from_le_bytes(balances[own + 20..own + 36].try_into().unwrap());
        return (pending == 0).then(|| settlement_pick(for_remote, own_amount, relative_epoch_since(delay), false));
    }
    let (entries, balances) = body_parts(&source.body, fixture.tlc_len());
    if balances[own..own + 20] != blake160(&party.settlement_key.0) {
        return None;
    }
    let own_amount = u128::from_le_bytes(balances[own + 20..own + 36].try_into().unwrap());
    if balances[other..other + 20] == [0; 20] {
        return Some(settlement_pick(for_remote, own_amount, 0, true));
    }
    let mut pending = entries.len();
    for (index, entry) in entries.iter().enumerate() {
        let since = u64::from_le_bytes(entry[entry.len() - 8..].try_into().unwrap());
        if since >> 56 != SINCE_ABSOLUTE_TIMESTAMP_FLAG {
            continue;
        }
        let expiry = (since & SINCE_VALUE_MASK) * 1000;
        let tlc = tlc_of(fixture, watched, entry);
        // fiber's witness flag: bit 0 clear for an offered TLC (crates/fiber-lib/src/watchtower/actor.rs:2333-2335).
        if (entry[0] & 1 == 0) == for_remote {
            if now_ms > expiry {
                return Some(tlc_pick(index, tlc, None, 0));
            }
        } else if let Some(preimage) = preimage_in(party.preimages, tlc) {
            return Some(tlc_pick(index, tlc, Some(preimage), 0));
        } else if now_ms > expiry {
            pending -= 1;
        }
    }
    (pending == 0).then(|| settlement_pick(for_remote, own_amount, 0, false))
}

/// The CKB arm of fiber's `build_settlement_tx` (crates/fiber-lib/src/watchtower/actor.rs:1653-1840): the remainder first and
/// the destination's output second, the sponsors added one at a time until they pay for that output and the fee. Returns the
/// spend and the body its remainder commits, if it has one.
fn build_spend(
    fixture: &WatchtowerFixture,
    source: &SpendSource,
    pick: &Pick,
    sponsors: &[(PackedOutPoint, u64)],
) -> (Transaction, Option<Vec<u8>>) {
    let args = source.output.lock().args().raw_data();
    let next = next_settlement_body(&source.body, pick.unlock.unlock_type, fixture.tlc_len());
    let next_args = [&args[0..36], &blake160(&next), &[0x01], &args[57..]].concat();
    let capacity = shannons(&source.output);
    let released = if pick.two_parties_all_settled { u128::from(capacity) } else { pick.amount };
    let new_capacity = u64::try_from(u128::from(capacity).saturating_sub(released)).unwrap();
    let remainder = source
        .output
        .clone()
        .as_builder()
        .lock(source.output.lock().as_builder().args(next_args.pack()).build())
        .capacity(new_capacity)
        .build();
    let settlement_output =
        CellOutput::new_builder().lock(fixture.destination.clone()).capacity(u64::try_from(released).unwrap()).build();
    let witness = [XUDT_COMPATIBLE_WITNESS.as_slice(), &[0x01], &source.body, &pick.unlock.to_witness()].concat();
    let placeholder = WitnessArgs::new_builder()
        .lock(BytesOpt::new_builder().set(Some(SIGNATURE_PLACEHOLDER.to_vec().pack())).build())
        .build();
    let input = CellInput::new_builder().previous_output(source.out_point.clone()).since(pick.since).build();
    let mut builder = TransactionBuilder::default().cell_deps(fixture.settlement_cell_deps.clone()).input(input);
    if !pick.two_parties_all_settled {
        builder = builder.output(remainder.clone()).output_data(Vec::<u8>::new().pack());
    }
    builder = builder
        .output(settlement_output.clone())
        .output_data(Vec::<u8>::new().pack())
        .witness(witness.pack())
        .witness(placeholder.as_bytes().pack());
    let occupied = settlement_output.occupied_capacity(Capacity::shannons(0)).unwrap().as_u64();
    let mut inputs_capacity = capacity;
    for (out_point, sponsor_capacity) in sponsors {
        inputs_capacity += sponsor_capacity;
        builder = builder.input(CellInput::new_builder().previous_output(out_point.clone()).since(pick.sponsor_since).build());
        let size = builder.clone().build().data().serialized_size_in_block() as u64;
        let fee = FeeRate::from_u64(WATCHTOWER_FEE_RATE).fee(size).as_u64();
        if inputs_capacity >= new_capacity + occupied + fee {
            let change = settlement_output.as_builder().capacity(inputs_capacity - new_capacity - fee).build();
            let outputs = if pick.two_parties_all_settled { vec![change] } else { vec![remainder, change] };
            let tx = builder.set_outputs(outputs).build().data();
            return (tx, (!pick.two_parties_all_settled).then_some(next));
        }
    }
    panic!("the sponsors do not cover the spend");
}

/// fiber-lsp-sdk's on-chain arm of `sign_content` (crates/fiber-lsp-sdk/src/signer.rs:1237-1252): recoverable ECDSA over
/// the transaction message with the purpose's key, the recovery id last.
fn sign_onchain(signer: &InMemorySigner, purpose: OnchainKeyPurpose, message: [u8; 32]) -> ([u8; 65], fiber_types::Pubkey) {
    let key = match purpose {
        OnchainKeyPurpose::Settlement => signer.tlc_base_key.clone(),
        OnchainKeyPurpose::Tlc { commitment_number } => signer.derive_tlc_key(commitment_number),
    };
    let (recovery_id, compact) = SECP256K1.sign_ecdsa_recoverable(&Message::from_digest(message), &key.0).serialize_compact();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&compact);
    signature[64] = i32::from(recovery_id) as u8;
    (signature, key.pubkey())
}

/// fiber's `verify_onchain_signature` (crates/fiber-lib/src/watchtower/signer.rs:131-147), after the length check of
/// `submit_watchtower_signature` (crates/fiber-lib/src/rpc/watchtower.rs:412-416).
fn verify_onchain_signature(expected: &[u8; 33], message: [u8; 32], signature: &[u8]) -> Result<(), String> {
    if signature.len() != 65 {
        return Err("watchtower signature must be 65 bytes".to_string());
    }
    let recovery_id = RecoveryId::try_from(i32::from(signature[64])).map_err(|e| format!("invalid recovery id: {e}"))?;
    let signature = RecoverableSignature::from_compact(&signature[..64], recovery_id)
        .map_err(|e| format!("invalid compact signature: {e}"))?;
    let recovered = SECP256K1
        .recover_ecdsa(&Message::from_digest(message), &signature)
        .map_err(|e| format!("failed to recover pubkey: {e}"))?;
    if recovered.serialize() != *expected {
        return Err("recovered public key does not match expected public key".to_string());
    }
    Ok(())
}

fn json_purpose(purpose: OnchainKeyPurpose) -> JsonOnchainKeyPurpose {
    match purpose {
        OnchainKeyPurpose::Settlement => JsonOnchainKeyPurpose::Settlement,
        OnchainKeyPurpose::Tlc { commitment_number } => JsonOnchainKeyPurpose::Tlc { commitment_number },
    }
}

/// The commitment of one view as fiber broadcasts it: signed, with the funding lock's deps
/// (crates/fiber-lib/src/fiber/channel.rs:11567-11581).
fn watched_commitment(signers: &Signers, fixture: &WatchtowerFixture, for_remote: bool) -> WatchedCommitment {
    let (label, version) =
        if for_remote { ("peer's commitment", REMOTE_BROADCAST_VERSION) } else { ("own commitment", LOCAL_BROADCAST_VERSION) };
    let channel = &fixture.channel;
    let built = build_commitment(
        &signers.device,
        &signers.peer,
        &channel.commitment_lock,
        &commitment_case(channel, label, for_remote, version),
    );
    let message = compute_tx_message(&built.tx);
    let slot = NonceSlot { purpose: NoncePurpose::Commitment, commitment_number: version };
    let session = musig_session(signers, KeyOrder::Sorted.device_first(signers), slot, message);
    let broadcast = built
        .tx
        .clone()
        .as_builder()
        .raw(built.tx.raw().as_builder().cell_deps(fixture.funding_cell_deps.clone().pack()).build())
        .witnesses(vec![funding_witness(&session).pack()].pack())
        .build();
    assert_eq!(compute_tx_message(&broadcast), message, "{label}: the deps and the witness are outside the message");
    let record = RecoveryRecord {
        reference: CommitmentReference { for_remote, version, tx_hash: bytes32(&built.tx.calc_tx_hash()).into() },
        transaction: built.tx.clone(),
        settlement: OwnedSettlementBinding {
            data: built.settlement.clone(),
            local_settlement_key: built.local_settlement_key,
            remote_settlement_key: built.remote_settlement_key,
            for_remote: Some(for_remote),
        },
        content: ChannelSigningContent::Musig2(Musig2SigningContent {
            slot,
            commitment_counter: Some(CommitmentCounter::Local),
            key_agg_ctx: session.key_agg_ctx.clone(),
            agg_nonce: session.agg_nonce.clone(),
            content: Musig2SignableContent::CommitmentTransaction(built.tx.clone()),
        }),
        // Sent, the device never sees the peer's half; received, it completes the signature
        // (crates/fiber-lsp-sdk/src/lifecycle.rs:260-292).
        session: fiber_lsp_sdk::SigningSessionEvidence {
            peer_public_nonce: session.peer_nonce.clone(),
            peer_partial_signature: (!for_remote).then_some(session.peer_partial),
        },
        complete_signature: (!for_remote).then_some(session.signature),
    };
    WatchedCommitment { for_remote, label, built, broadcast, record }
}

/// The external-signer watch channel fiber registers for the two views (crates/fiber-lib/src/fiber/channel.rs:11533-11552).
fn watch_channel(
    signers: &Signers,
    fixture: &WatchtowerFixture,
    remote: &WatchedCommitment,
    local: &WatchedCommitment,
) -> ChannelData {
    ChannelData {
        channel_id: Hash256::from(bytes_of::<32>(fixture.channel.channel_id.trim_start_matches("0x"))),
        funding_udt_type_script: None,
        local_settlement_key: None,
        local_settlement_key_pubkey: Some(remote.built.local_settlement_key),
        remote_settlement_key: remote.built.remote_settlement_key,
        local_funding_pubkey: fiber_pubkey(&pubkey_of(&signers.device.funding_key)),
        remote_funding_pubkey: fiber_pubkey(&pubkey_of(&signers.peer.funding_key)),
        remote_settlement_data: remote.built.settlement.clone(),
        pending_remote_settlement_data: remote.built.settlement.clone(),
        local_settlement_data: local.built.settlement.clone(),
        revocation_data: None,
        commitment_contract_features: fixture.features,
    }
}

/// The watchtower's own cells a spend's fee comes from, at the destination: the first spend of the peer's commitment takes
/// two, the first too small to cover the destination's output.
fn sponsor_capacities(for_remote: bool, index: usize) -> Vec<u64> {
    if for_remote && index == 0 {
        vec![30 * SHANNONS_PER_CKB, 100 * SHANNONS_PER_CKB]
    } else {
        vec![100 * SHANNONS_PER_CKB]
    }
}

struct WatchedSpend {
    vector: WatchtowerSpendVector,
    purpose: OnchainKeyPurpose,
    tx: Transaction,
    authorization: OnchainSpendAuthorization,
    /// The chain the spend is validated against, before it confirms.
    chain: HarnessChain,
}

/// One history of a commitment cell: the device's spends, and the peer's when it spends too.
struct WatchedHistory {
    spends: Vec<WatchedSpend>,
    peer_spends: Vec<PeerSpendVector>,
}

/// The spends of one commitment, each by the side `schedule` names in turn and built as that side's watchtower builds it,
/// the next spending the remainder of the one before; each of the device's validated by fiber-lsp-sdk's `validate` and
/// signed as fiber-lsp-sdk signs it.
fn watched_history(
    signers: &Signers,
    fixture: &WatchtowerFixture,
    channel_data: &ChannelData,
    watched: &WatchedCommitment,
    label: &str,
    median_time_ms: u64,
    schedule: &[Side],
) -> WatchedHistory {
    let onchain_hash = watched.broadcast.calc_tx_hash();
    let commitment_output = watched.broadcast.raw().outputs().get(0).unwrap();
    let mut chain = HarnessChain::new(median_time_ms);
    chain.broadcasts.insert(watched.record.reference.tx_hash.into(), bytes32(&onchain_hash));
    chain.add_cell(PackedOutPoint::new(onchain_hash.clone(), 0), commitment_output.clone(), Vec::new(), commitment_epoch());
    let mut source = Some(SpendSource {
        out_point: PackedOutPoint::new(onchain_hash, 0),
        output: commitment_output,
        body: watched.built.witness.clone(),
        first: true,
    });
    let mut history = WatchedHistory { spends: Vec::new(), peer_spends: Vec::new() };
    for (step, side) in schedule.iter().enumerate() {
        let cell = source.take().unwrap_or_else(|| panic!("{label}: no cell left for the {side:?}"));
        let pick = pick_unlock(fixture, watched, &side.party(fixture, watched), &cell, chain.median_time_ms)
            .unwrap_or_else(|| panic!("{label}: the {side:?} has nothing to spend"));
        let name = match side {
            Side::Device => format!("{label}: {}", pick.kind),
            Side::Peer => format!("{label}: peer's {}", pick.kind),
        };
        let sponsors: Vec<(PackedOutPoint, u64)> = sponsor_capacities(watched.for_remote, step)
            .into_iter()
            .enumerate()
            .map(|(index, capacity)| {
                let label = format!("watchtower sponsor of {name}");
                (PackedOutPoint::new(blake2b_256(label.as_bytes()).pack(), index as u32), capacity)
            })
            .collect();
        for (out_point, capacity) in &sponsors {
            let output = CellOutput::new_builder().lock(fixture.destination.clone()).capacity(*capacity).build();
            chain.add_cell(out_point.clone(), output, Vec::new(), sponsor_epoch());
        }
        let (tx, next) = build_spend(fixture, &cell, &pick, &sponsors);
        let tx_hash = tx.calc_tx_hash();
        match side {
            Side::Device => history.spends.push(device_spend(
                signers,
                fixture,
                channel_data,
                watched,
                &chain,
                &cell,
                &pick,
                &sponsors,
                name,
                &tx,
            )),
            Side::Peer => history.peer_spends.push(PeerSpendVector {
                name,
                transaction: tx.clone().into(),
                tx_hash: hex_0x(tx_hash.as_slice()),
            }),
        }
        chain.confirm(&tx);
        source = next.map(|body| SpendSource {
            out_point: PackedOutPoint::new(tx_hash, 0),
            output: tx.raw().outputs().get(0).unwrap(),
            body,
            first: false,
        });
    }
    if let Some(cell) = &source {
        let device = Side::Device.party(fixture, watched);
        assert!(
            pick_unlock(fixture, watched, &device, cell, chain.median_time_ms).is_none(),
            "{label}: the device has more to spend"
        );
    }
    history
}

/// One spend of the device's: validated by fiber-lsp-sdk's `validate` on the chain it meets, then signed with the key
/// fiber expects for its purpose.
#[allow(clippy::too_many_arguments)]
fn device_spend(
    signers: &Signers,
    fixture: &WatchtowerFixture,
    channel_data: &ChannelData,
    watched: &WatchedCommitment,
    chain: &HarnessChain,
    cell: &SpendSource,
    pick: &Pick,
    sponsors: &[(PackedOutPoint, u64)],
    name: String,
    tx: &Transaction,
) -> WatchedSpend {
    let inputs_capacity = shannons(&cell.output) + sponsors.iter().map(|(_, capacity)| capacity).sum::<u64>();
    let outputs_capacity: u64 = tx.raw().outputs().into_iter().map(|output| shannons(&output)).sum();
    let authorization = OnchainSpendAuthorization {
        source: watched.record.reference.clone(),
        destination: fixture.destination.clone(),
        fee: inputs_capacity - outputs_capacity,
        additional_inputs: sponsors.iter().map(|(out_point, _)| out_point.clone()).collect(),
        cell_deps: fixture.settlement_cell_deps.clone(),
    };
    let content = OnchainSigningContent { key_purpose: pick.purpose, transaction: tx.clone() };
    validate_onchain(&content, &authorization, &watched.record, chain)
        .unwrap_or_else(|error| panic!("{name}: fiber-lsp-sdk's validate refuses the watchtower's spend: {error}"));
    let destination_paid: u64 = tx
        .raw()
        .outputs()
        .into_iter()
        .filter(|output| output.lock() == fixture.destination)
        .map(|output| shannons(&output))
        .sum();
    let released = if pick.two_parties_all_settled { u128::from(shannons(&cell.output)) } else { pick.amount };
    assert!(
        u128::from(destination_paid) + u128::from(MAX_FEE_SHANNONS) >= released,
        "{name}: the destination is paid less than the device's bound"
    );

    let message = compute_tx_message(tx);
    let (signature, signer_pubkey) = sign_onchain(&signers.device_native, pick.purpose, message);
    let expected = channel_data.expected_onchain_pubkey(&pick.purpose).unwrap();
    assert_eq!(expected, signer_pubkey, "{name}: not the key fiber expects for the purpose");
    verify_onchain_signature(&expected.0, message, &signature).unwrap();
    WatchedSpend {
        vector: WatchtowerSpendVector {
            name,
            key_purpose: json_purpose(pick.purpose),
            transaction: tx.clone().into(),
            request_id: hex_0x(blake2b_256(tx.as_slice())),
            message: hex_0x(message),
            tx_hash: hex_0x(tx.calc_tx_hash().as_slice()),
            released_shannons: released.to_string(),
            signer_pubkey: hex_0x(signer_pubkey.0),
            signature: hex_0x(signature),
        },
        purpose: pick.purpose,
        tx: tx.clone(),
        authorization,
        chain: chain.clone(),
    }
}

fn with_outputs(tx: &Transaction, outputs: Vec<CellOutput>) -> Transaction {
    let data = vec![Vec::<u8>::new().pack(); outputs.len()];
    tx.clone().as_advanced_builder().set_outputs(outputs).set_outputs_data(data).build().data()
}

fn with_witness(tx: &Transaction, edit: impl FnOnce(&mut Vec<u8>)) -> Transaction {
    let mut witnesses: Vec<ckb_types::packed::Bytes> = tx.witnesses().into_iter().collect();
    let mut witness = witnesses[0].raw_data().to_vec();
    edit(&mut witness);
    witnesses[0] = witness.pack();
    tx.clone().as_advanced_builder().set_witnesses(witnesses).build().data()
}

fn outputs_of(tx: &Transaction) -> Vec<CellOutput> {
    tx.raw().outputs().into_iter().collect()
}

/// Where a spend's balance records start in its witness: after the prefix, the unlock count, the TLC count and the TLCs.
fn balances_offset(tx: &Transaction, tlc_len: usize) -> usize {
    18 + usize::from(tx.witnesses().get(0).unwrap().raw_data()[17]) * tlc_len
}

/// Spends with one part changed, each with the verdict of fiber-lsp-sdk's `validate`, on the chain its spend met.
fn watchtower_variants(fixture: &WatchtowerFixture, watched: &[WatchedView]) -> Vec<WatchtowerVariant> {
    let ckb = |capacity: u64, delta: i64| capacity.checked_add_signed(delta * SHANNONS_PER_CKB as i64).unwrap();
    let tlc_len = fixture.tlc_len();
    let (remote, remote_spends) = (&watched[0].commitment, &watched[0].spends);
    let (local, local_spends) = (&watched[1].commitment, &watched[1].spends);
    let other_number = |purpose: OnchainKeyPurpose| {
        let OnchainKeyPurpose::Tlc { commitment_number } = purpose else { panic!("a TLC spend") };
        let other =
            fixture.channel.tlcs.iter().map(|tlc| tlc.local_key_commitment_number).find(|number| *number != commitment_number);
        OnchainKeyPurpose::Tlc { commitment_number: other.unwrap() }
    };
    let first = &remote_spends[0];
    let mut variants: Vec<(&str, &WatchedCommitment, &WatchedSpend, Transaction, OnchainKeyPurpose)> = Vec::new();

    let mut outputs = outputs_of(&first.tx);
    outputs[1] = outputs[1].clone().as_builder().lock(watchtower_lock("foreign destination key")).build();
    variants.push(("foreign destination", remote, first, with_outputs(&first.tx, outputs), first.purpose));

    let mut outputs = outputs_of(&first.tx);
    outputs[0] = outputs[0].clone().as_builder().capacity(ckb(shannons(&outputs[0]), -1)).build();
    outputs[1] = outputs[1].clone().as_builder().capacity(ckb(shannons(&outputs[1]), 1)).build();
    variants.push(("altered remainder", remote, first, with_outputs(&first.tx, outputs), first.purpose));

    let timeout = &local_spends[0];
    let foreign = with_witness(&timeout.tx, |witness| witness[35..67].copy_from_slice(&blake2b_256(b"foreign payment")));
    variants.push(("foreign TLC", local, timeout, foreign, timeout.purpose));

    variants.push(("key of another number", remote, first, first.tx.clone(), other_number(first.purpose)));

    let settlement = &remote_spends[2];
    let offset = balances_offset(&settlement.tx, tlc_len);
    let moved = with_witness(&settlement.tx, |witness| {
        for (start, delta) in [(offset + 20, -1), (offset + 56, 1)] {
            let amount = u128::from_le_bytes(witness[start..start + 16].try_into().unwrap());
            let moved = amount.checked_add_signed(i128::from(delta) * i128::from(SHANNONS_PER_CKB)).unwrap();
            witness[start..start + 16].copy_from_slice(&moved.to_le_bytes());
        }
    });
    variants.push(("moved balance", remote, settlement, moved, settlement.purpose));

    let descendant = &remote_spends[1];
    let original = &remote.built.witness;
    let entry = body_parts(&descendant.tx.witnesses().get(0).unwrap().raw_data()[17..], tlc_len).0[0].to_vec();
    let index = body_parts(original, tlc_len).0.iter().position(|record| *record == entry.as_slice()).unwrap();
    let uncommitted = with_witness(&descendant.tx, |witness| {
        let unlock = Unlock { unlock_type: u8::try_from(index).unwrap(), preimage: None };
        *witness = [XUDT_COMPATIBLE_WITNESS.as_slice(), &[0x01], original, &unlock.to_witness()].concat();
    });
    variants.push(("uncommitted witness", remote, descendant, uncommitted, descendant.purpose));

    let outputs = outputs_of(&settlement.tx);
    let paid_out = outputs[1].clone().as_builder().capacity(shannons(&outputs[0]) + shannons(&outputs[1])).build();
    variants.push(("remainder paid out", remote, settlement, with_outputs(&settlement.tx, vec![paid_out]), settlement.purpose));

    variants
        .into_iter()
        .map(|(name, commitment, spend, tx, purpose)| {
            let content = OnchainSigningContent { key_purpose: purpose, transaction: tx.clone() };
            let error = validate_onchain(&content, &spend.authorization, &commitment.record, &spend.chain)
                .expect_err(&format!("{name}: fiber-lsp-sdk's validate accepts it"))
                .to_string();
            assert!(
                error.starts_with("invalid signing content: commitment validation: "),
                "{name}: refused by the harness's chain, not by validate: {error}"
            );
            WatchtowerVariant {
                name: name.to_string(),
                view_for_remote: commitment.for_remote,
                spend: spend.vector.name.clone(),
                request_id: hex_0x(blake2b_256(tx.as_slice())),
                transaction: tx.into(),
                key_purpose: json_purpose(purpose),
                fiber_error: error,
            }
        })
        .collect()
}

fn watchtower_fixture(signers: &Signers, channel: &SigningChannelVector) -> WatchtowerFixture {
    let preimage = blake2b_256(b"watchtower preimage");
    WatchtowerFixture {
        channel: SigningChannelVector { tlcs: watchtower_tlcs(signers, preimage), ..channel.clone() },
        features: lock_layout_features(&channel.lock_layout),
        destination: watchtower_lock("watchtower ckb key"),
        funding_cell_deps: funding_cell_deps(),
        settlement_cell_deps: settlement_cell_deps(),
        preimages: vec![preimage],
    }
}

/// One view: its commitment, the watchtower's chain of the device's spends, and the history where the peer spends first.
struct WatchedView {
    commitment: WatchedCommitment,
    spends: Vec<WatchedSpend>,
    peer_first: WatchedHistory,
}

/// Both views, the peer's commitment first. The peer first times the inbound TLC out and later settles its balance, so the
/// device claims its TLC from a remainder of the peer's and settles last, with no remainder.
fn watched_views(signers: &Signers, fixture: &WatchtowerFixture) -> Vec<WatchedView> {
    let remote = watched_commitment(signers, fixture, true);
    let local = watched_commitment(signers, fixture, false);
    let channel_data = watch_channel(signers, fixture, &remote, &local);
    [remote, local]
        .into_iter()
        .map(|commitment| {
            let label = commitment.label;
            let history = |label: &str, median_time_ms: u64, schedule: &[Side]| {
                watched_history(signers, fixture, &channel_data, &commitment, label, median_time_ms, schedule)
            };
            let spends = history(label, CHAIN_MEDIAN_TIME_MS, &[Side::Device; 3]).spends;
            let peer_first = history(
                &format!("{label}, peer first"),
                PEER_FIRST_MEDIAN_TIME_MS,
                &[Side::Peer, Side::Device, Side::Peer, Side::Device],
            );
            WatchedView { commitment, spends, peer_first }
        })
        .collect()
}

fn watchtower_vectors(signers: &Signers, channel: &SigningChannelVector) -> WatchtowerVectors {
    let fixture = watchtower_fixture(signers, channel);
    let watched = watched_views(signers, &fixture);
    let variants = watchtower_variants(&fixture, &watched);
    WatchtowerVectors {
        funding_cell_deps: fixture.funding_cell_deps.iter().cloned().map(JsonCellDep::from).collect(),
        settlement_cell_deps: fixture.settlement_cell_deps.iter().cloned().map(JsonCellDep::from).collect(),
        destination: fixture.destination.clone().into(),
        max_fee: MAX_FEE_SHANNONS.to_string(),
        tlcs: fixture.channel.tlcs.clone(),
        views: watched
            .into_iter()
            .map(|WatchedView { commitment, spends, peer_first }| WatchtowerViewVector {
                for_remote: commitment.for_remote,
                commitment: BroadcastCommitmentVector {
                    onchain_tx_hash: hex_0x(commitment.broadcast.calc_tx_hash().as_slice()),
                    message: hex_0x(compute_tx_message(&commitment.broadcast)),
                    settlement_witness: hex_0x(&commitment.built.witness),
                    transaction: commitment.broadcast.into(),
                },
                spends: spends.into_iter().chain(peer_first.spends).map(|spend| spend.vector).collect(),
                peer_spends: peer_first.peer_spends,
            })
            .collect(),
        variants,
    }
}

// --- gen-signing-vectors ---

fn signing_vectors() -> SigningVectors {
    let signers = Signers::new(&REMOTE_SIGNER_SEED);
    let channel = signing_channel(&signers);
    use ChannelSigningTransition::*;
    // Six slots, pairwise distinct: no two cases share a device nonce, whatever order a signer serves them in.
    let requests = vec![
        commitment_request(&signers, &channel, "send commitment signed", SendCommitmentSigned, 4, 4),
        commitment_request(&signers, &channel, "complete received commitment", CompleteReceivedCommitment, 3, 2),
        revocation_request(&signers, &channel, "send revoke and ack", SendRevokeAndAck, 3),
        revocation_request(&signers, &channel, "complete received revoke and ack", CompleteReceivedRevokeAndAck, 4),
        closing_request(&signers, &channel, "send closing signed", 5),
        announcement_request(&signers, &channel, "sign channel announcement"),
    ];
    let cases: Vec<SigningCase> = requests.into_iter().map(|request| signing_case(&signers, &channel, request)).collect();
    let variants = signing_variants(&cases[0]);
    assert!(variants.iter().any(|variant| !variant.verdict.accepted), "the variants hold a refusal");
    let watchtower = watchtower_vectors(&signers, &channel);
    let (device, peer) = party_vectors(&signers);

    SigningVectors { fiber_ref: FIBER_REF.to_string(), device, peer, channel, cases, variants, watchtower }
}

/// The channel's two parties as `signing.json` writes them, which the funding lock case of `vectors.json` takes as well.
pub(crate) fn channel_parties() -> (DeviceVector, PeerVector) {
    party_vectors(&Signers::new(&REMOTE_SIGNER_SEED))
}

fn party_vectors(signers: &Signers) -> (DeviceVector, PeerVector) {
    let device = DeviceVector {
        master_seed: hex::encode(MASTER_SEED),
        channel_index: DEVICE_CHANNEL_INDEX,
        funding_pubkey: hex::encode(pubkey_of(&signers.device.funding_key).serialize()),
        tlc_base_pubkey: hex::encode(pubkey_of(&signers.device.tlc_base_key).serialize()),
    };
    let peer = PeerVector {
        seed: hex::encode(REMOTE_SIGNER_SEED),
        funding_pubkey: hex::encode(pubkey_of(&signers.peer.funding_key).serialize()),
        tlc_base_pubkey: hex::encode(pubkey_of(&signers.peer.tlc_base_key).serialize()),
    };
    (device, peer)
}

pub fn gen_signing_vectors(out_path: &str) {
    let json = serde_json::to_string_pretty(&signing_vectors()).unwrap();
    std::fs::write(out_path, format!("{json}\n")).unwrap();
    println!("signing vectors written to {out_path}");
}

// --- verify-signing ---

#[derive(Deserialize)]
struct TsSigningOutput {
    cases: Vec<TsSigningCase>,
    /// One per watchtower spend: the TS writer lives in this repo, so an output without them is refused.
    watchtower: Vec<TsOnchainSignature>,
}

#[derive(Deserialize)]
struct TsSigningCase {
    name: String,
    public_nonce: String,
    partial_signature: String,
}

#[derive(Deserialize)]
struct TsOnchainSignature {
    name: String,
    signature: String,
}

pub fn verify_signing(vectors_path: &str, ts_out_path: &str) {
    let vectors: SigningVectors = serde_json::from_str(&std::fs::read_to_string(vectors_path).unwrap()).unwrap();
    let written: TsSigningOutput = serde_json::from_str(&std::fs::read_to_string(ts_out_path).unwrap()).unwrap();
    match check_signing(&vectors, &written) {
        Ok((verified, onchain)) => {
            println!(
                "OK: {verified} TS partial signatures verified by musig2 0.2.4 and aggregated into valid Schnorr signatures"
            );
            println!("OK: {onchain} TS on-chain signatures recover the keys fiber expects");
        }
        Err(failures) => {
            for failure in &failures {
                eprintln!("FAIL: {failure}");
            }
            std::process::exit(1);
        }
    }
}

/// The partial signatures verified, and the on-chain signatures.
fn check_signing(vectors: &SigningVectors, written: &TsSigningOutput) -> Result<(usize, usize), Vec<String>> {
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    for case in &written.cases {
        if !seen.insert(case.name.as_str()) {
            failures.push(format!("{}: written twice", case.name));
        }
    }
    for vector in &vectors.cases {
        if !seen.contains(vector.name.as_str()) {
            failures.push(format!("{}: the TS side did not write it", vector.name));
        }
    }
    let signers = Signers::new(&hex::decode(&vectors.peer.seed).unwrap());
    let mut verified = 0;
    for case in &written.cases {
        let Some(vector) = vectors.cases.iter().find(|vector| vector.name == case.name) else {
            failures.push(format!("{}: not a case of the vectors", case.name));
            continue;
        };
        match check_case(vectors, &signers, vector, case) {
            Ok(()) => verified += 1,
            Err(failure) => failures.push(format!("{}: {failure}", case.name)),
        }
    }
    let onchain = check_onchain_signatures(vectors, &written.watchtower, &mut failures);
    if failures.is_empty() {
        Ok((verified, onchain))
    } else {
        Err(failures)
    }
}

/// Every spend once and no other, each signature recovering the key the spend's vector names over fiber's message of it.
fn check_onchain_signatures(vectors: &SigningVectors, written: &[TsOnchainSignature], failures: &mut Vec<String>) -> usize {
    let spends: Vec<&WatchtowerSpendVector> = vectors.watchtower.views.iter().flat_map(|view| &view.spends).collect();
    let mut seen = BTreeSet::new();
    for entry in written {
        if !seen.insert(entry.name.as_str()) {
            failures.push(format!("{}: on-chain signature written twice", entry.name));
        }
    }
    for spend in &spends {
        if !seen.contains(spend.name.as_str()) {
            failures.push(format!("{}: the TS side did not write its on-chain signature", spend.name));
        }
    }
    let mut verified = 0;
    for entry in written {
        let Some(spend) = spends.iter().find(|spend| spend.name == entry.name) else {
            failures.push(format!("{}: not a watchtower spend of the vectors", entry.name));
            continue;
        };
        match check_onchain(spend, entry) {
            Ok(()) => verified += 1,
            Err(failure) => failures.push(format!("{}: {failure}", entry.name)),
        }
    }
    verified
}

fn check_onchain(spend: &WatchtowerSpendVector, ts: &TsOnchainSignature) -> Result<(), String> {
    let decode = |text: &str| hex::decode(text.trim_start_matches("0x")).map_err(|error| error.to_string());
    let tx: Transaction = spend.transaction.clone().into();
    let message = compute_tx_message(&tx);
    if hex_0x(message) != spend.message {
        return Err("the vector's message is not fiber's message of its transaction".to_string());
    }
    let expected: [u8; 33] =
        decode(&spend.signer_pubkey)?.try_into().map_err(|_| "a signer pubkey of other than 33 bytes".to_string())?;
    verify_onchain_signature(&expected, message, &decode(&ts.signature)?)
}

/// The TS half of one case: its nonce aggregates, its partial signature verifies, and the two halves sign.
fn check_case(vectors: &SigningVectors, signers: &Signers, vector: &SigningCase, ts: &TsSigningCase) -> Result<(), String> {
    let result: GetChannelSigningStatusResult = serde_json::from_value(vector.result.clone()).map_err(|error| error.to_string())?;
    let ChannelSigningStatus::SignatureRequired { content, session_evidence, .. } = result.status else {
        return Err("the vector is not a SignatureRequired status".to_string());
    };
    let content = musig2_from_rpc(content)?;
    let message = content.content.signing_message();
    let device_pubkey = musig_pubkey(&hex::decode(&vectors.device.funding_pubkey).unwrap());
    let decode = |text: &str| hex::decode(text).map_err(|error| error.to_string());
    let ts_nonce = PubNonce::from_bytes(&decode(&ts.public_nonce)?).map_err(|error| format!("public nonce: {error}"))?;
    let ts_partial =
        PartialSignature::from_slice(&decode(&ts.partial_signature)?).map_err(|error| format!("partial signature: {error}"))?;
    let peer_nonce = PubNonce::from_bytes(&session_evidence.peer_public_nonce).map_err(|error| error.to_string())?;
    if AggNonce::sum([ts_nonce.clone(), peer_nonce]).serialize() != content.agg_nonce.serialize() {
        return Err("the public nonce is not the device's half of the aggregated one".to_string());
    }
    verify_partial(&content.key_agg_ctx, ts_partial, &content.agg_nonce, device_pubkey, &ts_nonce, message)
        .map_err(|error| format!("fiber's musig2 crate refuses the partial signature: {error}"))?;
    let peer_partial: PartialSignature = match session_evidence.peer_partial_signature {
        Some(bytes) => PartialSignature::from_slice(&bytes).map_err(|error| error.to_string())?,
        None => {
            let peer_secnonce = signers.peer_secnonce(content.slot);
            sign_partial(&content.key_agg_ctx, signers.peer_seckey(), peer_secnonce, &content.agg_nonce, message)
                .map_err(|error| error.to_string())?
        }
    };
    let signature: CompactSignature =
        aggregate_partial_signatures(&content.key_agg_ctx, &content.agg_nonce, [ts_partial, peer_partial], message)
            .map_err(|error| format!("the two halves do not aggregate: {error}"))?;
    let aggregated: MusigPublicKey = content.key_agg_ctx.aggregated_pubkey();
    verify_single(aggregated, signature, message).map_err(|error| format!("the aggregated signature does not verify: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASES: usize = 6;
    const SPENDS: usize = 10;

    fn identity(vectors: &SigningVectors) -> TsSigningOutput {
        TsSigningOutput {
            cases: vectors
                .cases
                .iter()
                .map(|case| TsSigningCase {
                    name: case.name.clone(),
                    public_nonce: case.expected.public_nonce.clone(),
                    partial_signature: case.expected.partial_signature.clone(),
                })
                .collect(),
            watchtower: vectors
                .watchtower
                .views
                .iter()
                .flat_map(|view| &view.spends)
                .map(|spend| TsOnchainSignature { name: spend.name.clone(), signature: spend.signature.clone() })
                .collect(),
        }
    }

    fn onchain(written: &mut TsSigningOutput) -> &mut Vec<TsOnchainSignature> {
        &mut written.watchtower
    }

    fn assert_refused(vectors: &SigningVectors, written: TsSigningOutput, reason: &str) {
        let failures = check_signing(vectors, &written).unwrap_err();
        assert_eq!(failures.len(), 1, "{failures:#?}");
        assert!(failures[0].contains(reason), "expected {reason:?} in {failures:#?}");
    }

    #[test]
    fn accepts_every_case_as_the_vectors_write_it() {
        let vectors = signing_vectors();
        assert_eq!(check_signing(&vectors, &identity(&vectors)), Ok((CASES, SPENDS)));
    }

    #[test]
    fn refuses_an_output_without_onchain_signatures() {
        let error = serde_json::from_str::<TsSigningOutput>(r#"{ "cases": [] }"#).err().expect("an output without them reads");
        assert!(error.to_string().contains("missing field `watchtower`"), "{error}");
    }

    #[test]
    fn refuses_a_missing_onchain_signature() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        onchain(&mut written).remove(1);
        assert_refused(
            &vectors,
            written,
            "peer's commitment: outbound TLC by timeout: the TS side did not write its on-chain signature",
        );
    }

    #[test]
    fn refuses_an_onchain_signature_written_twice() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        let again = TsOnchainSignature {
            name: onchain(&mut written)[0].name.clone(),
            signature: onchain(&mut written)[0].signature.clone(),
        };
        onchain(&mut written).push(again);
        assert_refused(&vectors, written, "on-chain signature written twice");
    }

    #[test]
    fn refuses_an_onchain_signature_outside_the_vectors() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        onchain(&mut written)[0].name = "a spend the watchtower never built".to_string();
        let failures = check_signing(&vectors, &written).unwrap_err();
        assert!(failures.iter().any(|failure| failure.contains("not a watchtower spend of the vectors")), "{failures:#?}");
        assert!(failures.iter().any(|failure| failure.contains("did not write its on-chain signature")), "{failures:#?}");
    }

    #[test]
    fn refuses_an_onchain_signature_of_another_spend() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        onchain(&mut written)[0].signature = onchain(&mut written)[1].signature.clone();
        assert_refused(&vectors, written, "recovered public key does not match expected public key");
    }

    #[test]
    fn refuses_an_onchain_signature_with_a_recovery_id_out_of_range() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        let signature = &mut onchain(&mut written)[0].signature;
        signature.replace_range(signature.len() - 2.., "04");
        assert_refused(&vectors, written, "invalid recovery id");
    }

    #[test]
    fn refuses_an_onchain_signature_without_its_recovery_id() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        let signature = &mut onchain(&mut written)[0].signature;
        signature.truncate(signature.len() - 2);
        assert_refused(&vectors, written, "watchtower signature must be 65 bytes");
    }

    #[test]
    fn spends_each_commitment_in_the_watchtowers_order() {
        let vectors = signing_vectors();
        let names: Vec<Vec<&str>> = vectors
            .watchtower
            .views
            .iter()
            .map(|view| view.spends[..3].iter().map(|spend| spend.name.as_str()).collect())
            .collect();
        assert_eq!(
            names,
            [
                [
                    "peer's commitment: inbound TLC by preimage",
                    "peer's commitment: outbound TLC by timeout",
                    "peer's commitment: settlement"
                ],
                [
                    "own commitment: outbound TLC by timeout",
                    "own commitment: inbound TLC by preimage",
                    "own commitment: settlement"
                ],
            ]
        );
        for view in &vectors.watchtower.views {
            for pair in view.spends[..3].windows(2) {
                let next: Transaction = pair[1].transaction.clone().into();
                let input = next.raw().inputs().get(0).unwrap().previous_output();
                assert_eq!(
                    hex_0x(input.tx_hash().as_slice()),
                    pair[0].tx_hash,
                    "{}: not from the remainder before it",
                    pair[1].name
                );
            }
            let first: Transaction = view.spends[0].transaction.clone().into();
            assert_eq!(
                hex_0x(first.raw().inputs().get(0).unwrap().previous_output().tx_hash().as_slice()),
                view.commitment.onchain_tx_hash
            );
        }
    }

    #[test]
    fn spends_each_commitment_after_the_peer_in_the_peer_first_history() {
        let vectors = signing_vectors();
        let parent = |transaction: &JsonTransaction| {
            let tx: Transaction = transaction.clone().into();
            hex_0x(tx.raw().inputs().get(0).unwrap().previous_output().tx_hash().as_slice())
        };
        for view in &vectors.watchtower.views {
            let label = if view.for_remote { "peer's commitment, peer first" } else { "own commitment, peer first" };
            let (peer, device) = (&view.peer_spends, &view.spends[3..]);
            assert_eq!((peer.len(), device.len()), (2, 2));
            assert_eq!(
                [&peer[0].name, &device[0].name, &peer[1].name, &device[1].name],
                [
                    &format!("{label}: peer's outbound TLC by timeout"),
                    &format!("{label}: outbound TLC by timeout"),
                    &format!("{label}: peer's settlement"),
                    &format!("{label}: settlement as the last party"),
                ]
            );
            assert_eq!(parent(&peer[0].transaction), view.commitment.onchain_tx_hash);
            assert_eq!(parent(&device[0].transaction), peer[0].tx_hash);
            assert_eq!(parent(&peer[1].transaction), device[0].tx_hash);
            assert_eq!(parent(&device[1].transaction), peer[1].tx_hash);
            let last: Transaction = device[1].transaction.clone().into();
            assert_eq!(last.raw().outputs().len(), 1, "the last party's settlement leaves no remainder");
        }
    }

    #[test]
    fn watchtower_variants_carry_fibers_verdict() {
        let signers = Signers::new(&REMOTE_SIGNER_SEED);
        let vectors = signing_vectors();
        let fixture = watchtower_fixture(&signers, &vectors.channel);
        let watched = watched_views(&signers, &fixture);
        let verdicts: Vec<(&str, &str)> = vectors
            .watchtower
            .variants
            .iter()
            .map(|variant| {
                let view = watched.iter().find(|view| view.commitment.for_remote == variant.view_for_remote).unwrap();
                let (commitment, spends) = (&view.commitment, &view.spends);
                let spend = spends.iter().find(|spend| spend.vector.name == variant.spend).unwrap();
                let purpose = match variant.key_purpose {
                    JsonOnchainKeyPurpose::Settlement => OnchainKeyPurpose::Settlement,
                    JsonOnchainKeyPurpose::Tlc { commitment_number } => OnchainKeyPurpose::Tlc { commitment_number },
                };
                let content = OnchainSigningContent { key_purpose: purpose, transaction: variant.transaction.clone().into() };
                let error = validate_onchain(&content, &spend.authorization, &commitment.record, &spend.chain).unwrap_err();
                assert_eq!(error.to_string(), variant.fiber_error, "{}", variant.name);
                (
                    variant.name.as_str(),
                    variant.fiber_error.trim_start_matches("invalid signing content: commitment validation: "),
                )
            })
            .collect();
        assert_eq!(
            verdicts,
            [
                ("foreign destination", "unapproved on-chain destination"),
                ("altered remainder", "unapproved on-chain destination"),
                ("foreign TLC", "settlement witness is not committed by live input"),
                ("key of another number", "wrong TLC signing key"),
                ("moved balance", "settlement witness is not committed by live input"),
                ("uncommitted witness", "settlement witness is not committed by live input"),
                ("remainder paid out", "on-chain outputs do not conserve authorized funds and fee"),
            ]
        );
    }

    #[test]
    fn covers_every_transition_fiber_has() {
        let vectors = signing_vectors();
        let transitions: BTreeSet<String> = vectors.cases.iter().map(|case| case.transition.clone()).collect();
        // An exhaustive match: a transition a fiber release adds fails to compile here until a case is written for it.
        let all = [
            ChannelSigningTransition::SendCommitmentSigned,
            ChannelSigningTransition::CompleteReceivedCommitment,
            ChannelSigningTransition::SendRevokeAndAck,
            ChannelSigningTransition::CompleteReceivedRevokeAndAck,
            ChannelSigningTransition::SendClosingSigned,
            ChannelSigningTransition::SignChannelAnnouncement,
        ]
        .map(|transition| match transition {
            ChannelSigningTransition::SendCommitmentSigned
            | ChannelSigningTransition::CompleteReceivedCommitment
            | ChannelSigningTransition::SendRevokeAndAck
            | ChannelSigningTransition::CompleteReceivedRevokeAndAck
            | ChannelSigningTransition::SendClosingSigned
            | ChannelSigningTransition::SignChannelAnnouncement => transition_name(transition),
        });
        assert_eq!(transitions, all.into_iter().collect());
    }

    #[test]
    fn refuses_an_output_without_a_case() {
        let vectors = signing_vectors();
        let failures = check_signing(&vectors, &TsSigningOutput { cases: Vec::new(), ..identity(&vectors) }).unwrap_err();
        assert_eq!(failures.len(), CASES, "{failures:#?}");
        assert!(failures.iter().all(|failure| failure.contains("the TS side did not write it")));
    }

    #[test]
    fn refuses_a_missing_case() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        written.cases.remove(2);
        assert_refused(&vectors, written, "send revoke and ack: the TS side did not write it");
    }

    #[test]
    fn refuses_a_case_written_twice() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        let again = TsSigningCase {
            name: written.cases[0].name.clone(),
            public_nonce: written.cases[0].public_nonce.clone(),
            partial_signature: written.cases[0].partial_signature.clone(),
        };
        written.cases.push(again);
        assert_refused(&vectors, written, "written twice");
    }

    #[test]
    fn refuses_a_case_outside_the_vectors() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        written.cases[0].name = "send commitment signed twice".to_string();
        let failures = check_signing(&vectors, &written).unwrap_err();
        assert!(failures.iter().any(|failure| failure.contains("not a case of the vectors")), "{failures:#?}");
        assert!(failures.iter().any(|failure| failure.contains("send commitment signed: the TS side did not write it")));
    }

    #[test]
    fn refuses_a_partial_signature_of_another_case() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        written.cases[0].partial_signature = vectors.cases[1].expected.partial_signature.clone();
        assert_refused(&vectors, written, "fiber's musig2 crate refuses the partial signature");
    }

    #[test]
    fn refuses_a_public_nonce_the_aggregate_was_not_built_from() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        written.cases[0].public_nonce = vectors.cases[1].expected.public_nonce.clone();
        assert_refused(&vectors, written, "not the device's half of the aggregated one");
    }

    #[test]
    fn refuses_a_partial_signature_out_of_the_scalar_range() {
        let vectors = signing_vectors();
        let mut written = identity(&vectors);
        written.cases[0].partial_signature = "ff".repeat(32);
        assert_refused(&vectors, written, "partial signature");
    }

    #[test]
    fn variants_carry_fibers_verdict() {
        let vectors = signing_vectors();
        for variant in &vectors.variants {
            assert_eq!(verdict_of(&variant.result), variant.verdict, "{}", variant.name);
        }
        let accepted: Vec<&str> =
            vectors.variants.iter().filter(|variant| variant.verdict.accepted).map(|variant| variant.name.as_str()).collect();
        // fiber's codec takes a tweaked or a three-key context as well formed: refusing them is the signer's job.
        assert_eq!(
            accepted,
            [
                "key_agg_ctx with the parity header bit",
                "key_agg_ctx with the tweak header bit and its tweak",
                "key_agg_ctx with a count of 3 and three keys",
            ]
        );
    }
}
