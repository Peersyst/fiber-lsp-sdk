use std::collections::BTreeSet;

use ckb_jsonrpc_types::Transaction as JsonTransaction;
use ckb_types::prelude::*;
use fiber_json_types::{
    ChannelSigningStatus, ChannelSigningTransition, GetChannelSigningStatusResult, Hash256 as JsonHash256,
    SigningSessionEvidence, SigningSettlement, SigningSettlementTlc,
};
use fiber_lsp_sdk::json::{musig2_from_rpc, musig2_to_rpc, settlement_from_rpc};
use fiber_types::{
    settlement_matches_commitment_tx, CommitmentCounter, InMemorySigner, Musig2Context, Musig2SignableContent,
    Musig2SigningContent, NoncePurpose, NonceSlot, SettlementData, TLCId,
};
use musig2::secp256k1::{PublicKey as MusigPublicKey, SecretKey as MusigSecretKey};
use musig2::{
    aggregate_partial_signatures, sign_partial, verify_partial, verify_single, AggNonce, CompactSignature, KeyAggContext,
    PartialSignature, PubNonce, SecNonce, SecNonceBuilder,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    blake160, blake2b_256, build_announcement, build_commitment, build_revocation, build_shutdown, channel_seed, ckb_blake2b,
    derive_public_key, lock_layout_features, nonce_seed, pubkey_of, reserved_capacity, AnnouncementCaseVector,
    CommitmentCaseVector, FiberSigner, OutPointVector, RevocationCaseVector, ScriptVector, ShutdownCaseVector, TlcVector,
    COMMITMENT_LOCK_TESTNET_CODE_HASH, DEFAULT_DELAY_EPOCH, FIBER_REF, MASTER_SEED, REMOTE_SIGNER_SEED,
};

/// An index as the SDK allocates one, the open's time in seconds: well past the small indices.
const DEVICE_CHANNEL_INDEX: u64 = 1_760_572_800;
/// The funding lock's cell deps on the presets, which fiber sizes the commitment fee with (crates/fiber-lib/src/fiber/fee.rs:27-35).
const FUNDING_LOCK_CELL_DEPS_COUNT: u32 = 2;
const DEVICE: &str = "device";
const PEER: &str = "peer";

// --- the vector file ---

#[derive(Serialize, Deserialize)]
struct SigningVectors {
    fiber_ref: String,
    device: DeviceVector,
    peer: PeerVector,
    channel: SigningChannelVector,
    cases: Vec<SigningCase>,
    variants: Vec<SigningVariant>,
}

/// The SDK's master seed and channel index, so a TS signer derives these keys itself.
#[derive(Serialize, Deserialize)]
struct DeviceVector {
    master_seed: String,
    channel_index: u64,
    funding_pubkey: String,
    tlc_base_pubkey: String,
}

/// The node's end of the channel, a fiber `InMemorySigner`.
#[derive(Serialize, Deserialize)]
struct PeerVector {
    seed: String,
    funding_pubkey: String,
    tlc_base_pubkey: String,
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

// --- the two signers ---

struct Signers {
    device: FiberSigner,
    peer: FiberSigner,
    /// The peer's nonces come from fiber's own signer, as a node derives them.
    peer_native: InMemorySigner,
}

impl Signers {
    fn new(peer_seed: &[u8]) -> Self {
        let device = FiberSigner::generate_from_seed(&channel_seed(&MASTER_SEED, DEVICE_CHANNEL_INDEX));
        let peer = FiberSigner::generate_from_seed(peer_seed);
        let peer_native = InMemorySigner::generate_from_seed(peer_seed);
        assert_eq!(
            peer_native.funding_key.pubkey().serialize(),
            pubkey_of(&peer.funding_key).serialize(),
            "the harness's port and fiber's signer derive one peer"
        );
        Signers { device, peer, peer_native }
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

fn signing_case(signers: &Signers, channel: &SigningChannelVector, request: Request) -> SigningCase {
    let device_first = request.order.device_first(signers);
    let (device_pubkey, peer_pubkey) = (signers.device_pubkey(), signers.peer_pubkey());
    let keys = if device_first { vec![device_pubkey, peer_pubkey] } else { vec![peer_pubkey, device_pubkey] };
    let key_order = if device_first { [DEVICE, PEER] } else { [PEER, DEVICE] }.map(str::to_string);
    let key_agg_ctx = KeyAggContext::new(keys).unwrap();

    let device_secnonce = signers.device_secnonce(request.slot.commitment_number, nonce_context(request.slot.purpose));
    let peer_secnonce = signers.peer_secnonce(request.slot);
    let (device_nonce, peer_nonce) = (device_secnonce.public_nonce(), peer_secnonce.public_nonce());
    let agg_nonce = AggNonce::sum(if device_first {
        [device_nonce.clone(), peer_nonce.clone()]
    } else {
        [peer_nonce.clone(), device_nonce.clone()]
    });

    let content = Musig2SigningContent {
        slot: request.slot,
        commitment_counter: request.counter,
        key_agg_ctx: key_agg_ctx.clone(),
        agg_nonce: agg_nonce.clone(),
        content: request.signable,
    };
    let message = content.content.signing_message();
    assert_eq!(message, request.digest, "{}: fiber's signing_message is not the harness's digest", request.name);

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
    assert_aggregated_key(request.name, &content.content, &aggregated);

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

/// id, direction, hash algorithm, amount, payment hash label, expiry, and created_at as (local, remote).
type TlcFixture = (u64, &'static str, &'static str, &'static str, &'static str, &'static str, (u64, u64));

fn signing_channel(signers: &Signers) -> SigningChannelVector {
    let features = lock_layout_features("full_payment_hash");
    let close_script = |label: &str| ScriptVector {
        code_hash: hex::encode(blake2b_256(format!("{label} lock").as_bytes())),
        hash_type: "type".to_string(),
        args: hex::encode(blake160(label.as_bytes())),
    };
    let local_close_script = close_script("device close");
    let remote_close_script = close_script("peer close");
    let peer_tlc_base = pubkey_of(&signers.peer.tlc_base_key);
    let peer_tlc_key = |number: u64| derive_public_key(&peer_tlc_base, &signers.peer.get_commitment_point(number));
    // created_at as fiber keeps it, (local, remote): the device's key at the remote number, the peer's at the local one.
    let tlc = |(id, direction, hash_algorithm, amount, label, expiry_ms, created_at): TlcFixture| TlcVector {
        id,
        direction: direction.to_string(),
        hash_algorithm: hash_algorithm.to_string(),
        amount: amount.to_string(),
        payment_hash: hex::encode(blake2b_256(label.as_bytes())),
        expiry_ms: expiry_ms.to_string(),
        local_key_commitment_number: created_at.1,
        remote_tlc_pubkey: hex::encode(peer_tlc_key(created_at.0).serialize()),
    };
    SigningChannelVector {
        channel_id: format!("0x{}", hex::encode(blake2b_256(b"signing channel"))),
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
        // The reserve the peer declared at the open; the device pins it rather than computing it.
        remote_reserved: "6300000000".to_string(),
        local_close_script,
        remote_close_script,
        local_shutdown_fee_rate: "1000".to_string(),
        remote_shutdown_fee_rate: "1200".to_string(),
        tlcs: [
            (0, "offered", "ckb-hash", "1500000000", "signing payment one", "1760576400000", (1, 1)),
            (0, "received", "sha256", "2250000000", "signing payment two", "1760580000000", (2, 2)),
            (1, "offered", "sha256", "750000000", "signing payment three", "1760583600000", (3, 2)),
        ]
        .into_iter()
        .map(tlc)
        .collect(),
    }
}

/// fiber's `build_settlement_data` with every TLC pending (crates/fiber-lib/src/fiber/channel.rs:11409-11530).
fn pending_amount(tlcs: &[TlcVector], direction: &str) -> u128 {
    tlcs.iter().filter(|tlc| tlc.direction == direction).map(|tlc| tlc.amount.parse::<u128>().unwrap()).sum()
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
    let to_local: u128 = channel.to_local.parse().unwrap();
    let to_remote: u128 = channel.to_remote.parse().unwrap();
    let case = CommitmentCaseVector {
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
    };
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

    SigningVectors {
        fiber_ref: FIBER_REF.to_string(),
        device: DeviceVector {
            master_seed: hex::encode(MASTER_SEED),
            channel_index: DEVICE_CHANNEL_INDEX,
            funding_pubkey: hex::encode(pubkey_of(&signers.device.funding_key).serialize()),
            tlc_base_pubkey: hex::encode(pubkey_of(&signers.device.tlc_base_key).serialize()),
        },
        peer: PeerVector {
            seed: hex::encode(REMOTE_SIGNER_SEED),
            funding_pubkey: hex::encode(pubkey_of(&signers.peer.funding_key).serialize()),
            tlc_base_pubkey: hex::encode(pubkey_of(&signers.peer.tlc_base_key).serialize()),
        },
        channel,
        cases,
        variants,
    }
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
}

#[derive(Deserialize)]
struct TsSigningCase {
    name: String,
    public_nonce: String,
    partial_signature: String,
}

pub fn verify_signing(vectors_path: &str, ts_out_path: &str) {
    let vectors: SigningVectors = serde_json::from_str(&std::fs::read_to_string(vectors_path).unwrap()).unwrap();
    let written: TsSigningOutput = serde_json::from_str(&std::fs::read_to_string(ts_out_path).unwrap()).unwrap();
    match check_signing(&vectors, &written) {
        Ok(verified) => println!(
            "OK: {verified} TS partial signatures verified by musig2 0.2.4 and aggregated into valid Schnorr signatures"
        ),
        Err(failures) => {
            for failure in &failures {
                eprintln!("FAIL: {failure}");
            }
            std::process::exit(1);
        }
    }
}

fn check_signing(vectors: &SigningVectors, written: &TsSigningOutput) -> Result<usize, Vec<String>> {
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
    if failures.is_empty() {
        Ok(verified)
    } else {
        Err(failures)
    }
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
        }
    }

    fn assert_refused(vectors: &SigningVectors, written: TsSigningOutput, reason: &str) {
        let failures = check_signing(vectors, &written).unwrap_err();
        assert_eq!(failures.len(), 1, "{failures:#?}");
        assert!(failures[0].contains(reason), "expected {reason:?} in {failures:#?}");
    }

    #[test]
    fn accepts_every_case_as_the_vectors_write_it() {
        let vectors = signing_vectors();
        assert_eq!(check_signing(&vectors, &identity(&vectors)), Ok(CASES));
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
        let failures = check_signing(&vectors, &TsSigningOutput { cases: Vec::new() }).unwrap_err();
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
