//! Cross-implementation vector generator and verifier for the SDK's derivation
//! scheme and musig2 signing; see `interop/README.md` for what the two halves of
//! the vectors are and how to regenerate them.
//!
//! Subcommands:
//!   gen-vectors <out.json>
//!   verify-ts <vectors.json> <ts-out.json>

use musig2::{
    aggregate_partial_signatures, sign_partial, verify_partial, AggNonce, CompactSignature,
    KeyAggContext, PartialSignature, PubNonce, SecNonce, SecNonceBuilder,
};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Sha512;

// --- CKB hashing ---

/// CKB-style blake2b-256 over the concatenated chunks (personalization
/// "ckb-default-hash", which `ckb_hash` applies).
fn ckb_blake2b(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = ckb_hash::new_blake2b();
    for chunk in chunks {
        hasher.update(chunk);
    }
    let mut result = [0u8; 32];
    hasher.finalize(&mut result);
    result
}

fn blake2b_256(data: &[u8]) -> [u8; 32] {
    ckb_blake2b(&[data])
}

/// fiber `blake2b_hash_with_salt`: the salt is hashed BEFORE the data.
fn blake2b_hash_with_salt(data: &[u8], salt: &[u8]) -> [u8; 32] {
    ckb_blake2b(&[salt, data])
}

// --- fiber scheme (ported from crates/fiber-types/src/channel.rs) ---

fn pubkey_of(sk: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, sk)
}

/// fiber `Privkey::tweak` — (scalar + sk) mod n.
fn tweak(sk: &SecretKey, scalar: [u8; 32]) -> SecretKey {
    let scalar = Scalar::from_be_bytes(scalar).expect("scalar in range");
    sk.add_tweak(&scalar).expect("valid tweak")
}

fn get_tweak_by_commitment_point(commitment_point: &PublicKey) -> [u8; 32] {
    blake2b_256(&commitment_point.serialize())
}

fn derive_private_key(secret: &SecretKey, commitment_point: &PublicKey) -> SecretKey {
    tweak(secret, get_tweak_by_commitment_point(commitment_point))
}

fn get_commitment_secret(commitment_seed: &[u8; 32], commitment_number: u64) -> [u8; 32] {
    let mut res: [u8; 32] = *commitment_seed;
    for i in 0..48 {
        let bitpos = 47 - i;
        if commitment_number & (1 << bitpos) == (1 << bitpos) {
            res[bitpos / 8] ^= 1 << (bitpos & 7);
            res = blake2b_256(&res);
        }
    }
    res
}

fn get_commitment_point(commitment_seed: &[u8; 32], commitment_number: u64) -> PublicKey {
    let sk = SecretKey::from_slice(&get_commitment_secret(commitment_seed, commitment_number))
        .expect("valid commitment secret");
    pubkey_of(&sk)
}

struct FiberSigner {
    funding_key: SecretKey,
    tlc_base_key: SecretKey,
    musig2_base_nonce: SecretKey,
    commitment_seed: [u8; 32],
}

impl FiberSigner {
    /// fiber `InMemorySigner::generate_from_seed`, including the upstream
    /// "musig nocne" spelling, which is part of the derivation.
    fn generate_from_seed(params: &[u8]) -> Self {
        let seed = blake2b_256(params);
        let commitment_seed = ckb_blake2b(&[&seed, b"commitment seed"]);

        let key_derive = |seed: &[u8], info: &[u8]| {
            SecretKey::from_slice(&blake2b_hash_with_salt(seed, info)).expect("valid key")
        };

        let funding_key = key_derive(&seed, b"funding key");
        let tlc_base_key = key_derive(&funding_key.secret_bytes(), b"HTLC base key");
        let musig2_base_nonce = key_derive(&tlc_base_key.secret_bytes(), b"musig nocne");

        FiberSigner {
            funding_key,
            tlc_base_key,
            musig2_base_nonce,
            commitment_seed,
        }
    }

    fn get_commitment_point(&self, n: u64) -> PublicKey {
        get_commitment_point(&self.commitment_seed, n)
    }

    fn derive_tlc_key(&self, n: u64) -> SecretKey {
        derive_private_key(&self.tlc_base_key, &self.get_commitment_point(n))
    }

    /// The fiber half of the nonce derivation: the per-commitment secret the SDK
    /// then binds a context string to in `nonce_seed` (below).
    fn musig2_nonce_seckey(&self, n: u64) -> SecretKey {
        derive_private_key(&self.musig2_base_nonce, &self.get_commitment_point(n))
    }
}

// --- SDK-owned derivations (not part of fiber's scheme) ---

/// BIP32 master node from a seed: HMAC-SHA512 under the fixed "Bitcoin seed" key,
/// left half the key and right half the chain code.
fn bip32_master(seed: &[u8]) -> (SecretKey, [u8; 32]) {
    let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").expect("hmac takes any key length");
    mac.update(seed);
    let i = mac.finalize().into_bytes();
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&i[32..]);
    (
        SecretKey::from_slice(&i[..32]).expect("master key in range"),
        chain_code,
    )
}

/// BIP32 hardened child. The parent's PRIVATE key goes into the hash, which is what
/// makes the branch unwalkable from a public key alone. BIP32's "retry with the next
/// index" rule for an invalid child is left out on both sides on purpose: a 2^-127
/// event should fail loudly here and in `@scure/bip32`, not diverge in silence.
fn bip32_derive_hardened(parent: &(SecretKey, [u8; 32]), index: u32) -> (SecretKey, [u8; 32]) {
    let (parent_key, parent_chain_code) = parent;
    let hardened = index.checked_add(0x8000_0000).expect("account index fits a hardened level");
    let mut mac = Hmac::<Sha512>::new_from_slice(parent_chain_code).expect("hmac takes any key length");
    mac.update(&[0u8]);
    mac.update(&parent_key.secret_bytes());
    mac.update(&hardened.to_be_bytes());
    let i = mac.finalize().into_bytes();
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&i[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&i[32..]);
    (tweak(parent_key, scalar), chain_code)
}

/// The master seed the SDK is constructed with: the private key at the hardened
/// path m/1017'/309'/account'.
fn master_seed(bip39_seed: &[u8; 64], account_index: u32) -> [u8; 32] {
    let purpose = bip32_derive_hardened(&bip32_master(bip39_seed), MASTER_SEED_PURPOSE);
    let coin_type = bip32_derive_hardened(&purpose, MASTER_SEED_COIN_TYPE);
    bip32_derive_hardened(&coin_type, account_index).0.secret_bytes()
}

fn master_seed_path(account_index: u32) -> String {
    format!("m/{MASTER_SEED_PURPOSE}'/{MASTER_SEED_COIN_TYPE}'/{account_index}'")
}

/// Wallet identity key, used to answer the signer-session challenge. It identifies
/// the master seed, not the handset.
fn wallet_identity_key(master_seed: &[u8; 32]) -> [u8; 32] {
    ckb_blake2b(&[master_seed, b"wallet identity"])
}

/// Per-channel seed. Deterministic on purpose: it replaces fiber's node-side
/// random channel seed so every channel is recoverable from the master seed.
fn channel_seed(master_seed: &[u8; 32], channel_index: u64) -> [u8; 32] {
    ckb_blake2b(&[
        master_seed,
        format!("fiber channel {channel_index}").as_bytes(),
    ])
}

/// Deterministic musig2 nonce seed for one (commitment number, context) slot.
fn nonce_seed(signer: &FiberSigner, commitment_number: u64, context: &str) -> [u8; 32] {
    let seckey = signer.musig2_nonce_seckey(commitment_number);
    ckb_blake2b(&[&seckey.secret_bytes(), context.as_bytes()])
}

// --- digest reconstruction (ported from crates/fiber-lib/src/fiber/channel.rs and fee.rs) ---

use ckb_types::packed::{
    Byte, Bytes as PackedBytes, BytesVec, CellDep, CellDepVec, CellInput, CellInputVec, CellOutput, CellOutputVec,
    OutPoint as PackedOutPoint, RawTransaction, Script as PackedScript, ScriptOpt, Transaction,
};
use ckb_types::prelude::*;

const FUNDING_CELL_WITNESS_LEN: usize = 112;
const COMMITMENT_LOCK_ARGS_PLACEHOLDER_LEN: usize = 57;
const SINCE_RELATIVE_EPOCH_FLAGS: u64 = 0xA000_0000_0000_0000;
const SINCE_ABSOLUTE_TIMESTAMP_FLAG: u64 = 0x4000_0000_0000_0000;
const FEE_RATE_WEIGHT_SCALE: u128 = 1000;

fn blake160(data: &[u8]) -> [u8; 20] {
    blake2b_256(data)[0..20].try_into().unwrap()
}

/// fiber `derive_public_key` / `try_derive_tlc_pubkey`: base + blake2b(point)*G.
fn derive_public_key(base: &PublicKey, commitment_point: &PublicKey) -> PublicKey {
    let secp = Secp256k1::new();
    let tweak = Scalar::from_be_bytes(get_tweak_by_commitment_point(commitment_point)).unwrap();
    base.add_exp_tweak(&secp, &tweak).unwrap()
}

/// The x-only aggregate of the two keys in the exact order given, as fiber bakes it into lock args.
fn xonly_agg(first: &PublicKey, second: &PublicKey) -> [u8; 32] {
    let keys = vec![
        musig2::secp256k1::PublicKey::from_slice(&first.serialize()).unwrap(),
        musig2::secp256k1::PublicKey::from_slice(&second.serialize()).unwrap(),
    ];
    let ctx = KeyAggContext::new(keys).unwrap();
    let agg: musig2::secp256k1::PublicKey = ctx.aggregated_pubkey();
    agg.x_only_public_key().0.serialize()
}

#[derive(Serialize, Deserialize, Clone)]
struct ScriptVector {
    code_hash: String,
    hash_type: String,
    args: String,
}

fn packed_script(script: &ScriptVector) -> PackedScript {
    let code_hash: [u8; 32] = hex::decode(&script.code_hash).unwrap().try_into().unwrap();
    let hash_type: u8 = match script.hash_type.as_str() {
        "data" => 0,
        "type" => 1,
        "data1" => 2,
        "data2" => 4,
        other => panic!("unknown hash_type {other}"),
    };
    PackedScript::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(Byte::new(hash_type))
        .args(hex::decode(&script.args).unwrap().pack())
        .build()
}

fn packed_script_opt(script: &Option<ScriptVector>) -> ScriptOpt {
    ScriptOpt::new_builder().set(script.as_ref().map(packed_script)).build()
}

#[derive(Serialize, Deserialize, Clone)]
struct OutPointVector {
    tx_hash: String,
    index: u32,
}

fn packed_out_point(out_point: &OutPointVector) -> PackedOutPoint {
    let tx_hash: [u8; 32] = hex::decode(&out_point.tx_hash).unwrap().try_into().unwrap();
    let index: ckb_types::packed::Uint32 = out_point.index.pack();
    PackedOutPoint::new_builder().tx_hash(tx_hash.pack()).index(index).build()
}

#[derive(Serialize, Deserialize, Clone)]
struct TlcVector {
    id: u64,
    /// Direction from the local (device) side, before any for_remote flip.
    direction: String,
    hash_algorithm: String,
    amount: String,
    payment_hash: String,
    expiry_ms: String,
    created_at_remote_commitment_number: u64,
    remote_commitment_point: String,
}

/// fiber `settlement_tlc_to_witness`: one 85-byte TLC record.
fn settlement_tlc_witness(local: &FiberSigner, remote_tlc_base: &PublicKey, tlc: &TlcVector, for_remote: bool) -> Vec<u8> {
    let offered = match tlc.direction.as_str() {
        "offered" => true,
        "received" => false,
        other => panic!("unknown direction {other}"),
    };
    // for_remote=false flips every TLC id (fiber's flip_mut), which only shows up in the flag bit.
    let effective_offered = if for_remote { offered } else { !offered };
    let algorithm: u8 = match tlc.hash_algorithm.as_str() {
        "ckb-hash" => 0,
        "sha256" => 1,
        other => panic!("unknown hash_algorithm {other}"),
    };
    let flag = (algorithm << 1) | u8::from(!effective_offered);
    let amount: u128 = tlc.amount.parse().unwrap();
    let point = PublicKey::from_slice(&hex::decode(&tlc.remote_commitment_point).unwrap()).unwrap();
    let local_key_hash = blake160(&pubkey_of(&local.derive_tlc_key(tlc.created_at_remote_commitment_number)).serialize());
    let remote_key_hash = blake160(&derive_public_key(remote_tlc_base, &point).serialize());
    let since = SINCE_ABSOLUTE_TIMESTAMP_FLAG | (tlc.expiry_ms.parse::<u64>().unwrap() / 1000);

    let mut witness = vec![flag];
    witness.extend(amount.to_le_bytes());
    witness.extend(&hex::decode(&tlc.payment_hash).unwrap()[0..20]);
    if for_remote {
        witness.extend(remote_key_hash);
        witness.extend(local_key_hash);
    } else {
        witness.extend(local_key_hash);
        witness.extend(remote_key_hash);
    }
    witness.extend(since.to_le_bytes());
    witness
}

/// fiber `get_active_tlcs` ordering: two direction groups, each ascending by id.
fn ordered_tlcs<'a>(tlcs: &'a [TlcVector], for_remote: bool) -> Vec<&'a TlcVector> {
    let first_direction = if for_remote { "received" } else { "offered" };
    let mut first: Vec<&TlcVector> = tlcs.iter().filter(|tlc| tlc.direction == first_direction).collect();
    let mut second: Vec<&TlcVector> = tlcs.iter().filter(|tlc| tlc.direction != first_direction).collect();
    first.sort_by_key(|tlc| tlc.id);
    second.sort_by_key(|tlc| tlc.id);
    first.into_iter().chain(second).collect()
}

/// fiber `settlement_data_to_witness`.
fn settlement_witness(
    local: &FiberSigner,
    remote_tlc_base: &PublicKey,
    for_remote: bool,
    local_amount: u128,
    remote_amount: u128,
    tlcs: &[TlcVector],
) -> Vec<u8> {
    let mut witness = vec![u8::try_from(tlcs.len()).unwrap()];
    for tlc in ordered_tlcs(tlcs, for_remote) {
        witness.extend(settlement_tlc_witness(local, remote_tlc_base, tlc, for_remote));
    }
    let local_hash = blake160(&pubkey_of(&local.tlc_base_key).serialize());
    let remote_hash = blake160(&remote_tlc_base.serialize());
    if for_remote {
        witness.extend(remote_hash);
        witness.extend(remote_amount.to_le_bytes());
        witness.extend(local_hash);
        witness.extend(local_amount.to_le_bytes());
    } else {
        witness.extend(local_hash);
        witness.extend(local_amount.to_le_bytes());
        witness.extend(remote_hash);
        witness.extend(remote_amount.to_le_bytes());
    }
    witness
}

/// fiber `commitment_tx_size` / `shutdown_tx_size`: the mock tx both fee calculations measure.
fn mock_tx_size(cell_deps_count: usize, outputs: Vec<CellOutput>, outputs_data: Vec<PackedBytes>) -> u64 {
    let raw = RawTransaction::new_builder()
        .cell_deps(CellDepVec::new_builder().set(vec![CellDep::default(); cell_deps_count]).build())
        .inputs(CellInputVec::new_builder().set(vec![CellInput::default()]).build())
        .outputs(CellOutputVec::new_builder().set(outputs).build())
        .outputs_data(BytesVec::new_builder().set(outputs_data).build())
        .build();
    let witnesses = BytesVec::new_builder().set(vec![vec![0u8; FUNDING_CELL_WITNESS_LEN].pack()]).build();
    let tx = Transaction::new_builder().raw(raw).witnesses(witnesses).build();
    // `serialized_size_in_block`: the molecule length plus the 4-byte offset a block entry costs.
    (tx.as_slice().len() + 4) as u64
}

fn commitment_tx_size(cell_deps_count: usize, udt_type_script: &Option<ScriptVector>, commitment_lock: &ScriptVector) -> u64 {
    let mock_lock = ScriptVector {
        args: hex::encode([0u8; COMMITMENT_LOCK_ARGS_PLACEHOLDER_LEN]),
        ..commitment_lock.clone()
    };
    let output = CellOutput::new_builder()
        .lock(packed_script(&mock_lock))
        .type_(packed_script_opt(udt_type_script))
        .build();
    let data = if udt_type_script.is_some() { vec![0u8; 16] } else { Vec::new() };
    mock_tx_size(cell_deps_count, vec![output], vec![data.pack()])
}

fn shutdown_tx_size(cell_deps_count: usize, udt_type_script: &Option<ScriptVector>, close_scripts: [&ScriptVector; 2]) -> u64 {
    let outputs = close_scripts
        .iter()
        .map(|script| {
            CellOutput::new_builder()
                .lock(packed_script(script))
                .type_(packed_script_opt(udt_type_script))
                .build()
        })
        .collect();
    let data = if udt_type_script.is_some() { vec![0u8; 16] } else { Vec::new() };
    mock_tx_size(cell_deps_count, outputs, vec![data.pack(), data.pack()])
}

/// fiber `checked_fee_from_rate`: truncating division by the 1000-byte weight scale.
fn fee_from_rate(fee_rate: u64, tx_size: u64) -> u64 {
    u64::try_from(u128::from(fee_rate) * u128::from(tx_size) / FEE_RATE_WEIGHT_SCALE).unwrap()
}

/// fiber `compute_tx_message`: the raw transaction hashed with its cell deps emptied.
fn compute_raw_tx_message(raw: &RawTransaction) -> [u8; 32] {
    let cleared = raw.clone().as_builder().cell_deps(CellDepVec::default()).build();
    blake2b_256(cleared.as_slice())
}

fn commitment_lock_args(xonly: &[u8; 32], delay_epoch: u64, commitment_number: u64, witness: &[u8]) -> Vec<u8> {
    let mut args = Vec::with_capacity(COMMITMENT_LOCK_ARGS_PLACEHOLDER_LEN);
    args.extend(&blake2b_256(xonly)[0..20]);
    args.extend((SINCE_RELATIVE_EPOCH_FLAGS | delay_epoch).to_le_bytes());
    args.extend(commitment_number.to_be_bytes());
    args.extend(blake160(witness));
    args.push(0x00);
    args
}

// --- Vector file shape ---

#[derive(Serialize, Deserialize)]
struct Vectors {
    scheme_version: u32,
    fiber_ref: String,
    hashes: Vec<HashVector>,
    fiber_scheme: FiberSchemeVectors,
    sdk_scheme: SdkSchemeVectors,
    musig: MusigVector,
    digest: DigestVectors,
}

#[derive(Serialize, Deserialize)]
struct DigestVectors {
    /// The commitment lock template of every case; the SDK's testnet preset, so the vectors also pin that constant.
    commitment_lock: ScriptVector,
    remote: RemoteSignerVector,
    commitment_cases: Vec<CommitmentCaseVector>,
    shutdown_cases: Vec<ShutdownCaseVector>,
    revocation_cases: Vec<RevocationCaseVector>,
    announcement_cases: Vec<AnnouncementCaseVector>,
}

#[derive(Serialize, Deserialize)]
struct RemoteSignerVector {
    seed: String,
    funding_pubkey: String,
    tlc_base_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct CommitmentCaseVector {
    name: String,
    for_remote: bool,
    funding_out_point: OutPointVector,
    commitment_number: u64,
    delay_epoch: String,
    fee_rate: String,
    cell_deps_count: u32,
    udt_type_script: Option<ScriptVector>,
    to_local: String,
    to_remote: String,
    settlement_local: String,
    settlement_remote: String,
    local_reserved: String,
    remote_reserved: String,
    tlcs: Vec<TlcVector>,
    settlement_witness: String,
    lock_args: String,
    tx_size: u64,
    fee: String,
    digest: String,
}

#[derive(Serialize, Deserialize)]
struct ShutdownCaseVector {
    name: String,
    funding_out_point: OutPointVector,
    local_close_script: ScriptVector,
    remote_close_script: ScriptVector,
    local_fee_rate: String,
    remote_fee_rate: String,
    cell_deps_count: u32,
    udt_type_script: Option<ScriptVector>,
    to_local: String,
    to_remote: String,
    local_reserved: String,
    remote_reserved: String,
    tx_size: u64,
    local_fee: String,
    remote_fee: String,
    digest: String,
}

#[derive(Serialize, Deserialize)]
struct RevocationCaseVector {
    name: String,
    for_remote: bool,
    revoked_commitment_number: u64,
    payout_script: ScriptVector,
    delay_epoch: String,
    fee_rate: String,
    cell_deps_count: u32,
    udt_type_script: Option<ScriptVector>,
    to_local: String,
    to_remote: String,
    local_reserved: String,
    remote_reserved: String,
    fee: String,
    digest: String,
}

#[derive(Serialize, Deserialize)]
struct AnnouncementCaseVector {
    name: String,
    chain_hash: String,
    funding_out_point: OutPointVector,
    /// Deliberately unsorted: both implementations must sort by node pubkey themselves.
    node_ids: [String; 2],
    capacity: String,
    udt_type_script: Option<ScriptVector>,
    digest: String,
}

#[derive(Serialize, Deserialize)]
struct HashVector {
    label: String,
    chunks: Vec<String>,
    digest: String,
}

#[derive(Serialize, Deserialize)]
struct FiberSchemeVectors {
    channel_seed: String,
    channel_keys: ChannelKeysVector,
    commitments: Vec<CommitmentVector>,
}

#[derive(Serialize, Deserialize)]
struct ChannelKeysVector {
    funding_key: String,
    tlc_base_key: String,
    musig2_base_nonce: String,
    commitment_seed: String,
    funding_pubkey: String,
    tlc_base_pubkey: String,
}

#[derive(Serialize, Deserialize)]
struct CommitmentVector {
    n: u64,
    secret: String,
    point: String,
    tlc_privkey: String,
    tlc_pubkey: String,
    musig2_nonce_seckey: String,
}

#[derive(Serialize, Deserialize)]
struct SdkSchemeVectors {
    bip39_seed: String,
    master_seeds: Vec<MasterSeedVector>,
    master_seed: String,
    wallet_identity_key: String,
    channel_seeds: Vec<ChannelSeedVector>,
    channel: SdkChannelVector,
}

#[derive(Serialize, Deserialize)]
struct MasterSeedVector {
    account_index: u32,
    path: String,
    master_seed: String,
}

#[derive(Serialize, Deserialize)]
struct ChannelSeedVector {
    channel_index: u64,
    seed: String,
}

#[derive(Serialize, Deserialize)]
struct SdkChannelVector {
    channel_index: u64,
    seed: String,
    channel_keys: ChannelKeysVector,
    nonce_seeds: Vec<NonceSeedVector>,
}

#[derive(Serialize, Deserialize)]
struct NonceSeedVector {
    commitment_number: u64,
    context: String,
    seed: String,
}

#[derive(Serialize, Deserialize)]
struct MusigVector {
    remote_seckey: String,
    remote_pubkey: String,
    remote_pubnonce: String,
    message: String,
}

#[derive(Deserialize)]
struct TsOutput {
    local_pubnonce: String,
    partial_signature: String,
}

// --- Fixed public test inputs (test keys only) ---

/// Channel seed used for the standalone fiber-scheme half.
const CHANNEL_SEED_PARAMS: [u8; 32] = [0x42; 32];
/// Master seed used for the SDK-owned half.
const MASTER_SEED: [u8; 32] = [0x24; 32];
/// BIP39 seed used for the master seed path; unrelated to MASTER_SEED, which the
/// rest of the SDK half starts from directly.
const BIP39_SEED: [u8; 64] = [0x37; 64];
const REMOTE_SEED: [u8; 32] = [0x99; 32];

const MASTER_SEED_PURPOSE: u32 = 1017;
const MASTER_SEED_COIN_TYPE: u32 = 309;

/// The last index is the highest a hardened level can hold (2^31 - 1).
const ACCOUNT_INDICES: [u32; 3] = [0, 1, 2147483647];

/// Includes the boundaries of the 48-bit commitment chain: a lone top bit and
/// all 48 bits set (the maximum a commitment number may reach).
const COMMITMENT_NUMBERS: [u64; 9] = [
    0,
    1,
    2,
    5,
    1000,
    65535,
    4294967295,
    140737488355328,
    281474976710655,
];

/// The last index is JS's `Number.MAX_SAFE_INTEGER`: the channel index is
/// formatted into a string, so both sides must agree at that boundary.
const CHANNEL_INDICES: [u64; 6] = [0, 1, 2, 7, 1000, 9007199254740991];

const NONCE_CONTEXTS: [&str; 4] = ["COMMITMENT", "REVOKE", "CLOSE", "ANNOUNCEMENT"];

const SCHEME_VERSION: u32 = 1;
const FIBER_REF: &str = "b71a61c3";

/// Peer-side channel signer for the digest cases: its public halves are the "remote" inputs the node would attach.
const REMOTE_SIGNER_SEED: [u8; 32] = [0x77; 32];

/// The SDK's testnet commitment lock preset; keeping it in the vectors pins the TS constant too.
const COMMITMENT_LOCK_TESTNET_CODE_HASH: &str = "740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8";

/// Default commitment delay: EpochNumberWithFraction(number 1, index 0, length 1) as a full value.
const DEFAULT_DELAY_EPOCH: u64 = (1 << 40) | 1;

fn remote_secnonce() -> SecNonce {
    SecNonceBuilder::new(REMOTE_SEED).build()
}

fn build_commitment_case(
    local: &FiberSigner,
    remote: &FiberSigner,
    commitment_lock: &ScriptVector,
    mut case: CommitmentCaseVector,
) -> CommitmentCaseVector {
    let local_pub = pubkey_of(&local.funding_key);
    let remote_pub = pubkey_of(&remote.funding_key);
    let xonly = if case.for_remote {
        xonly_agg(&local_pub, &remote_pub)
    } else {
        xonly_agg(&remote_pub, &local_pub)
    };

    let is_udt = case.udt_type_script.is_some();
    let to_local: u128 = case.to_local.parse().unwrap();
    let to_remote: u128 = case.to_remote.parse().unwrap();
    let settlement_local: u128 = case.settlement_local.parse().unwrap();
    let settlement_remote: u128 = case.settlement_remote.parse().unwrap();
    let local_reserved: u64 = case.local_reserved.parse().unwrap();
    let remote_reserved: u64 = case.remote_reserved.parse().unwrap();

    let witness_local = if is_udt { settlement_local } else { settlement_local + u128::from(local_reserved) };
    let witness_remote = if is_udt { settlement_remote } else { settlement_remote + u128::from(remote_reserved) };
    let witness = settlement_witness(
        local,
        &pubkey_of(&remote.tlc_base_key),
        case.for_remote,
        witness_local,
        witness_remote,
        &case.tlcs,
    );
    let args = commitment_lock_args(&xonly, case.delay_epoch.parse().unwrap(), case.commitment_number, &witness);

    let tx_size = commitment_tx_size(case.cell_deps_count as usize, &case.udt_type_script, commitment_lock);
    let fee = fee_from_rate(case.fee_rate.parse().unwrap(), tx_size);
    let liquid = to_local + to_remote;
    let total_reserved = local_reserved + remote_reserved;
    let capacity = if is_udt {
        total_reserved - fee
    } else {
        u64::try_from(liquid + u128::from(total_reserved)).unwrap() - fee
    };
    let lock = packed_script(&ScriptVector { args: hex::encode(&args), ..commitment_lock.clone() });
    let output = CellOutput::new_builder()
        .capacity(ckb_types::prelude::Pack::<ckb_types::packed::Uint64>::pack(&capacity))
        .lock(lock)
        .type_(packed_script_opt(&case.udt_type_script))
        .build();
    let output_data: PackedBytes = if is_udt { liquid.to_le_bytes().to_vec().pack() } else { Vec::<u8>::new().pack() };
    let input = CellInput::new_builder().previous_output(packed_out_point(&case.funding_out_point)).build();
    let raw = RawTransaction::new_builder()
        .inputs(CellInputVec::new_builder().set(vec![input]).build())
        .outputs(CellOutputVec::new_builder().set(vec![output]).build())
        .outputs_data(BytesVec::new_builder().set(vec![output_data]).build())
        .build();

    case.settlement_witness = hex::encode(&witness);
    case.lock_args = hex::encode(&args);
    case.tx_size = tx_size;
    case.fee = fee.to_string();
    case.digest = hex::encode(compute_raw_tx_message(&raw));
    case
}

fn build_shutdown_case(local: &FiberSigner, remote: &FiberSigner, mut case: ShutdownCaseVector) -> ShutdownCaseVector {
    let tx_size = shutdown_tx_size(
        case.cell_deps_count as usize,
        &case.udt_type_script,
        [&case.local_close_script, &case.remote_close_script],
    );
    let local_fee = fee_from_rate(case.local_fee_rate.parse().unwrap(), tx_size);
    let remote_fee = fee_from_rate(case.remote_fee_rate.parse().unwrap(), tx_size);

    let is_udt = case.udt_type_script.is_some();
    let to_local: u128 = case.to_local.parse().unwrap();
    let to_remote: u128 = case.to_remote.parse().unwrap();
    let local_reserved: u64 = case.local_reserved.parse().unwrap();
    let remote_reserved: u64 = case.remote_reserved.parse().unwrap();
    let local_capacity = if is_udt {
        local_reserved - local_fee
    } else {
        u64::try_from(to_local + u128::from(local_reserved)).unwrap() - local_fee
    };
    let remote_capacity = if is_udt {
        remote_reserved - remote_fee
    } else {
        u64::try_from(to_remote + u128::from(remote_reserved)).unwrap() - remote_fee
    };

    let build_output = |capacity: u64, script: &ScriptVector| {
        CellOutput::new_builder()
            .capacity(ckb_types::prelude::Pack::<ckb_types::packed::Uint64>::pack(&capacity))
            .lock(packed_script(script))
            .type_(packed_script_opt(&case.udt_type_script))
            .build()
    };
    let local_output = build_output(local_capacity, &case.local_close_script);
    let remote_output = build_output(remote_capacity, &case.remote_close_script);
    let local_data: PackedBytes = if is_udt { to_local.to_le_bytes().to_vec().pack() } else { Vec::<u8>::new().pack() };
    let remote_data: PackedBytes = if is_udt { to_remote.to_le_bytes().to_vec().pack() } else { Vec::<u8>::new().pack() };

    // fiber's order_things_for_musig2: the outputs are permuted by the funding-pubkey sort, not by role.
    let local_first = pubkey_of(&local.funding_key).serialize() <= pubkey_of(&remote.funding_key).serialize();
    let (outputs, outputs_data) = if local_first {
        (vec![local_output, remote_output], vec![local_data, remote_data])
    } else {
        (vec![remote_output, local_output], vec![remote_data, local_data])
    };
    let input = CellInput::new_builder().previous_output(packed_out_point(&case.funding_out_point)).build();
    let raw = RawTransaction::new_builder()
        .inputs(CellInputVec::new_builder().set(vec![input]).build())
        .outputs(CellOutputVec::new_builder().set(outputs).build())
        .outputs_data(BytesVec::new_builder().set(outputs_data).build())
        .build();

    case.tx_size = tx_size;
    case.local_fee = local_fee.to_string();
    case.remote_fee = remote_fee.to_string();
    case.digest = hex::encode(compute_raw_tx_message(&raw));
    case
}

fn build_revocation_case(
    local: &FiberSigner,
    remote: &FiberSigner,
    commitment_lock: &ScriptVector,
    mut case: RevocationCaseVector,
) -> RevocationCaseVector {
    let local_pub = pubkey_of(&local.funding_key);
    let remote_pub = pubkey_of(&remote.funding_key);
    // Role order on purpose: the x-only key must match the revoked commitment cell's lock args.
    let xonly = if case.for_remote {
        xonly_agg(&local_pub, &remote_pub)
    } else {
        xonly_agg(&remote_pub, &local_pub)
    };

    let is_udt = case.udt_type_script.is_some();
    let to_local: u128 = case.to_local.parse().unwrap();
    let to_remote: u128 = case.to_remote.parse().unwrap();
    let local_reserved: u64 = case.local_reserved.parse().unwrap();
    let remote_reserved: u64 = case.remote_reserved.parse().unwrap();
    let fee = fee_from_rate(
        case.fee_rate.parse().unwrap(),
        commitment_tx_size(case.cell_deps_count as usize, &case.udt_type_script, commitment_lock),
    );
    let liquid = to_local + to_remote;
    let total_reserved = local_reserved + remote_reserved;
    let capacity = if is_udt {
        total_reserved - fee
    } else {
        u64::try_from(liquid + u128::from(total_reserved)).unwrap() - fee
    };

    let output = CellOutput::new_builder()
        .capacity(ckb_types::prelude::Pack::<ckb_types::packed::Uint64>::pack(&capacity))
        .lock(packed_script(&case.payout_script))
        .type_(packed_script_opt(&case.udt_type_script))
        .build();
    let output_data: PackedBytes = if is_udt { liquid.to_le_bytes().to_vec().pack() } else { Vec::<u8>::new().pack() };
    let mut args = Vec::with_capacity(36);
    args.extend(&blake2b_256(&xonly)[0..20]);
    args.extend((SINCE_RELATIVE_EPOCH_FLAGS | case.delay_epoch.parse::<u64>().unwrap()).to_le_bytes());
    args.extend(case.revoked_commitment_number.to_be_bytes());

    case.fee = fee.to_string();
    case.digest = hex::encode(ckb_blake2b(&[output.as_slice(), output_data.as_slice(), &args]));
    case
}

fn build_announcement_case(local: &FiberSigner, remote: &FiberSigner, mut case: AnnouncementCaseVector) -> AnnouncementCaseVector {
    let local_pub = pubkey_of(&local.funding_key);
    let remote_pub = pubkey_of(&remote.funding_key);
    let sorted_xonly = if local_pub.serialize() <= remote_pub.serialize() {
        xonly_agg(&local_pub, &remote_pub)
    } else {
        xonly_agg(&remote_pub, &local_pub)
    };

    let mut node_ids: Vec<[u8; 33]> = case
        .node_ids
        .iter()
        .map(|id| hex::decode(id).unwrap().try_into().unwrap())
        .collect();
    node_ids.sort();
    let chain_hash: [u8; 32] = hex::decode(&case.chain_hash).unwrap().try_into().unwrap();

    let announcement = fiber_types::protocol::ChannelAnnouncement {
        node1_signature: None,
        node2_signature: None,
        ckb_signature: None,
        features: 0,
        chain_hash: chain_hash.into(),
        channel_outpoint: packed_out_point(&case.funding_out_point),
        node1_id: fiber_types::primitives::Pubkey(node_ids[0]),
        node2_id: fiber_types::primitives::Pubkey(node_ids[1]),
        ckb_key: secp030::XOnlyPublicKey::from_slice(&sorted_xonly).unwrap(),
        capacity: case.capacity.parse().unwrap(),
        udt_type_script: case.udt_type_script.as_ref().map(packed_script),
    };
    case.digest = hex::encode(announcement.message_to_sign());
    case
}

fn channel_keys_vector(signer: &FiberSigner) -> ChannelKeysVector {
    ChannelKeysVector {
        funding_key: hex::encode(signer.funding_key.secret_bytes()),
        tlc_base_key: hex::encode(signer.tlc_base_key.secret_bytes()),
        musig2_base_nonce: hex::encode(signer.musig2_base_nonce.secret_bytes()),
        commitment_seed: hex::encode(signer.commitment_seed),
        funding_pubkey: hex::encode(pubkey_of(&signer.funding_key).serialize()),
        tlc_base_pubkey: hex::encode(pubkey_of(&signer.tlc_base_key).serialize()),
    }
}

fn hash_vector(label: &str, chunks: &[&[u8]]) -> HashVector {
    HashVector {
        label: label.to_string(),
        chunks: chunks.iter().map(hex::encode).collect(),
        digest: hex::encode(ckb_blake2b(chunks)),
    }
}

fn gen_vectors(out_path: &str) {
    let signer = FiberSigner::generate_from_seed(&CHANNEL_SEED_PARAMS);

    let commitments = COMMITMENT_NUMBERS
        .iter()
        .map(|&n| {
            let tlc_key = signer.derive_tlc_key(n);
            CommitmentVector {
                n,
                secret: hex::encode(get_commitment_secret(&signer.commitment_seed, n)),
                point: hex::encode(signer.get_commitment_point(n).serialize()),
                tlc_privkey: hex::encode(tlc_key.secret_bytes()),
                tlc_pubkey: hex::encode(pubkey_of(&tlc_key).serialize()),
                musig2_nonce_seckey: hex::encode(signer.musig2_nonce_seckey(n).secret_bytes()),
            }
        })
        .collect();

    let sdk_channel_index = CHANNEL_INDICES[0];
    let sdk_channel_seed = channel_seed(&MASTER_SEED, sdk_channel_index);
    let sdk_signer = FiberSigner::generate_from_seed(&sdk_channel_seed);
    let mut nonce_seeds = Vec::new();
    for &n in COMMITMENT_NUMBERS.iter() {
        for context in NONCE_CONTEXTS.iter() {
            nonce_seeds.push(NonceSeedVector {
                commitment_number: n,
                context: context.to_string(),
                seed: hex::encode(nonce_seed(&sdk_signer, n, context)),
            });
        }
    }

    let remote_sk = SecretKey::from_slice(&blake2b_256(&REMOTE_SEED)).unwrap();
    let message = blake2b_256(b"fiber remote signer test message");

    let digest = digest_vectors(&sdk_signer);

    let vectors = Vectors {
        scheme_version: SCHEME_VERSION,
        fiber_ref: FIBER_REF.to_string(),
        hashes: vec![
            hash_vector("empty", &[b""]),
            hash_vector("abc", &[b"abc"]),
            hash_vector("two chunks", &[b"dead", b"beef"]),
            hash_vector("salt before data", &[b"funding key", b"seed"]),
        ],
        fiber_scheme: FiberSchemeVectors {
            channel_seed: hex::encode(CHANNEL_SEED_PARAMS),
            channel_keys: channel_keys_vector(&signer),
            commitments,
        },
        sdk_scheme: SdkSchemeVectors {
            bip39_seed: hex::encode(BIP39_SEED),
            master_seeds: ACCOUNT_INDICES
                .iter()
                .map(|&account_index| MasterSeedVector {
                    account_index,
                    path: master_seed_path(account_index),
                    master_seed: hex::encode(master_seed(&BIP39_SEED, account_index)),
                })
                .collect(),
            master_seed: hex::encode(MASTER_SEED),
            wallet_identity_key: hex::encode(wallet_identity_key(&MASTER_SEED)),
            channel_seeds: CHANNEL_INDICES
                .iter()
                .map(|&channel_index| ChannelSeedVector {
                    channel_index,
                    seed: hex::encode(channel_seed(&MASTER_SEED, channel_index)),
                })
                .collect(),
            channel: SdkChannelVector {
                channel_index: sdk_channel_index,
                seed: hex::encode(sdk_channel_seed),
                channel_keys: channel_keys_vector(&sdk_signer),
                nonce_seeds,
            },
        },
        musig: MusigVector {
            remote_seckey: hex::encode(remote_sk.secret_bytes()),
            remote_pubkey: hex::encode(pubkey_of(&remote_sk).serialize()),
            remote_pubnonce: hex::encode(remote_secnonce().public_nonce().serialize()),
            message: hex::encode(message),
        },
        digest,
    };

    let json = serde_json::to_string_pretty(&vectors).unwrap();
    std::fs::write(out_path, format!("{json}\n")).unwrap();
    println!("vectors written to {out_path}");
}

/// The digest half of the vectors: fixture channels through the ported fiber build functions.
fn digest_vectors(local: &FiberSigner) -> DigestVectors {
    let remote = FiberSigner::generate_from_seed(&REMOTE_SIGNER_SEED);
    let commitment_lock = ScriptVector {
        code_hash: COMMITMENT_LOCK_TESTNET_CODE_HASH.to_string(),
        hash_type: "type".to_string(),
        args: String::new(),
    };
    let udt_script = ScriptVector {
        code_hash: hex::encode(blake2b_256(b"udt code hash")),
        hash_type: "type".to_string(),
        args: hex::encode(blake2b_256(b"udt args")),
    };
    let funding = OutPointVector { tx_hash: hex::encode(blake2b_256(b"funding tx")), index: 0 };
    let local_close = ScriptVector {
        code_hash: hex::encode(blake2b_256(b"local close")),
        hash_type: "type".to_string(),
        args: hex::encode(blake160(b"local close args")),
    };
    let remote_close = ScriptVector {
        code_hash: hex::encode(blake2b_256(b"remote close")),
        hash_type: "data1".to_string(),
        args: hex::encode(blake2b_256(b"remote close args")),
    };

    let point = |n: u64| hex::encode(remote.get_commitment_point(n).serialize());
    let ckb_tlcs = vec![
        TlcVector {
            id: 7,
            direction: "offered".to_string(),
            hash_algorithm: "ckb-hash".to_string(),
            amount: "1500000000".to_string(),
            payment_hash: hex::encode(blake2b_256(b"payment one")),
            expiry_ms: "1723257890123".to_string(),
            created_at_remote_commitment_number: 5,
            remote_commitment_point: point(5),
        },
        TlcVector {
            id: 2,
            direction: "received".to_string(),
            hash_algorithm: "sha256".to_string(),
            amount: "2250000000".to_string(),
            payment_hash: hex::encode(blake2b_256(b"payment two")),
            expiry_ms: "1750000000000".to_string(),
            created_at_remote_commitment_number: 0,
            remote_commitment_point: point(1),
        },
        TlcVector {
            id: 5,
            direction: "offered".to_string(),
            hash_algorithm: "sha256".to_string(),
            amount: "750000000".to_string(),
            payment_hash: hex::encode(blake2b_256(b"payment three")),
            expiry_ms: "1699999999999".to_string(),
            created_at_remote_commitment_number: 1,
            remote_commitment_point: point(2),
        },
    ];
    let udt_tlcs = vec![
        TlcVector {
            id: 1,
            direction: "offered".to_string(),
            hash_algorithm: "ckb-hash".to_string(),
            amount: "100000000000000000000".to_string(),
            payment_hash: hex::encode(blake2b_256(b"udt payment one")),
            expiry_ms: "1731234567891".to_string(),
            created_at_remote_commitment_number: 3,
            remote_commitment_point: point(3),
        },
        TlcVector {
            id: 9,
            direction: "received".to_string(),
            hash_algorithm: "sha256".to_string(),
            amount: "50000000000000000000".to_string(),
            payment_hash: hex::encode(blake2b_256(b"udt payment two")),
            expiry_ms: "1745678901234".to_string(),
            created_at_remote_commitment_number: 8,
            remote_commitment_point: point(8),
        },
    ];

    let commitment_case =|name: &str, for_remote: bool| CommitmentCaseVector {
        name: name.to_string(),
        for_remote,
        funding_out_point: funding.clone(),
        commitment_number: 11,
        delay_epoch: DEFAULT_DELAY_EPOCH.to_string(),
        fee_rate: "1000".to_string(),
        cell_deps_count: 2,
        udt_type_script: None,
        to_local: "62000000000".to_string(),
        to_remote: "18500000000".to_string(),
        settlement_local: "59750000000".to_string(),
        settlement_remote: "16250000000".to_string(),
        local_reserved: "4200000000".to_string(),
        remote_reserved: "6300000000".to_string(),
        tlcs: Vec::new(),
        settlement_witness: String::new(),
        lock_args: String::new(),
        tx_size: 0,
        fee: String::new(),
        digest: String::new(),
    };

    let commitment_cases = vec![
        build_commitment_case(local, &remote, &commitment_lock, {
            let mut case = commitment_case("ckb, no tlcs, for remote", true);
            case.commitment_number = 0;
            case.settlement_local = case.to_local.clone();
            case.settlement_remote = case.to_remote.clone();
            case
        }),
        build_commitment_case(local, &remote, &commitment_lock, {
            let mut case = commitment_case("ckb, three tlcs, for remote", true);
            case.funding_out_point = OutPointVector { index: 3, ..funding.clone() };
            case.fee_rate = "1537".to_string();
            case.tlcs = ckb_tlcs.clone();
            case
        }),
        build_commitment_case(local, &remote, &commitment_lock, {
            let mut case = commitment_case("ckb, three tlcs, for local", false);
            case.delay_epoch = ((12u64 << 40) | (3 << 24) | 7).to_string();
            case.commitment_number = 12;
            case.tlcs = ckb_tlcs.clone();
            case
        }),
        build_commitment_case(local, &remote, &commitment_lock, {
            let mut case = commitment_case("udt, two tlcs, for remote", true);
            case.cell_deps_count = 3;
            case.udt_type_script = Some(udt_script.clone());
            case.to_local = "500000000000000000000".to_string();
            case.to_remote = "300000000000000000000".to_string();
            case.settlement_local = "400000000000000000000".to_string();
            case.settlement_remote = "250000000000000000000".to_string();
            case.tlcs = udt_tlcs.clone();
            case
        }),
    ];

    let shutdown_case = |name: &str| ShutdownCaseVector {
        name: name.to_string(),
        funding_out_point: funding.clone(),
        local_close_script: local_close.clone(),
        remote_close_script: remote_close.clone(),
        local_fee_rate: "1000".to_string(),
        remote_fee_rate: "2143".to_string(),
        cell_deps_count: 2,
        udt_type_script: None,
        to_local: "62000000000".to_string(),
        to_remote: "18500000000".to_string(),
        local_reserved: "4200000000".to_string(),
        remote_reserved: "6300000000".to_string(),
        tx_size: 0,
        local_fee: String::new(),
        remote_fee: String::new(),
        digest: String::new(),
    };
    let shutdown_cases = vec![
        build_shutdown_case(local, &remote, shutdown_case("ckb")),
        build_shutdown_case(local, &remote, {
            let mut case = shutdown_case("udt");
            case.cell_deps_count = 3;
            case.udt_type_script = Some(udt_script.clone());
            case.to_local = "500000000000000000000".to_string();
            case.to_remote = "300000000000000000000".to_string();
            case
        }),
    ];

    let revocation_case = |name: &str, for_remote: bool, payout: &ScriptVector| RevocationCaseVector {
        name: name.to_string(),
        for_remote,
        revoked_commitment_number: 4,
        payout_script: payout.clone(),
        delay_epoch: DEFAULT_DELAY_EPOCH.to_string(),
        fee_rate: "1000".to_string(),
        cell_deps_count: 2,
        udt_type_script: None,
        to_local: "62000000000".to_string(),
        to_remote: "18500000000".to_string(),
        local_reserved: "4200000000".to_string(),
        remote_reserved: "6300000000".to_string(),
        fee: String::new(),
        digest: String::new(),
    };
    let revocation_cases = vec![
        build_revocation_case(local, &remote, &commitment_lock, revocation_case("ckb, send side", false, &remote_close)),
        build_revocation_case(local, &remote, &commitment_lock, {
            let mut case = revocation_case("udt, receive side", true, &local_close);
            case.revoked_commitment_number = 9;
            case.cell_deps_count = 3;
            case.udt_type_script = Some(udt_script.clone());
            case.to_local = "500000000000000000000".to_string();
            case.to_remote = "300000000000000000000".to_string();
            case
        }),
    ];

    let node_one = pubkey_of(&SecretKey::from_slice(&blake2b_256(b"node one")).unwrap()).serialize();
    let node_two = pubkey_of(&SecretKey::from_slice(&blake2b_256(b"node two")).unwrap()).serialize();
    let (smaller_node, larger_node) = if node_one <= node_two { (node_one, node_two) } else { (node_two, node_one) };
    let sorted_node_ids = [hex::encode(smaller_node), hex::encode(larger_node)];
    // Handed over larger-first on purpose: both implementations must sort by node pubkey themselves.
    let unsorted_node_ids = [hex::encode(larger_node), hex::encode(smaller_node)];
    let announcement_case = |name: &str| AnnouncementCaseVector {
        name: name.to_string(),
        chain_hash: hex::encode(blake2b_256(b"chain hash")),
        funding_out_point: funding.clone(),
        node_ids: unsorted_node_ids.clone(),
        capacity: "80500000000".to_string(),
        udt_type_script: None,
        digest: String::new(),
    };
    let announcement_cases = vec![
        build_announcement_case(local, &remote, announcement_case("ckb")),
        // The same channel with the node ids already in sorted order: the other branch of the node id sort.
        build_announcement_case(local, &remote, {
            let mut case = announcement_case("ckb, node ids already sorted");
            case.node_ids = sorted_node_ids.clone();
            case
        }),
        build_announcement_case(local, &remote, {
            let mut case = announcement_case("udt");
            case.capacity = "800000000000000000000".to_string();
            case.udt_type_script = Some(udt_script.clone());
            case
        }),
    ];

    DigestVectors {
        commitment_lock,
        remote: RemoteSignerVector {
            seed: hex::encode(REMOTE_SIGNER_SEED),
            funding_pubkey: hex::encode(pubkey_of(&remote.funding_key).serialize()),
            tlc_base_pubkey: hex::encode(pubkey_of(&remote.tlc_base_key).serialize()),
        },
        commitment_cases,
        shutdown_cases,
        revocation_cases,
        announcement_cases,
    }
}

fn verify_ts(vectors_path: &str, ts_out_path: &str) {
    let vectors: Vectors =
        serde_json::from_str(&std::fs::read_to_string(vectors_path).unwrap()).unwrap();
    let ts: TsOutput =
        serde_json::from_str(&std::fs::read_to_string(ts_out_path).unwrap()).unwrap();

    let local_pk = musig2::secp256k1::PublicKey::from_slice(
        &hex::decode(&vectors.fiber_scheme.channel_keys.funding_pubkey).unwrap(),
    )
    .unwrap();
    let remote_pk = musig2::secp256k1::PublicKey::from_slice(
        &hex::decode(&vectors.musig.remote_pubkey).unwrap(),
    )
    .unwrap();
    let remote_sk = musig2::secp256k1::SecretKey::from_slice(
        &hex::decode(&vectors.musig.remote_seckey).unwrap(),
    )
    .unwrap();
    let message = hex::decode(&vectors.musig.message).unwrap();

    // The fixed order of this vector's slot; the engine signs whatever list it is handed
    // (fiber sorts funding-cell spends and keeps role order for revocations, see the digest section).
    let key_agg_ctx = KeyAggContext::new(vec![local_pk, remote_pk]).unwrap();

    let local_pubnonce = PubNonce::from_bytes(&hex::decode(&ts.local_pubnonce).unwrap()).unwrap();
    let remote_pubnonce = remote_secnonce().public_nonce();
    let agg_nonce = AggNonce::sum([local_pubnonce.clone(), remote_pubnonce]);

    let ts_partial =
        PartialSignature::from_slice(&hex::decode(&ts.partial_signature).unwrap()).unwrap();

    verify_partial(
        &key_agg_ctx,
        ts_partial,
        &agg_nonce,
        local_pk,
        &local_pubnonce,
        &message,
    )
    .expect("TS partial signature must verify under fiber's musig2 crate");
    println!("OK: TS partial signature verified by musig2 0.2.4");

    let remote_partial: PartialSignature = sign_partial(
        &key_agg_ctx,
        remote_sk,
        remote_secnonce(),
        &agg_nonce,
        &message,
    )
    .expect("remote partial");

    let final_sig: CompactSignature = aggregate_partial_signatures(
        &key_agg_ctx,
        &agg_nonce,
        [ts_partial, remote_partial],
        &message,
    )
    .expect("aggregation must succeed");

    let agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    musig2::verify_single(agg_pubkey, final_sig, &message)
        .expect("aggregated signature must verify");
    println!("OK: aggregated schnorr signature verified");
    println!("final_signature={}", hex::encode(final_sig.serialize()));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen-vectors") => gen_vectors(&args[2]),
        Some("verify-ts") => verify_ts(&args[2], &args[3]),
        _ => {
            eprintln!("usage: gen-vectors <out.json> | verify-ts <vectors.json> <ts-out.json>");
            std::process::exit(1);
        }
    }
}
