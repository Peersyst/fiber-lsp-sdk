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

// --- Vector file shape ---

#[derive(Serialize, Deserialize)]
struct Vectors {
    scheme_version: u32,
    fiber_ref: String,
    hashes: Vec<HashVector>,
    fiber_scheme: FiberSchemeVectors,
    sdk_scheme: SdkSchemeVectors,
    musig: MusigVector,
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

fn remote_secnonce() -> SecNonce {
    SecNonceBuilder::new(REMOTE_SEED).build()
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
    };

    let json = serde_json::to_string_pretty(&vectors).unwrap();
    std::fs::write(out_path, format!("{json}\n")).unwrap();
    println!("vectors written to {out_path}");
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

    // fiber's role ordering ([local, remote]), not lexicographic sorting.
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
