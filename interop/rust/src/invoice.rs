//! Fiber's invoice string, pinned from fiber's own encoder and decoder: invoices written by `CkbInvoice`'s `Display`, the
//! arithmetic coder on data no invoice reaches, UTF-8 as Rust reads it, and the variants of one invoice with fiber's verdict.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::time::Duration;

use arcode::bitbit::{BitReader, BitWriter, MSB};
use arcode::{ArithmeticDecoder, ArithmeticEncoder, EOFKind, Model};
use bech32::{ToBase32, Variant};
use fiber_types::gen::invoice::RawInvoiceData;
use fiber_types::{
    construct_invoice_preimage, sha256, Attribute, CkbInvoice, CkbScript, Currency, FeatureVector, HashAlgorithm,
    InvoiceData, InvoiceSignature,
};
use molecule::prelude::Entity;
use secp030::ecdsa::{RecoverableSignature, RecoveryId};
use secp030::{Message, PublicKey, SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{packed_script, ScriptVector, FIBER_REF};

// Literals at crates/fiber-types/src/invoice.rs:144-154.
const SIGNATURE_U5_SIZE: usize = 104;
const MAX_INVOICE_DATA_LENGTH: usize = 16 * 1024;
// The coder's precision, crates/fiber-types/src/invoice.rs:161,177.
const CODER_PRECISION: u64 = 48;

const PAYEE_SECRET_KEY: [u8; 32] = [0x11; 32];
const OTHER_SECRET_KEY: [u8; 32] = [0x22; 32];
const PAYMENT_HASH: [u8; 32] = [0x03; 32];

// --- the vector file ---

#[derive(Serialize, Deserialize)]
pub struct InvoiceVectors {
    fiber_ref: String,
    payee_secret_key: String,
    payee_public_key: String,
    invoices: Vec<InvoiceCase>,
    coder: CoderVectors,
    utf8: Vec<Utf8Case>,
    variants: Vec<VariantCase>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct AttributeValues {
    #[serde(rename = "type")]
    kind: String,
    value: Value,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct InvoiceValues {
    currency: String,
    amount: Option<String>,
    timestamp: String,
    payment_hash: String,
    attrs: Vec<AttributeValues>,
}

#[derive(Serialize, Deserialize)]
struct InvoiceCase {
    name: String,
    values: InvoiceValues,
    molecule: String,
    compressed: String,
    digest: String,
    signature: Option<String>,
    string: String,
}

#[derive(Serialize, Deserialize)]
struct CoderVectors {
    compress: Vec<CompressCase>,
    decompress: Vec<DecompressCase>,
}

#[derive(Serialize, Deserialize)]
struct CompressCase {
    name: String,
    data: String,
    compressed: String,
}

#[derive(Serialize, Deserialize)]
struct DecompressCase {
    name: String,
    compressed: String,
    data: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Utf8Case {
    name: String,
    bytes: String,
    text: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct VariantCase {
    name: String,
    string: String,
    fiber: String,
    error: Option<String>,
}

// --- the coder, ported verbatim from crates/fiber-types/src/invoice.rs:158-199 ---

fn ar_encompress(data: &[u8]) -> Vec<u8> {
    let mut model = Model::builder().num_bits(8).eof(EOFKind::EndAddOne).build();
    let mut compressed_writer = BitWriter::new(Cursor::new(vec![]));
    let mut encoder = ArithmeticEncoder::new(CODER_PRECISION);
    for &sym in data {
        encoder.encode(sym as u32, &model, &mut compressed_writer).unwrap();
        model.update_symbol(sym as u32);
    }
    encoder.encode(model.eof(), &model, &mut compressed_writer).unwrap();
    encoder.finish_encode(&mut compressed_writer).unwrap();
    compressed_writer.pad_to_byte().unwrap();
    compressed_writer.get_ref().get_ref().clone()
}

fn ar_decompress_with_limit(data: &[u8], max_len: usize) -> Option<Vec<u8>> {
    let mut model = Model::builder().num_bits(8).eof(EOFKind::EndAddOne).build();
    let mut input_reader = BitReader::<_, MSB>::new(data);
    let mut decoder = ArithmeticDecoder::new(CODER_PRECISION);
    let mut decompressed_data = vec![];
    while !decoder.finished() {
        let sym = decoder.decode(&model, &mut input_reader).ok()?;
        model.update_symbol(sym);
        decompressed_data.push(sym as u8);
        if !decoder.finished() && decompressed_data.len() > max_len {
            return None;
        }
    }
    decompressed_data.pop()?;
    Some(decompressed_data)
}

// --- building strings ---

fn secret(bytes: [u8; 32]) -> SecretKey {
    SecretKey::from_slice(&bytes).unwrap()
}

fn public(bytes: [u8; 32]) -> PublicKey {
    PublicKey::from_secret_key(SECP256K1, &secret(bytes))
}

fn groups(bytes: &[u8]) -> Vec<bech32::u5> {
    bytes.to_base32()
}

fn u5s(values: &[u8]) -> Vec<bech32::u5> {
    values.iter().map(|value| bech32::u5::try_from_u8(*value).unwrap()).collect()
}

/// The digest fiber signs over a human-readable part and a compressed stream (`invoice.rs:687-692`).
fn digest_of(hrp: &str, compressed: &[u8]) -> [u8; 32] {
    sha256(construct_invoice_preimage(hrp.as_bytes(), &groups(compressed)))
}

/// `r || s || recovery id`, the 65 bytes fiber writes as 104 groups (`invoice.rs:487-499`).
fn signature_bytes(signature: &RecoverableSignature) -> Vec<u8> {
    let (recovery_id, compact) = signature.serialize_compact();
    [compact.as_slice(), &[i32::from(recovery_id) as u8]].concat()
}

fn sign(hrp: &str, compressed: &[u8], key: [u8; 32]) -> Vec<u8> {
    let message = Message::from_digest(digest_of(hrp, compressed));
    signature_bytes(&SECP256K1.sign_ecdsa_recoverable(&message, &secret(key)))
}

fn encode_string(hrp: &str, flag: u8, compressed: &[u8], signature: &[u8], variant: Variant) -> String {
    let mut data = u5s(&[flag]);
    data.extend(groups(compressed));
    data.extend(groups(signature));
    bech32::encode(hrp, data, variant).unwrap()
}

fn signed_string(hrp: &str, molecule: &[u8], key: [u8; 32]) -> String {
    let compressed = ar_encompress(molecule);
    encode_string(hrp, 1, &compressed, &sign(hrp, &compressed, key), Variant::Bech32m)
}

// --- molecule by hand, for what fiber's builders refuse to write ---

fn le(value: u128, width: usize) -> Vec<u8> {
    value.to_le_bytes()[..width].to_vec()
}

fn table(fields: &[Vec<u8>]) -> Vec<u8> {
    let header = 4 * (fields.len() + 1);
    let total = header + fields.iter().map(Vec::len).sum::<usize>();
    let mut out = le(total as u128, 4);
    let mut offset = header;
    for field in fields {
        out.extend(le(offset as u128, 4));
        offset += field.len();
    }
    for field in fields {
        out.extend(field);
    }
    out
}

fn dynvec(items: &[Vec<u8>]) -> Vec<u8> {
    if items.is_empty() {
        le(4, 4)
    } else {
        table(items)
    }
}

fn mol_bytes(data: &[u8]) -> Vec<u8> {
    [le(data.len() as u128, 4), data.to_vec()].concat()
}

fn attr(id: u32, body: Vec<u8>) -> Vec<u8> {
    [le(id as u128, 4), body].concat()
}

fn raw(timestamp: u128, attrs: &[Vec<u8>]) -> Vec<u8> {
    table(&[le(timestamp, 16), PAYMENT_HASH.to_vec(), dynvec(attrs)])
}

fn payee_attr(key: &[u8]) -> Vec<u8> {
    attr(7, table(&[mol_bytes(key)]))
}

// --- fiber's invoices ---

fn currency_name(currency: Currency) -> &'static str {
    match currency {
        Currency::Fibb => "Fibb",
        Currency::Fibt => "Fibt",
        Currency::Fibd => "Fibd",
    }
}

fn hash_algorithm_name(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::CkbHash => "ckb_hash",
        HashAlgorithm::Sha256 => "sha256",
    }
}

fn script_vector(script: &CkbScript) -> ScriptVector {
    let hash_type = match u8::from(script.0.hash_type()) {
        0 => "data",
        1 => "type",
        2 => "data1",
        4 => "data2",
        other => panic!("hash type {other}"),
    };
    ScriptVector {
        code_hash: hex::encode(script.0.code_hash().as_slice()),
        hash_type: hash_type.to_string(),
        args: hex::encode(script.0.args().raw_data()),
    }
}

/// Names each of fiber's attributes in an exhaustive match, so a variant a new release adds fails to compile here.
fn attribute_values(attribute: &Attribute) -> AttributeValues {
    let (kind, value) = match attribute {
        Attribute::FinalHtlcTimeout(value) => ("final_htlc_timeout", json!(value.to_string())),
        Attribute::FinalHtlcMinimumExpiryDelta(value) => ("final_htlc_minimum_expiry_delta", json!(value.to_string())),
        Attribute::ExpiryTime(value) => ("expiry_time", json!(value.as_secs().to_string())),
        Attribute::Description(value) => ("description", json!(value)),
        Attribute::FallbackAddr(value) => ("fallback_addr", json!(value)),
        Attribute::UdtScript(script) => ("udt_script", serde_json::to_value(script_vector(script)).unwrap()),
        Attribute::PayeePublicKey(key) => ("payee_public_key", json!(hex::encode(key.serialize()))),
        Attribute::HashAlgorithm(algorithm) => ("hash_algorithm", json!(hash_algorithm_name(*algorithm))),
        Attribute::Feature(feature) => ("feature", json!(hex::encode(feature.bytes()))),
        Attribute::PaymentSecret(secret) => ("payment_secret", json!(hex::encode(secret.as_ref()))),
    };
    AttributeValues { kind: kind.to_string(), value }
}

fn attribute_of(values: &AttributeValues) -> Attribute {
    let text = || values.value.as_str().unwrap().to_string();
    let decimal = || text().parse::<u64>().unwrap();
    let bytes = || hex::decode(text()).unwrap();
    match values.kind.as_str() {
        "final_htlc_timeout" => Attribute::FinalHtlcTimeout(decimal()),
        "final_htlc_minimum_expiry_delta" => Attribute::FinalHtlcMinimumExpiryDelta(decimal()),
        "expiry_time" => Attribute::ExpiryTime(Duration::from_secs(decimal())),
        "description" => Attribute::Description(text()),
        "fallback_addr" => Attribute::FallbackAddr(text()),
        "udt_script" => {
            let script: ScriptVector = serde_json::from_value(values.value.clone()).unwrap();
            Attribute::UdtScript(CkbScript(packed_script(&script)))
        }
        "payee_public_key" => Attribute::PayeePublicKey(PublicKey::from_slice(&bytes()).unwrap()),
        "hash_algorithm" => Attribute::HashAlgorithm(match text().as_str() {
            "ckb_hash" => HashAlgorithm::CkbHash,
            "sha256" => HashAlgorithm::Sha256,
            other => panic!("hash algorithm {other}"),
        }),
        "feature" => Attribute::Feature(FeatureVector::from(bytes())),
        "payment_secret" => Attribute::PaymentSecret(<[u8; 32]>::try_from(bytes()).unwrap().into()),
        other => panic!("attribute {other}"),
    }
}

fn invoice_values(invoice: &CkbInvoice) -> InvoiceValues {
    InvoiceValues {
        currency: currency_name(invoice.currency).to_string(),
        amount: invoice.amount.map(|amount| amount.to_string()),
        timestamp: invoice.data.timestamp.to_string(),
        payment_hash: hex::encode(invoice.data.payment_hash.as_ref()),
        attrs: invoice.data.attrs.iter().map(attribute_values).collect(),
    }
}

fn unsigned_invoice(values: &InvoiceValues) -> CkbInvoice {
    CkbInvoice {
        currency: match values.currency.as_str() {
            "Fibb" => Currency::Fibb,
            "Fibt" => Currency::Fibt,
            "Fibd" => Currency::Fibd,
            other => panic!("currency {other}"),
        },
        amount: values.amount.as_deref().map(|amount| amount.parse().unwrap()),
        signature: None,
        data: InvoiceData {
            timestamp: values.timestamp.parse().unwrap(),
            payment_hash: <[u8; 32]>::try_from(hex::decode(&values.payment_hash).unwrap()).unwrap().into(),
            attrs: values.attrs.iter().map(attribute_of).collect(),
        },
    }
}

fn hrp_of(invoice: &CkbInvoice) -> String {
    format!("{}{}", invoice.currency, invoice.amount.map_or_else(String::new, |amount| amount.to_string()))
}

fn invoice_case(name: &str, currency: Currency, amount: Option<u128>, timestamp: u128, attrs: Vec<Attribute>, signed: bool) -> InvoiceCase {
    let mut invoice = CkbInvoice {
        currency,
        amount,
        signature: None,
        data: InvoiceData { timestamp, payment_hash: PAYMENT_HASH.into(), attrs },
    };
    if signed {
        invoice.update_signature(|message| SECP256K1.sign_ecdsa_recoverable(message, &secret(PAYEE_SECRET_KEY))).unwrap();
    }
    let molecule = RawInvoiceData::from(invoice.data.clone()).as_slice().to_vec();
    let compressed = ar_encompress(&molecule);
    let hrp = hrp_of(&invoice);
    let signature = invoice.signature.as_ref().map(|signature| signature_bytes(&signature.0));
    let string = invoice.to_string();
    // The port of the coder and of the layout is pinned to fiber's own `Display` here.
    let flag = u8::from(signature.is_some());
    assert_eq!(
        encode_string(&hrp, flag, &compressed, signature.as_deref().unwrap_or_default(), Variant::Bech32m),
        string,
        "{name}: the harness's encoding differs from fiber's"
    );
    assert_eq!(ar_decompress_with_limit(&compressed, MAX_INVOICE_DATA_LENGTH).as_deref(), Some(molecule.as_slice()));
    if signed {
        let parsed: CkbInvoice = string.parse().unwrap();
        assert_eq!(parsed.to_string(), string, "{name}: fiber does not read its own string back");
    }
    InvoiceCase {
        name: name.to_string(),
        values: invoice_values(&invoice),
        molecule: hex::encode(&molecule),
        compressed: hex::encode(&compressed),
        digest: hex::encode(digest_of(&hrp, &compressed)),
        signature: signature.map(hex::encode),
        string,
    }
}

fn udt_script(hash_type: u8) -> CkbScript {
    use ckb_types::packed::{Byte, Script};
    use ckb_types::prelude::*;
    CkbScript(
        Script::new_builder()
            .code_hash([0xab; 32].pack())
            .hash_type(Byte::new(hash_type))
            .args(vec![1u8, 2, 3].pack())
            .build(),
    )
}

fn mpp_feature() -> FeatureVector {
    let mut feature = FeatureVector::new();
    feature.set_basic_mpp_optional();
    feature
}

/// The largest description that keeps the molecule at the decoder's limit, given the other fields of `max_data`.
fn max_description() -> String {
    // Table header 16, timestamp 16, hash 32, dynvec header 8, union id 4, description table header 8, Bytes length 4.
    "a".repeat(MAX_INVOICE_DATA_LENGTH - 88)
}

fn invoices() -> Vec<InvoiceCase> {
    let payee = public(PAYEE_SECRET_KEY);
    let ts = 1_704_067_200_000;
    let one = |name: &str, attribute: Attribute| invoice_case(name, Currency::Fibd, Some(1), 5, vec![attribute], true);
    vec![
        invoice_case("min unsigned", Currency::Fibd, None, 0, vec![], false),
        invoice_case("min signed", Currency::Fibd, None, 0, vec![], true),
        invoice_case(
            "hold invoice as new_invoice shapes it",
            Currency::Fibt,
            Some(250_000_000),
            ts,
            vec![
                Attribute::Description("coffee".to_string()),
                Attribute::ExpiryTime(Duration::from_secs(3600)),
                Attribute::FinalHtlcMinimumExpiryDelta(9_600_000),
                Attribute::HashAlgorithm(HashAlgorithm::CkbHash),
                Attribute::PayeePublicKey(payee),
            ],
            true,
        ),
        invoice_case(
            "hold invoice unsigned",
            Currency::Fibt,
            Some(250_000_000),
            ts,
            vec![
                Attribute::ExpiryTime(Duration::from_secs(3600)),
                Attribute::FinalHtlcMinimumExpiryDelta(9_600_000),
                Attribute::HashAlgorithm(HashAlgorithm::CkbHash),
            ],
            false,
        ),
        invoice_case(
            "every attribute",
            Currency::Fibb,
            Some(u128::MAX),
            u128::MAX,
            vec![
                Attribute::Description("description é".to_string()),
                Attribute::ExpiryTime(Duration::from_secs(u64::MAX)),
                Attribute::FallbackAddr("address".to_string()),
                Attribute::Feature(mpp_feature()),
                Attribute::PaymentSecret([7u8; 32].into()),
                Attribute::FinalHtlcTimeout(5),
                Attribute::FinalHtlcMinimumExpiryDelta(u64::MAX),
                Attribute::UdtScript(udt_script(4)),
                Attribute::HashAlgorithm(HashAlgorithm::Sha256),
                Attribute::PayeePublicKey(payee),
            ],
            true,
        ),
        invoice_case("zero amount", Currency::Fibt, Some(0), ts, vec![], true),
        one("expiry time alone", Attribute::ExpiryTime(Duration::from_secs(0))),
        one("description alone", Attribute::Description("pay me 😀 €".to_string())),
        one("empty description", Attribute::Description(String::new())),
        one("final htlc timeout alone", Attribute::FinalHtlcTimeout(u64::MAX)),
        one("final htlc minimum expiry delta alone", Attribute::FinalHtlcMinimumExpiryDelta(9_600_000)),
        one("fallback address alone", Attribute::FallbackAddr("ckt1qyq".to_string())),
        one("feature alone", Attribute::Feature(FeatureVector::from(vec![0x2a, 0x00, 0x01]))),
        one("empty feature", Attribute::Feature(FeatureVector::from(vec![]))),
        one("udt script alone", Attribute::UdtScript(udt_script(1))),
        one("udt script with data hash type", Attribute::UdtScript(udt_script(0))),
        one("udt script with data1 hash type", Attribute::UdtScript(udt_script(2))),
        one("payee public key alone", Attribute::PayeePublicKey(payee)),
        one("ckb hash alone", Attribute::HashAlgorithm(HashAlgorithm::CkbHash)),
        one("sha256 alone", Attribute::HashAlgorithm(HashAlgorithm::Sha256)),
        one("payment secret alone", Attribute::PaymentSecret([9u8; 32].into())),
        invoice_case(
            "multi-path as new_invoice shapes it",
            Currency::Fibt,
            Some(10_000_000_000),
            ts,
            vec![
                Attribute::ExpiryTime(Duration::from_secs(600)),
                Attribute::Feature(mpp_feature()),
                Attribute::PaymentSecret([5u8; 32].into()),
                Attribute::FinalHtlcMinimumExpiryDelta(9_600_000),
                Attribute::PayeePublicKey(payee),
            ],
            true,
        ),
        invoice_case("largest data", Currency::Fibd, Some(1), 5, vec![Attribute::Description(max_description())], true),
    ]
}

fn assert_invoice_coverage(cases: &[InvoiceCase]) {
    let alone: BTreeSet<String> = cases
        .iter()
        .filter(|case| case.values.attrs.len() == 1)
        .map(|case| case.values.attrs[0].kind.clone())
        .collect();
    let every: BTreeSet<String> = [
        Attribute::FinalHtlcTimeout(0),
        Attribute::FinalHtlcMinimumExpiryDelta(0),
        Attribute::ExpiryTime(Duration::ZERO),
        Attribute::Description(String::new()),
        Attribute::FallbackAddr(String::new()),
        Attribute::UdtScript(udt_script(0)),
        Attribute::PayeePublicKey(public(PAYEE_SECRET_KEY)),
        Attribute::HashAlgorithm(HashAlgorithm::CkbHash),
        Attribute::Feature(FeatureVector::new()),
        Attribute::PaymentSecret([0u8; 32].into()),
    ]
    .iter()
    .map(|attribute| attribute_values(attribute).kind)
    .collect();
    assert_eq!(alone, every, "every attribute alone");
    let currencies: BTreeSet<&str> = cases.iter().map(|case| case.values.currency.as_str()).collect();
    assert_eq!(currencies, BTreeSet::from(["Fibb", "Fibt", "Fibd"]), "every currency");
    let algorithms: BTreeSet<&str> = cases
        .iter()
        .flat_map(|case| &case.values.attrs)
        .filter(|attribute| attribute.kind == "hash_algorithm")
        .map(|attribute| attribute.value.as_str().unwrap())
        .collect();
    assert_eq!(algorithms, BTreeSet::from(["ckb_hash", "sha256"]), "every hash algorithm");
    assert!(cases.iter().any(|case| case.signature.is_none()) && cases.iter().any(|case| case.signature.is_some()));
    assert!(cases.iter().any(|case| case.values.amount.is_none()));
    let largest = cases.iter().find(|case| case.name == "largest data").unwrap();
    assert_eq!(largest.molecule.len() / 2, MAX_INVOICE_DATA_LENGTH, "largest data sits at the decoder's limit");
}

// --- the coder past what an invoice reaches ---

fn coder() -> CoderVectors {
    let mut state: u32 = 0x9e37_79b9;
    let mut pseudo_random = |length: usize| -> Vec<u8> {
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    };
    let compress_inputs: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one zero byte", vec![0]),
        ("one 0xff byte", vec![0xff]),
        ("every byte value once", (0..=255).collect()),
        ("every byte value twice, descending", (0..=255).rev().chain((0..=255).rev()).collect()),
        ("a long run", vec![0x61; 4096]),
        ("pseudo-random, 1000 bytes", pseudo_random(1000)),
        ("pseudo-random, 16384 bytes", pseudo_random(MAX_INVOICE_DATA_LENGTH)),
        ("16385 zero bytes", vec![0; MAX_INVOICE_DATA_LENGTH + 1]),
    ];
    let compress: Vec<CompressCase> = compress_inputs
        .iter()
        .map(|(name, data)| CompressCase { name: name.to_string(), data: hex::encode(data), compressed: hex::encode(ar_encompress(data)) })
        .collect();

    let molecule = raw(5, &[attr(0, le(3600, 8))]);
    let canonical = ar_encompress(&molecule);
    let last = canonical.len() - 1;
    let mut streams: Vec<(String, Vec<u8>)> = vec![
        ("canonical".to_string(), canonical.clone()),
        ("empty".to_string(), vec![]),
        ("five trailing 0xff bytes".to_string(), [canonical.clone(), vec![0xff; 5]].concat()),
        ("five trailing zero bytes".to_string(), [canonical.clone(), vec![0; 5]].concat()),
        ("garbage".to_string(), vec![0xff; 32]),
        ("16385 zero bytes".to_string(), ar_encompress(&vec![0; MAX_INVOICE_DATA_LENGTH + 1])),
        ("16384 zero bytes".to_string(), ar_encompress(&vec![0; MAX_INVOICE_DATA_LENGTH])),
        // Found by search: decoding ends on the last of the 48 zero bits the decoder pads a short input with, and with one
        // zero byte fewer it would need 56, so the padding budget is pinned at both edges.
        ("needs all 48 padding bits".to_string(), [vec![0x4e], vec![0; 10]].concat()),
        ("needs 56 padding bits".to_string(), [vec![0x4e], vec![0; 9]].concat()),
    ];
    for bit in 0..8 {
        let mut stream = canonical.clone();
        stream[last] ^= 1 << bit;
        streams.push((format!("last byte, bit {bit} flipped"), stream));
    }
    for cut in 1..=7 {
        streams.push((format!("last {cut} bytes cut"), canonical[..canonical.len() - cut].to_vec()));
    }
    let decompress = streams
        .into_iter()
        .map(|(name, compressed)| DecompressCase {
            name,
            data: ar_decompress_with_limit(&compressed, MAX_INVOICE_DATA_LENGTH).map(hex::encode),
            compressed: hex::encode(compressed),
        })
        .collect();
    CoderVectors { compress, decompress }
}

// --- UTF-8 as fiber reads it (`String::from_utf8`, invoice.rs:1078,1097) ---

fn utf8() -> Vec<Utf8Case> {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("ascii", b"coffee".to_vec()),
        ("two bytes, U+0080", vec![0xc2, 0x80]),
        ("two bytes, U+07FF", vec![0xdf, 0xbf]),
        ("three bytes, U+0800", vec![0xe0, 0xa0, 0x80]),
        ("three bytes, U+D7FF", vec![0xed, 0x9f, 0xbf]),
        ("three bytes, U+E000", vec![0xee, 0x80, 0x80]),
        ("three bytes, U+FFFF", vec![0xef, 0xbf, 0xbf]),
        ("four bytes, U+10000", vec![0xf0, 0x90, 0x80, 0x80]),
        ("four bytes, U+10FFFF", vec![0xf4, 0x8f, 0xbf, 0xbf]),
        ("mixed widths", "a é € 😀".as_bytes().to_vec()),
        ("a nul byte", vec![0x61, 0x00, 0x62]),
        ("overlong nul", vec![0xc0, 0x80]),
        ("overlong two bytes, C1", vec![0xc1, 0xbf]),
        ("overlong three bytes", vec![0xe0, 0x80, 0x80]),
        ("overlong three bytes, U+07FF", vec![0xe0, 0x9f, 0xbf]),
        ("overlong four bytes", vec![0xf0, 0x80, 0x80, 0x80]),
        ("overlong four bytes, U+FFFF", vec![0xf0, 0x8f, 0xbf, 0xbf]),
        ("high surrogate", vec![0xed, 0xa0, 0x80]),
        ("low surrogate", vec![0xed, 0xbf, 0xbf]),
        ("past U+10FFFF", vec![0xf4, 0x90, 0x80, 0x80]),
        ("lead byte F5", vec![0xf5, 0x80, 0x80, 0x80]),
        ("lead byte FF", vec![0xff]),
        ("stray continuation", vec![0x80]),
        ("two bytes cut", vec![0xc3]),
        ("three bytes cut", vec![0xef, 0xbf]),
        ("four bytes cut", vec![0xf0, 0x9f, 0x98]),
        ("continuation missing mid-sequence", vec![0xe2, 0x28, 0xa1]),
        ("cut before more text", vec![0xc3, 0x61]),
    ];
    cases
        .into_iter()
        .map(|(name, bytes)| Utf8Case {
            name: name.to_string(),
            text: String::from_utf8(bytes.clone()).ok(),
            bytes: hex::encode(bytes),
        })
        .collect()
}

// --- the variants of one invoice, with fiber's verdict ---

fn verdict(string: &str) -> (String, Option<String>) {
    let owned = string.to_string();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(move || owned.parse::<CkbInvoice>().map(|invoice| invoice.to_string()));
    std::panic::set_hook(previous);
    match outcome {
        Err(_) => ("panicked".to_string(), None),
        Ok(Err(err)) => ("refused".to_string(), Some(err.to_string())),
        Ok(Ok(written)) if written == string => ("accepted".to_string(), None),
        Ok(Ok(_)) => ("rewritten".to_string(), None),
    }
}

fn variants() -> Vec<VariantCase> {
    let payee = public(PAYEE_SECRET_KEY).serialize().to_vec();
    let payee_uncompressed = public(PAYEE_SECRET_KEY).serialize_uncompressed().to_vec();
    let other = public(OTHER_SECRET_KEY).serialize().to_vec();
    let ts = 1_704_067_200_000;
    let hrp = "fibt100000000";
    let base_attrs = |algorithm: u8, key: &[u8]| vec![attr(0, le(3600, 8)), attr(3, le(9_600_000, 8)), attr(8, vec![algorithm]), payee_attr(key)];
    let molecule = raw(ts, &base_attrs(1, &payee));
    let compressed = ar_encompress(&molecule);
    let signature = sign(hrp, &compressed, PAYEE_SECRET_KEY);
    let base = encode_string(hrp, 1, &compressed, &signature, Variant::Bech32m);
    let with = |compressed: &[u8], signature: &[u8]| encode_string(hrp, 1, compressed, signature, Variant::Bech32m);
    let small = |molecule: Vec<u8>| signed_string("fibt1", &molecule, PAYEE_SECRET_KEY);

    let mut out: Vec<(String, String)> = vec![];
    let mut push = |name: &str, string: String| out.push((name.to_string(), string));
    push("canonical", base.clone());
    push("upper case", base.to_uppercase());
    push("mixed case", format!("{}{}", &base[..20], base[20..].to_uppercase()));
    push("upper-case human-readable part only", format!("FIBT{}", &base[4..]));
    push("leading zero in the amount", encode_string("fibt0100000000", 1, &compressed, &signature, Variant::Bech32m));
    push("plain bech32 checksum", encode_string(hrp, 1, &compressed, &signature, Variant::Bech32));
    push("five trailing 0xff bytes in the stream", with(&[compressed.clone(), vec![0xff; 5]].concat(), &signature));
    push("five trailing zero bytes in the stream", with(&[compressed.clone(), vec![0; 5]].concat(), &signature));
    for bit in 0..8 {
        let mut stream = compressed.clone();
        let last = stream.len() - 1;
        stream[last] ^= 1 << bit;
        push(&format!("last stream byte, bit {bit} flipped"), with(&stream, &signature));
    }
    for cut in [1, 2, 5, 6, 7] {
        push(&format!("last {cut} stream bytes cut"), with(&compressed[..compressed.len() - cut], &signature));
    }
    push("hash algorithm byte 7 under the same signature", with(&ar_encompress(&raw(ts, &base_attrs(7, &payee))), &signature));
    push("hash algorithm byte 0 under the same signature", with(&ar_encompress(&raw(ts, &base_attrs(0, &payee))), &signature));
    {
        let order = secp030::constants::CURVE_ORDER;
        let s: [u8; 32] = signature[32..64].try_into().unwrap();
        let high = sub_be(&order, &s);
        let mut high_s = [&signature[..32], &high[..]].concat();
        high_s.push(signature[64] ^ 1);
        push("high-S signature", with(&compressed, &high_s));
        let flip = |recovery_id: u8| [&signature[..64], &[recovery_id][..]].concat();
        push("recovery id flipped, with a payee key", with(&compressed, &flip(signature[64] ^ 1)));
        push("recovery id 4", with(&compressed, &flip(4)));
        push("recovery id plus 2", with(&compressed, &flip(signature[64] + 2)));
    }
    push("unsigned flag with a signature tail", encode_string(hrp, 0, &compressed, &signature, Variant::Bech32m));
    push("flag 2 with a signature tail", encode_string(hrp, 2, &compressed, &signature, Variant::Bech32m));
    push("unsigned, as fiber writes it", encode_string(hrp, 0, &compressed, &[], Variant::Bech32m));
    let small_unsigned = ar_encompress(&raw(0, &[]));
    push("smallest unsigned, as fiber writes it", encode_string("fibd", 0, &small_unsigned, &[], Variant::Bech32m));
    push("signed flag and 103 zero groups", bech32::encode("fibd", u5s(&[[1].as_slice(), &[0; SIGNATURE_U5_SIZE - 1]].concat()), Variant::Bech32m).unwrap());
    push("signed flag and 104 zero groups", bech32::encode("fibd", u5s(&[[1].as_slice(), &[0; SIGNATURE_U5_SIZE]].concat()), Variant::Bech32m).unwrap());
    push("unsigned flag and 102 zero groups", bech32::encode("fibd", u5s(&[[0].as_slice(), &[0; SIGNATURE_U5_SIZE - 2]].concat()), Variant::Bech32m).unwrap());
    push("no data", bech32::encode("fibd", u5s(&[]), Variant::Bech32m).unwrap());
    {
        // A stream whose groups carry padding bits that are not zero: 1 byte is 2 groups, 2 bits of padding.
        let mut data = u5s(&[1]);
        let mut stream = groups(&compressed);
        let last = stream.len() - 1;
        let padding_bits = (stream.len() * 5) % 8;
        if padding_bits > 0 {
            stream[last] = bech32::u5::try_from_u8(stream[last].to_u8() | 1).unwrap();
            data.extend(stream);
            data.extend(groups(&signature));
            push("padding bits set", bech32::encode(hrp, data, Variant::Bech32m).unwrap());
        }
    }
    push("uncompressed payee key under the same signature", with(&ar_encompress(&raw(ts, &base_attrs(1, &payee_uncompressed))), &signature));
    push(
        "uncompressed payee key, signed over the bytes received",
        signed_string(hrp, &raw(ts, &base_attrs(1, &payee_uncompressed)), PAYEE_SECRET_KEY),
    );
    push("payee key of another signer", small(raw(5, &[payee_attr(&other)])));
    push("no payee key", small(raw(5, &[attr(0, le(1, 8))])));
    {
        let unsigned = raw(5, &[attr(0, le(1, 8))]);
        let stream = ar_encompress(&unsigned);
        let signature = sign("fibt1", &stream, PAYEE_SECRET_KEY);
        let flipped = [&signature[..64], &[signature[64] ^ 1][..]].concat();
        push("recovery id flipped, without a payee key", encode_string("fibt1", 1, &stream, &flipped, Variant::Bech32m));
        let other_bytes = ar_encompress(&raw(6, &[attr(0, le(1, 8))]));
        push(
            "signature over other bytes, without a payee key",
            encode_string("fibt1", 1, &stream, &sign("fibt1", &other_bytes, PAYEE_SECRET_KEY), Variant::Bech32m),
        );
    }
    push("duplicate expiry", small(raw(5, &[attr(0, le(1, 8)), attr(0, le(99_999_999_999, 8))])));
    push("duplicate payee key, another key second", small(raw(5, &[payee_attr(&payee), payee_attr(&other)])));
    push("payee key of 32 bytes", small(raw(5, &[payee_attr(&payee[1..])])));
    {
        let mut not_a_point = vec![0x02];
        not_a_point.extend([0xff; 32]);
        push("payee key not on the curve", small(raw(5, &[payee_attr(&not_a_point)])));
    }
    push("unknown attribute id 10", small(raw(5, &[attr(10, le(1, 8)), attr(0, le(1, 8))])));
    push("deprecated final htlc timeout", small(raw(5, &[attr(2, le(5, 8)), attr(0, le(1, 8))])));
    push("description of 700 bytes", small(raw(5, &[attr(1, table(&[mol_bytes(&[0x61; 700])]))])));
    push("description that is not utf-8", small(raw(5, &[attr(1, table(&[mol_bytes(&[0xff, 0xfe])]))])));
    push("fallback address that is not utf-8", small(raw(5, &[attr(4, table(&[mol_bytes(&[0xc0, 0x80])]))])));
    push("multi-path without a payment secret", small(raw(5, &[attr(5, table(&[mol_bytes(&[0x08])]))])));
    push("zero amount", signed_string("fibt0", &raw(5, &[attr(0, le(1, 8))]), PAYEE_SECRET_KEY));
    push(
        "amount past u128",
        signed_string("fibt340282366920938463463374607431768211456", &raw(5, &[]), PAYEE_SECRET_KEY),
    );
    push("unknown currency", signed_string("fibx5", &raw(5, &[]), PAYEE_SECRET_KEY));
    push("currency without its prefix", signed_string("fib5", &raw(5, &[]), PAYEE_SECRET_KEY));
    push(
        "udt script with hash type 9",
        small(raw(5, &[attr(6, table(&[table(&[vec![0xab; 32], vec![9], mol_bytes(&[1, 2])])]))])),
    );
    push(
        "udt script with an extra field",
        small(raw(5, &[attr(6, table(&[table(&[vec![0xab; 32], vec![1], mol_bytes(&[1, 2]), vec![0]])]))])),
    );
    push("extra field in the data table", small(table(&[le(5, 16), PAYMENT_HASH.to_vec(), dynvec(&[]), vec![1, 2, 3]])));
    push("trailing byte after the data", small([raw(5, &[]), vec![0]].concat()));
    push("expiry of 7 bytes", small(raw(5, &[attr(0, le(1, 7))])));
    push("payment secret of 31 bytes", small(raw(5, &[attr(9, vec![9; 31])])));
    {
        let fill = |length: usize| raw(5, &[attr(1, table(&[mol_bytes(&vec![0x61; length])]))]);
        let at_limit = fill(MAX_INVOICE_DATA_LENGTH - 88);
        assert_eq!(at_limit.len(), MAX_INVOICE_DATA_LENGTH);
        push("data of 16384 bytes", small(at_limit));
        push("data of 16385 bytes", small(fill(MAX_INVOICE_DATA_LENGTH - 87)));
    }
    {
        let algorithm = |byte: u8| raw(5, &[attr(0, le(1, 8)), attr(8, vec![byte])]);
        let stream = ar_encompress(&algorithm(0));
        let over_zero = sign("fibt1", &stream, PAYEE_SECRET_KEY);
        push("hash algorithm ckb hash", encode_string("fibt1", 1, &stream, &over_zero, Variant::Bech32m));
        push(
            "hash algorithm byte 7, signed over byte 0",
            encode_string("fibt1", 1, &ar_encompress(&algorithm(7)), &over_zero, Variant::Bech32m),
        );
        push("hash algorithm byte 7, signed over the bytes received", small(algorithm(7)));
    }
    out.into_iter()
        .map(|(name, string)| {
            let (fiber, error) = verdict(&string);
            VariantCase { name, string, fiber, error }
        })
        .collect()
}

/// `a - b` over 32 big-endian bytes, `a >= b`.
fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut value = a[i] as i16 - b[i] as i16 - borrow;
        borrow = i16::from(value < 0);
        if value < 0 {
            value += 256;
        }
        out[i] = value as u8;
    }
    out
}

fn assert_variant_coverage(cases: &[VariantCase]) {
    let names: BTreeSet<&str> = cases.iter().map(|case| case.name.as_str()).collect();
    assert_eq!(names.len(), cases.len(), "distinct variant names");
    let verdicts: BTreeSet<&str> = cases.iter().map(|case| case.fiber.as_str()).collect();
    assert_eq!(verdicts, BTreeSet::from(["accepted", "panicked", "refused", "rewritten"]), "every verdict fiber gives");
    assert_eq!(cases[0].fiber, "accepted", "the canonical variant is accepted as it is");
}

pub fn gen_invoice_vectors(out_path: &str) {
    let invoices = invoices();
    assert_invoice_coverage(&invoices);
    let variants = variants();
    assert_variant_coverage(&variants);
    let vectors = InvoiceVectors {
        fiber_ref: FIBER_REF.to_string(),
        payee_secret_key: hex::encode(PAYEE_SECRET_KEY),
        payee_public_key: hex::encode(public(PAYEE_SECRET_KEY).serialize()),
        invoices,
        coder: coder(),
        utf8: utf8(),
        variants,
    };
    let json = serde_json::to_string_pretty(&vectors).unwrap();
    std::fs::write(out_path, format!("{json}\n")).unwrap();
    println!("invoice vectors written to {out_path}");
}

// --- verify-invoices ---

#[derive(Deserialize)]
struct TsInvoiceCase {
    name: String,
    values: InvoiceValues,
    signature: String,
    string: String,
}

#[derive(Deserialize)]
struct TsInvoiceOutput {
    cases: Vec<TsInvoiceCase>,
}

pub fn verify_invoices(vectors_path: &str, ts_out_path: &str) {
    let vectors: InvoiceVectors = serde_json::from_str(&std::fs::read_to_string(vectors_path).unwrap()).unwrap();
    let written: TsInvoiceOutput = serde_json::from_str(&std::fs::read_to_string(ts_out_path).unwrap()).unwrap();
    match check_invoices(&vectors, &written) {
        Ok(verified) => println!("OK: {verified} strings the TS encoder wrote read by fiber's decoder as their values, and written back unchanged"),
        Err(failures) => {
            for failure in &failures {
                eprintln!("FAIL: {failure}");
            }
            std::process::exit(1);
        }
    }
}

fn check_invoices(vectors: &InvoiceVectors, written: &TsInvoiceOutput) -> Result<usize, Vec<String>> {
    let mut failures = Vec::new();
    let signed: Vec<&InvoiceCase> = vectors.invoices.iter().filter(|case| case.signature.is_some()).collect();
    for case in &signed {
        match written.cases.iter().find(|written| written.name == case.name) {
            None => failures.push(format!("{}: the TS side did not write this vector", case.name)),
            Some(written) if written.string != case.string => {
                failures.push(format!("{}: the TS string differs from the vector", case.name))
            }
            Some(_) => {}
        }
    }
    if written.cases.len() <= signed.len() {
        failures.push("the TS side wrote no string beyond the vectors".to_string());
    }
    let mut verified = 0;
    for case in &written.cases {
        let label = &case.name;
        let mut expected = unsigned_invoice(&case.values);
        let signature = hex::decode(&case.signature).unwrap();
        let recovery_id = RecoveryId::try_from(i32::from(signature[64])).unwrap();
        expected.signature = Some(InvoiceSignature(RecoverableSignature::from_compact(&signature[..64], recovery_id).unwrap()));
        match case.string.parse::<CkbInvoice>() {
            Err(err) => failures.push(format!("{label}: fiber refuses the string: {err}")),
            Ok(parsed) if parsed.to_string() != case.string => failures.push(format!("{label}: fiber writes the string back differently")),
            Ok(parsed) if parsed != expected => failures.push(format!("{label}: fiber reads other values than the TS side wrote")),
            Ok(_) => verified += 1,
        }
    }
    if failures.is_empty() {
        Ok(verified)
    } else {
        Err(failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> InvoiceVectors {
        serde_json::from_str(&std::fs::read_to_string("../vectors/invoice.json").unwrap()).unwrap()
    }

    fn ts_case(case: &InvoiceCase) -> Value {
        json!({ "name": case.name, "values": case.values, "signature": case.signature, "string": case.string })
    }

    /// What the TS side writes: every signed vector, plus one string the vectors do not hold.
    fn identity(vectors: &InvoiceVectors) -> Value {
        let mut cases: Vec<Value> = vectors.invoices.iter().filter(|case| case.signature.is_some()).map(ts_case).collect();
        let mut extra = ts_case(vectors.invoices.iter().find(|case| case.name == "min signed").unwrap());
        extra["name"] = json!("extra");
        cases.push(extra);
        json!({ "cases": cases })
    }

    fn check(written: Value) -> Result<usize, Vec<String>> {
        check_invoices(&vectors(), &serde_json::from_value(written).unwrap())
    }

    fn assert_refused(written: Value, reason: &str) {
        let failures = check(written).unwrap_err();
        assert!(failures.iter().any(|failure| failure.contains(reason)), "{failures:?} does not mention {reason}");
    }

    #[test]
    fn accepts_every_vector_and_a_string_beyond_them() {
        let vectors = vectors();
        let signed = vectors.invoices.iter().filter(|case| case.signature.is_some()).count();
        assert_eq!(check(identity(&vectors)), Ok(signed + 1));
    }

    #[test]
    fn refuses_a_missing_vector() {
        let mut written = identity(&vectors());
        written["cases"].as_array_mut().unwrap().remove(0);
        assert_refused(written, "did not write this vector");
    }

    #[test]
    fn refuses_nothing_beyond_the_vectors() {
        let mut written = identity(&vectors());
        written["cases"].as_array_mut().unwrap().pop();
        assert_refused(written, "no string beyond the vectors");
    }

    #[test]
    fn refuses_a_vector_written_differently() {
        let mut written = identity(&vectors());
        let string = written["cases"][0]["string"].as_str().unwrap().to_uppercase();
        written["cases"][0]["string"] = json!(string);
        assert_refused(written, "differs from the vector");
    }

    #[test]
    fn refuses_a_string_fiber_rewrites() {
        let mut written = identity(&vectors());
        let last = written["cases"].as_array().unwrap().len() - 1;
        let string = written["cases"][last]["string"].as_str().unwrap().to_uppercase();
        written["cases"][last]["string"] = json!(string);
        assert_refused(written, "writes the string back differently");
    }

    #[test]
    fn refuses_a_string_fiber_refuses() {
        let mut written = identity(&vectors());
        let last = written["cases"].as_array().unwrap().len() - 1;
        let mut string = written["cases"][last]["string"].as_str().unwrap().to_string();
        string.pop();
        string.push('q');
        written["cases"][last]["string"] = json!(string);
        assert_refused(written, "fiber refuses the string");
    }

    #[test]
    fn refuses_values_other_than_the_string_carries() {
        let mut written = identity(&vectors());
        let last = written["cases"].as_array().unwrap().len() - 1;
        written["cases"][last]["values"]["timestamp"] = json!("6");
        assert_refused(written, "other values");
    }

    #[test]
    fn ports_the_coder_round_trip_and_its_limit() {
        for case in &vectors().coder.compress {
            let data = hex::decode(&case.data).unwrap();
            let decompressed = ar_decompress_with_limit(&hex::decode(&case.compressed).unwrap(), MAX_INVOICE_DATA_LENGTH);
            if data.len() > MAX_INVOICE_DATA_LENGTH {
                assert_eq!(decompressed, None, "{}", case.name);
            } else {
                assert_eq!(decompressed, Some(data), "{}", case.name);
            }
        }
    }
}
