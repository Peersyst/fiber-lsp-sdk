use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ckb_jsonrpc_types::{
    CellDep, CellInput, CellOutput, DepType, JsonBytes, OutPoint, Script, Transaction, Uint32, Uint64,
};
use ckb_types::packed::{BytesOpt, WitnessArgs};
use ckb_types::prelude::*;
use ckb_types::H256;
use fiber_types::{FeatureVector, InvoiceSignature};
use fiber_json_types::{
    AbandonChannelParams, Attribute, AwaitingChannelReadyFlags, AwaitingTxSignaturesFlags, Channel, ChannelState,
    CkbInvoice, CkbInvoiceStatus, CloseFlags, CollaboratingFundingTxFlags, Currency, GetInvoiceResult,
    GetPaymentCommandParams, GetPaymentCommandResult, Hash256, HashAlgorithm, Htlc, InboundTlcStatus,
    InvoiceData, InvoiceParams, InvoiceResult, ListChannelsParams, ListChannelsResult, NegotiatingFundingFlags,
    NewInvoiceParams, OpenChannelWithExternalFundingParams, OpenChannelWithExternalFundingResult,
    OutboundTlcStatus, PaymentCustomRecords, PaymentStatus, Pubkey, SendPaymentCommandParams,
    SettleInvoiceParams, SettleInvoiceResult, ShuttingDownFlags, SigningCommitmentFlags,
    SubmitSignedFundingTxParams, SubmitSignedFundingTxResult, TlcStatus,
};
use jsonrpsee_types::error::CALL_EXECUTION_FAILED_CODE;
use jsonrpsee_types::{ErrorCode, ErrorObject, Id, Params, Request, Response, ResponsePayload};
use secp030::ecdsa::{RecoverableSignature, RecoveryId};
use secp030::{Message, SECP256K1};
use secp256k1::SecretKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{blake160, blake2b_256, packed_out_point, packed_script, pubkey_of, OutPointVector, ScriptVector, FIBER_REF};

const JSONRPSEE_VERSION: &str = "0.25.1";
// Literals at crates/fiber-lib/src/rpc/middleware.rs:188-228; the message suffix names the Biscuit limit hit.
const UNAUTHORIZED_CODE: i32 = -32999;
const UNAUTHORIZED_MESSAGE: &str = "Unauthorized";
const UNAUTHORIZED_TIMEOUT_MESSAGE: &str = "Unauthorized: Biscuit authorization timed out";
const SECP256K1_BLAKE160_CODE_HASH: &str = "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
const SECP256K1_SIGNATURE_LEN: usize = 65;

// --- the vector file ---

#[derive(Serialize, Deserialize)]
pub struct RpcVectors {
    fiber_ref: String,
    jsonrpsee_version: String,
    envelopes: EnvelopeVectors,
    methods: MethodVectors,
}

#[derive(Serialize, Deserialize)]
struct EnvelopeVectors {
    request: RequestEnvelope,
    results: Vec<ResultEnvelope>,
    errors: Vec<ErrorEnvelope>,
}

#[derive(Serialize, Deserialize)]
struct RequestEnvelope {
    id: u64,
    method: String,
    params: Value,
    text: String,
}

#[derive(Serialize, Deserialize)]
struct ResultEnvelope {
    name: String,
    id: u64,
    result: Value,
    text: String,
}

#[derive(Serialize, Deserialize)]
struct ErrorEnvelope {
    name: String,
    id: Value,
    code: i32,
    message: String,
    data: Value,
    text: String,
}

#[derive(Serialize, Deserialize)]
struct MethodVectors {
    open_channel_with_external_funding: MethodCases,
    submit_signed_funding_tx: MethodCases,
    abandon_channel: MethodCases,
    list_channels: MethodCases,
    new_invoice: MethodCases,
    get_invoice: MethodCases,
    settle_invoice: MethodCases,
    cancel_invoice: MethodCases,
    send_payment: MethodCases,
    get_payment: MethodCases,
}

#[derive(Serialize, Deserialize)]
struct MethodCases {
    params: Vec<Case>,
    results: Vec<Case>,
}

#[derive(Serialize, Deserialize)]
struct Case {
    name: String,
    values: Value,
    json: Value,
}

fn case<V: Serialize, J: Serialize>(name: &str, values: &V, json: &J) -> Case {
    Case {
        name: name.to_string(),
        values: serde_json::to_value(values).unwrap(),
        json: serde_json::to_value(json).unwrap(),
    }
}

// --- the fixed values, in the harness's forms ---

#[derive(Serialize, Clone)]
struct CellDepValues {
    out_point: OutPointVector,
    dep_type: String,
}

#[derive(Serialize, Clone)]
struct CellInputValues {
    since: String,
    previous_output: OutPointVector,
}

#[derive(Serialize, Clone)]
struct CellOutputValues {
    capacity: String,
    lock: ScriptVector,
    #[serde(rename = "type")]
    type_: Option<ScriptVector>,
}

#[derive(Serialize, Clone)]
struct TransactionValues {
    version: u32,
    cell_deps: Vec<CellDepValues>,
    header_deps: Vec<String>,
    inputs: Vec<CellInputValues>,
    outputs: Vec<CellOutputValues>,
    outputs_data: Vec<String>,
    witnesses: Vec<String>,
}

#[derive(Serialize, Clone)]
struct StateValues {
    name: String,
    flags: Vec<String>,
}

#[derive(Serialize, Clone)]
struct HtlcStatusValues {
    direction: String,
    status: String,
}

#[derive(Serialize, Clone)]
struct HtlcValues {
    id: String,
    amount: String,
    payment_hash: String,
    expiry: String,
    forwarding_channel_id: Option<String>,
    forwarding_tlc_id: Option<String>,
    status: HtlcStatusValues,
}

#[derive(Serialize, Clone)]
struct ChannelValues {
    channel_id: String,
    is_public: bool,
    is_acceptor: bool,
    is_one_way: bool,
    channel_outpoint: Option<OutPointVector>,
    pubkey: String,
    funding_udt_type_script: Option<ScriptVector>,
    state: StateValues,
    local_balance: String,
    offered_tlc_balance: String,
    remote_balance: String,
    received_tlc_balance: String,
    pending_tlcs: Vec<HtlcValues>,
    latest_commitment_transaction_hash: Option<String>,
    created_at: String,
    enabled: bool,
    tlc_expiry_delta: String,
    tlc_fee_proportional_millionths: String,
    shutdown_transaction_hash: Option<String>,
    failure_detail: Option<String>,
}

#[derive(Serialize, Clone)]
struct AttributeValues {
    name: String,
    value: Value,
}

#[derive(Serialize, Clone)]
struct InvoiceDataValues {
    timestamp: String,
    payment_hash: String,
    attrs: Vec<AttributeValues>,
}

#[derive(Serialize, Clone)]
struct InvoiceValues {
    currency: String,
    amount: Option<String>,
    signature: Option<String>,
    data: InvoiceDataValues,
}

#[derive(Serialize, Clone)]
struct CustomRecordValues {
    key: u32,
    data: String,
}

#[derive(Serialize, Clone)]
struct PaymentValues {
    payment_hash: String,
    status: String,
    created_at: String,
    last_updated_at: String,
    failed_error: Option<String>,
    fee: String,
    custom_records: Option<Vec<CustomRecordValues>>,
}

#[derive(Serialize)]
struct OpenChannelParamsValues {
    pubkey: String,
    funding_amount: String,
    public: bool,
    shutdown_script: ScriptVector,
    funding_lock_script: ScriptVector,
}

#[derive(Serialize)]
struct SubmitSignedFundingTxParamsValues {
    channel_id: String,
    signed_funding_tx: TransactionValues,
}

#[derive(Serialize)]
struct ChannelIdParamsValues {
    channel_id: String,
}

#[derive(Serialize)]
struct ListChannelsParamsValues {
    include_closed: Option<bool>,
    only_pending: Option<bool>,
}

#[derive(Serialize)]
struct NewInvoiceParamsValues {
    amount: String,
    currency: String,
    payment_hash: String,
    hash_algorithm: String,
    expiry: String,
    description: Option<String>,
}

#[derive(Serialize)]
struct PaymentHashParamsValues {
    payment_hash: String,
}

#[derive(Serialize)]
struct SettleInvoiceParamsValues {
    payment_hash: String,
    payment_preimage: String,
}

#[derive(Serialize)]
struct SendPaymentParamsValues {
    invoice: String,
    max_fee_amount: String,
    dry_run: bool,
}

#[derive(Serialize)]
struct OpenChannelResultValues {
    channel_id: String,
    unsigned_funding_tx: TransactionValues,
}

#[derive(Serialize)]
struct SubmitSignedFundingTxResultValues {
    channel_id: String,
    funding_tx_hash: String,
}

#[derive(Serialize)]
struct ListChannelsResultValues {
    channels: Vec<ChannelValues>,
}

#[derive(Serialize)]
struct InvoiceResultValues {
    invoice_address: String,
    invoice: InvoiceValues,
}

#[derive(Serialize)]
struct GetInvoiceResultValues {
    invoice_address: String,
    invoice: InvoiceValues,
    status: String,
}

// --- from the harness's forms to fiber's types ---

fn bytes_of<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

fn hash256(hex_str: &str) -> Hash256 {
    Hash256(bytes_of(hex_str))
}

fn h256(hex_str: &str) -> H256 {
    H256(bytes_of(hex_str))
}

fn pubkey(hex_str: &str) -> Pubkey {
    Pubkey(bytes_of(hex_str))
}

fn u64_of(decimal: &str) -> u64 {
    decimal.parse().unwrap()
}

fn u128_of(decimal: &str) -> u128 {
    decimal.parse().unwrap()
}

fn json_bytes(hex_str: &str) -> JsonBytes {
    JsonBytes::from_vec(hex::decode(hex_str).unwrap())
}

fn json_script(script: &ScriptVector) -> Script {
    packed_script(script).into()
}

fn json_out_point(out_point: &OutPointVector) -> OutPoint {
    packed_out_point(out_point).into()
}

fn json_transaction(tx: &TransactionValues) -> Transaction {
    Transaction {
        version: Uint32::from(tx.version),
        cell_deps: tx
            .cell_deps
            .iter()
            .map(|dep| CellDep {
                out_point: json_out_point(&dep.out_point),
                dep_type: match dep.dep_type.as_str() {
                    "code" => DepType::Code,
                    "dep_group" => DepType::DepGroup,
                    other => panic!("unknown dep_type {other}"),
                },
            })
            .collect(),
        header_deps: tx.header_deps.iter().map(|hash| h256(hash)).collect(),
        inputs: tx
            .inputs
            .iter()
            .map(|input| CellInput {
                since: Uint64::from(u64_of(&input.since)),
                previous_output: json_out_point(&input.previous_output),
            })
            .collect(),
        outputs: tx
            .outputs
            .iter()
            .map(|output| CellOutput {
                capacity: Uint64::from(u64_of(&output.capacity)),
                lock: json_script(&output.lock),
                type_: output.type_.as_ref().map(json_script),
            })
            .collect(),
        outputs_data: tx.outputs_data.iter().map(|data| json_bytes(data)).collect(),
        witnesses: tx.witnesses.iter().map(|witness| json_bytes(witness)).collect(),
    }
}

// --- every value fiber has, which the vectors must cover ---
// Each list sits next to an exhaustive match, so a variant a fiber release adds fails to compile.

fn invoice_statuses() -> Vec<CkbInvoiceStatus> {
    use CkbInvoiceStatus::*;
    let all = vec![Open, Cancelled, Expired, Received, Paid];
    for status in &all {
        match status {
            Open | Cancelled | Expired | Received | Paid => {}
        }
    }
    all
}

fn payment_statuses() -> Vec<PaymentStatus> {
    use PaymentStatus::*;
    let all = vec![Created, Inflight, Success, Failed];
    for status in &all {
        match status {
            Created | Inflight | Success | Failed => {}
        }
    }
    all
}

fn currencies() -> Vec<Currency> {
    use Currency::*;
    let all = vec![Fibb, Fibt, Fibd];
    for currency in &all {
        match currency {
            Fibb | Fibt | Fibd => {}
        }
    }
    all
}

fn hash_algorithms() -> Vec<HashAlgorithm> {
    use HashAlgorithm::*;
    let all = vec![CkbHash, Sha256];
    for algorithm in &all {
        match algorithm {
            CkbHash | Sha256 => {}
        }
    }
    all
}

fn channel_states() -> Vec<ChannelState> {
    use ChannelState::*;
    let all = vec![
        NegotiatingFunding(NegotiatingFundingFlags(0)),
        CollaboratingFundingTx(CollaboratingFundingTxFlags(0)),
        SigningCommitment(SigningCommitmentFlags(0)),
        AwaitingTxSignatures(AwaitingTxSignaturesFlags(0)),
        AwaitingChannelReady(AwaitingChannelReadyFlags(0)),
        ChannelReady,
        ShuttingDown(ShuttingDownFlags(0)),
        Closed(CloseFlags(0)),
        Stale,
    ];
    for state in &all {
        match state {
            NegotiatingFunding(_) | CollaboratingFundingTx(_) | SigningCommitment(_) | AwaitingTxSignatures(_)
            | AwaitingChannelReady(_) | ChannelReady | ShuttingDown(_) | Closed(_) | Stale => {}
        }
    }
    all
}

fn close_flags() -> Vec<String> {
    emitted_flags(&serde_json::to_value(ChannelState::Closed(CloseFlags(u32::MAX))).unwrap())
}

fn name_of<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value).unwrap().as_str().unwrap().to_string()
}

fn state_name_of(state: &ChannelState) -> String {
    serde_json::to_value(state).unwrap()["state_name"].as_str().unwrap().to_string()
}

fn named<T: Serialize + Copy>(all: &[T], name: &str) -> T {
    *all.iter().find(|value| name_of(*value) == name).unwrap_or_else(|| panic!("fiber has no {name}"))
}

fn emitted_flags(state: &Value) -> Vec<String> {
    state
        .get("state_flags")
        .map(|value| value.as_str().unwrap().split('|').filter(|flag| !flag.is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}

fn assert_coverage(methods: &MethodVectors) {
    let values = |cases: &[&MethodCases]| -> Vec<Value> {
        cases.iter().flat_map(|method| method.results.iter().map(|case| case.values.clone())).collect()
    };
    let set = |names: Vec<String>| names.into_iter().collect::<BTreeSet<String>>();
    let channels: Vec<Value> = values(&[&methods.list_channels])
        .iter()
        .flat_map(|result| result["channels"].as_array().unwrap().clone())
        .collect();
    let text = |value: &Value| value.as_str().unwrap().to_string();
    assert_eq!(
        set(channels.iter().map(|channel| text(&channel["state"]["name"])).collect()),
        set(channel_states().iter().map(state_name_of).collect()),
        "channel states"
    );
    assert_eq!(
        set(channels
            .iter()
            .filter(|channel| channel["state"]["name"] == "Closed")
            .flat_map(|channel| channel["state"]["flags"].as_array().unwrap().iter().map(text).collect::<Vec<_>>())
            .collect()),
        set(close_flags()),
        "close flags"
    );
    assert_eq!(
        set(values(&[&methods.get_invoice, &methods.cancel_invoice]).iter().map(|result| text(&result["status"])).collect()),
        set(invoice_statuses().iter().map(name_of).collect()),
        "invoice statuses"
    );
    assert_eq!(
        set(values(&[&methods.send_payment, &methods.get_payment]).iter().map(|result| text(&result["status"])).collect()),
        set(payment_statuses().iter().map(name_of).collect()),
        "payment statuses"
    );
    let invoice_params: Vec<Value> = methods.new_invoice.params.iter().map(|case| case.values.clone()).collect();
    assert_eq!(
        set(invoice_params.iter().map(|params| text(&params["currency"])).collect()),
        set(currencies().iter().map(name_of).collect()),
        "currencies"
    );
    assert_eq!(
        set(invoice_params.iter().map(|params| text(&params["hash_algorithm"])).collect()),
        set(hash_algorithms().iter().map(name_of).collect()),
        "hash algorithms"
    );
}

fn tlc_status(status: &HtlcStatusValues) -> TlcStatus {
    match (status.direction.as_str(), status.status.as_str()) {
        ("Outbound", "LocalAnnounced") => TlcStatus::Outbound(OutboundTlcStatus::LocalAnnounced),
        ("Outbound", "Committed") => TlcStatus::Outbound(OutboundTlcStatus::Committed),
        ("Outbound", "RemoteRemoved") => TlcStatus::Outbound(OutboundTlcStatus::RemoteRemoved),
        ("Inbound", "RemoteAnnounced") => TlcStatus::Inbound(InboundTlcStatus::RemoteAnnounced),
        ("Inbound", "Committed") => TlcStatus::Inbound(InboundTlcStatus::Committed),
        ("Inbound", "LocalRemoved") => TlcStatus::Inbound(InboundTlcStatus::LocalRemoved),
        (direction, status) => panic!("unknown tlc status {direction}/{status}"),
    }
}

fn attribute(attr: &AttributeValues) -> Attribute {
    let text = || attr.value.as_str().unwrap().to_string();
    match attr.name.as_str() {
        "expiry_time" => Attribute::ExpiryTime(Duration::from_secs(u64_of(&text()))),
        "final_htlc_minimum_expiry_delta" => Attribute::FinalHtlcMinimumExpiryDelta(u64_of(&text())),
        "description" => Attribute::Description(text()),
        "udt_script" => Attribute::UdtScript(format!("0x{}", text())),
        "payee_public_key" => Attribute::PayeePublicKey(pubkey(&text())),
        "hash_algorithm" => Attribute::HashAlgorithm(named(&hash_algorithms(), &text())),
        "feature" => Attribute::Feature(
            attr.value.as_array().unwrap().iter().map(|flag| flag.as_str().unwrap().to_string()).collect(),
        ),
        other => panic!("unknown invoice attribute {other}"),
    }
}

/// Fiber's `InvoiceSignature` form: the 65 bytes as 104 five-bit values, one per byte, in hex.
fn invoice_signature(hex_str: &str) -> String {
    let bytes: [u8; 65] = bytes_of(hex_str);
    let recovery_id = RecoveryId::try_from(i32::from(bytes[64])).unwrap();
    let signature = RecoverableSignature::from_compact(&bytes[..64], recovery_id).unwrap();
    name_of(&InvoiceSignature(signature))
}

fn json_invoice(invoice: &InvoiceValues) -> CkbInvoice {
    CkbInvoice {
        currency: named(&currencies(), &invoice.currency),
        amount: invoice.amount.as_deref().map(u128_of),
        signature: invoice.signature.as_deref().map(invoice_signature),
        data: InvoiceData {
            timestamp: u128_of(&invoice.data.timestamp),
            payment_hash: hash256(&invoice.data.payment_hash),
            attrs: invoice.data.attrs.iter().map(attribute).collect(),
        },
    }
}

fn json_payment(payment: &PaymentValues) -> GetPaymentCommandResult {
    GetPaymentCommandResult {
        payment_hash: hash256(&payment.payment_hash),
        status: named(&payment_statuses(), &payment.status),
        created_at: u64_of(&payment.created_at),
        last_updated_at: u64_of(&payment.last_updated_at),
        failed_error: payment.failed_error.clone(),
        fee: u128_of(&payment.fee),
        custom_records: payment.custom_records.as_ref().map(|records| PaymentCustomRecords {
            data: records.iter().map(|record| (record.key, hex::decode(&record.data).unwrap())).collect(),
        }),
        #[cfg(debug_assertions)]
        routers: vec![],
    }
}

/// Flags are hand-listed: a composite leaks when bits overlap (`OUR_INIT_SENT` emits `OUR_INIT_SENT|INIT_SENT`).
fn state(fiber: ChannelState, name: &str, flags: &[&str]) -> (ChannelState, StateValues) {
    let json = serde_json::to_value(fiber).unwrap();
    assert_eq!(json["state_name"], name, "state name");
    assert_eq!(emitted_flags(&json), flags, "flags fiber emits for {name}");
    (fiber, StateValues { name: name.to_string(), flags: flags.iter().map(|flag| flag.to_string()).collect() })
}

fn json_channel(values: &ChannelValues, state: ChannelState) -> Channel {
    Channel {
        channel_id: hash256(&values.channel_id),
        is_public: values.is_public,
        is_acceptor: values.is_acceptor,
        is_one_way: values.is_one_way,
        channel_outpoint: values.channel_outpoint.as_ref().map(packed_out_point),
        pubkey: pubkey(&values.pubkey),
        funding_udt_type_script: values.funding_udt_type_script.as_ref().map(json_script),
        state,
        local_balance: u128_of(&values.local_balance),
        offered_tlc_balance: u128_of(&values.offered_tlc_balance),
        remote_balance: u128_of(&values.remote_balance),
        received_tlc_balance: u128_of(&values.received_tlc_balance),
        pending_tlcs: values
            .pending_tlcs
            .iter()
            .map(|tlc| Htlc {
                id: u64_of(&tlc.id),
                amount: u128_of(&tlc.amount),
                payment_hash: hash256(&tlc.payment_hash),
                expiry: u64_of(&tlc.expiry),
                forwarding_channel_id: tlc.forwarding_channel_id.as_deref().map(hash256),
                forwarding_tlc_id: tlc.forwarding_tlc_id.as_deref().map(u64_of),
                status: tlc_status(&tlc.status),
            })
            .collect(),
        latest_commitment_transaction_hash: values.latest_commitment_transaction_hash.as_deref().map(h256),
        created_at: u64_of(&values.created_at),
        enabled: values.enabled,
        tlc_expiry_delta: u64_of(&values.tlc_expiry_delta),
        tlc_fee_proportional_millionths: u128_of(&values.tlc_fee_proportional_millionths),
        shutdown_transaction_hash: values.shutdown_transaction_hash.as_deref().map(h256),
        failure_detail: values.failure_detail.clone(),
    }
}

// --- fixtures ---

fn hash_hex(label: &str) -> String {
    hex::encode(blake2b_256(label.as_bytes()))
}

fn pubkey_hex(label: &str) -> String {
    let seckey = SecretKey::from_slice(&blake2b_256(label.as_bytes())).unwrap();
    hex::encode(pubkey_of(&seckey).serialize())
}

fn sighash_script(label: &str) -> ScriptVector {
    ScriptVector {
        code_hash: SECP256K1_BLAKE160_CODE_HASH.to_string(),
        hash_type: "type".to_string(),
        args: hex::encode(blake160(label.as_bytes())),
    }
}

fn udt_script() -> ScriptVector {
    ScriptVector { code_hash: hash_hex("udt code hash"), hash_type: "type".to_string(), args: hash_hex("udt args") }
}

fn out_point(label: &str, index: u32) -> OutPointVector {
    OutPointVector { tx_hash: hash_hex(label), index }
}

fn witness_args(lock: [u8; SECP256K1_SIGNATURE_LEN]) -> String {
    let lock = BytesOpt::new_builder().set(Some(lock.to_vec().pack())).build();
    hex::encode(WitnessArgs::new_builder().lock(lock).build().as_bytes())
}

/// As crates/fiber-lib/src/ckb/funding/funding_tx.rs:533-575 builds it; `signed` only fills the first witness.
fn funding_tx(udt: bool, signed: bool) -> TransactionValues {
    let user_lock = sighash_script("user lock args");
    let funding_lock = ScriptVector {
        code_hash: hash_hex("funding lock code hash"),
        hash_type: "data1".to_string(),
        args: hex::encode(blake160(b"aggregated funding pubkey")),
    };
    let signature = if signed { [0x5a; SECP256K1_SIGNATURE_LEN] } else { [0; SECP256K1_SIGNATURE_LEN] };
    let mut tx = TransactionValues {
        version: 0,
        cell_deps: vec![CellDepValues { out_point: out_point("secp256k1 dep group", 0), dep_type: "dep_group".to_string() }],
        header_deps: vec![],
        inputs: vec![CellInputValues { since: "0".to_string(), previous_output: out_point("user cell one", 1) }],
        outputs: vec![
            CellOutputValues { capacity: "6100000000".to_string(), lock: funding_lock, type_: None },
            CellOutputValues { capacity: "9900000000".to_string(), lock: user_lock.clone(), type_: None },
        ],
        outputs_data: vec![String::new(), String::new()],
        witnesses: vec![witness_args(signature)],
    };
    if udt {
        tx.cell_deps.push(CellDepValues { out_point: out_point("udt code cell", 2), dep_type: "code".to_string() });
        tx.header_deps.push(hash_hex("header dep"));
        tx.inputs.push(CellInputValues { since: u64::MAX.to_string(), previous_output: out_point("user cell two", 0) });
        tx.outputs[0].capacity = "14200000000".to_string();
        tx.outputs[0].type_ = Some(udt_script());
        tx.outputs.insert(
            1,
            CellOutputValues { capacity: "14200000000".to_string(), lock: user_lock, type_: Some(udt_script()) },
        );
        tx.outputs_data = vec![
            hex::encode(1_000_000u128.to_le_bytes()),
            hex::encode(u128::MAX.to_le_bytes()),
            String::new(),
        ];
        tx.witnesses.push(String::new());
    }
    tx
}

fn base_channel(label: &str) -> ChannelValues {
    ChannelValues {
        channel_id: hash_hex(&format!("channel {label}")),
        is_public: true,
        is_acceptor: false,
        is_one_way: false,
        channel_outpoint: Some(out_point(&format!("funding tx {label}"), 0)),
        pubkey: pubkey_hex("peer node"),
        funding_udt_type_script: None,
        state: StateValues { name: String::new(), flags: vec![] },
        local_balance: "5000000000".to_string(),
        offered_tlc_balance: "0".to_string(),
        remote_balance: "1000000000".to_string(),
        received_tlc_balance: "0".to_string(),
        pending_tlcs: vec![],
        latest_commitment_transaction_hash: Some(hash_hex(&format!("commitment tx {label}"))),
        created_at: "1726000000000".to_string(),
        enabled: true,
        tlc_expiry_delta: "86400000".to_string(),
        tlc_fee_proportional_millionths: "1000".to_string(),
        shutdown_transaction_hash: None,
        failure_detail: None,
    }
}

/// What `only_pending` synthesizes for an unstored opening (crates/fiber-lib/src/rpc/channel.rs:387-468).
fn synthetic_channel(label: &str) -> ChannelValues {
    let mut channel = base_channel(label);
    channel.is_public = false;
    channel.channel_outpoint = None;
    channel.remote_balance = "0".to_string();
    channel.latest_commitment_transaction_hash = None;
    channel.enabled = false;
    channel.tlc_expiry_delta = "0".to_string();
    channel.tlc_fee_proportional_millionths = "0".to_string();
    channel
}

fn channel(mut values: ChannelValues, state: (ChannelState, StateValues)) -> (ChannelValues, Channel) {
    values.state = state.1;
    let json = json_channel(&values, state.0);
    (values, json)
}

fn list_channels_case(name: &str, channels: Vec<(ChannelValues, Channel)>) -> Case {
    let (values, json): (Vec<_>, Vec<_>) = channels.into_iter().unzip();
    case(name, &ListChannelsResultValues { channels: values }, &ListChannelsResult { channels: json })
}

fn open_channels() -> Vec<(ChannelValues, Channel)> {
    let mut ready = base_channel("ready");
    ready.received_tlc_balance = "150000000".to_string();
    ready.pending_tlcs = vec![
        HtlcValues {
            id: "3".to_string(),
            amount: "250000000".to_string(),
            payment_hash: hash_hex("tlc three"),
            expiry: "1726003600000".to_string(),
            forwarding_channel_id: Some(hash_hex("channel forwarding")),
            forwarding_tlc_id: Some("11".to_string()),
            status: HtlcStatusValues { direction: "Outbound".to_string(), status: "Committed".to_string() },
        },
        HtlcValues {
            id: "0".to_string(),
            amount: "150000000".to_string(),
            payment_hash: hash_hex("tlc zero"),
            expiry: "1726007200000".to_string(),
            forwarding_channel_id: None,
            forwarding_tlc_id: None,
            status: HtlcStatusValues { direction: "Inbound".to_string(), status: "RemoteAnnounced".to_string() },
        },
    ];
    let mut udt = base_channel("udt");
    udt.is_acceptor = true;
    udt.is_one_way = true;
    udt.funding_udt_type_script = Some(udt_script());
    udt.local_balance = u128::MAX.to_string();
    udt.offered_tlc_balance = u128::MAX.to_string();
    udt.tlc_fee_proportional_millionths = u128::MAX.to_string();
    let shutting_down = base_channel("shutting down");
    vec![
        channel(ready, state(ChannelState::ChannelReady, "ChannelReady", &[])),
        channel(udt, state(ChannelState::ChannelReady, "ChannelReady", &[])),
        channel(
            shutting_down,
            state(
                ChannelState::ShuttingDown(ShuttingDownFlags(ShuttingDownFlags::AWAITING_PENDING_TLCS)),
                "ShuttingDown",
                &["OUR_SHUTDOWN_SENT", "THEIR_SHUTDOWN_SENT", "AWAITING_PENDING_TLCS"],
            ),
        ),
    ]
}

fn pending_channels() -> Vec<(ChannelValues, Channel)> {
    let mut aborted = synthetic_channel("funding aborted");
    aborted.failure_detail = Some("funding transaction not submitted within the timeout".to_string());
    // A settled abandon fails the open record with this literal (crates/fiber-lib/src/fiber/network.rs:1733).
    let mut abandoned = synthetic_channel("abandoned");
    abandoned.failure_detail = Some("Channel was abandoned".to_string());
    // ABANDONED is never synthesized: only a stored actor state carries it.
    let mut abandoning = base_channel("abandoning");
    abandoning.channel_outpoint = None;
    abandoning.latest_commitment_transaction_hash = None;
    vec![
        channel(
            synthetic_channel("waiting for the peer"),
            state(
                ChannelState::NegotiatingFunding(NegotiatingFundingFlags(NegotiatingFundingFlags::OUR_INIT_SENT)),
                "NegotiatingFunding",
                &["OUR_INIT_SENT", "INIT_SENT"],
            ),
        ),
        channel(
            base_channel("awaiting external funding"),
            state(
                ChannelState::NegotiatingFunding(NegotiatingFundingFlags(
                    NegotiatingFundingFlags::INIT_SENT | NegotiatingFundingFlags::AWAITING_EXTERNAL_FUNDING,
                )),
                "NegotiatingFunding",
                &["OUR_INIT_SENT", "THEIR_INIT_SENT", "INIT_SENT", "AWAITING_EXTERNAL_FUNDING"],
            ),
        ),
        channel(
            base_channel("just created"),
            state(ChannelState::NegotiatingFunding(NegotiatingFundingFlags(0)), "NegotiatingFunding", &[]),
        ),
        channel(
            base_channel("collaborating"),
            state(
                ChannelState::CollaboratingFundingTx(CollaboratingFundingTxFlags(
                    CollaboratingFundingTxFlags::COLLABORATION_COMPLETED,
                )),
                "CollaboratingFundingTx",
                &["OUR_TX_COMPLETE_SENT", "THEIR_TX_COMPLETE_SENT", "COLLABORATION_COMPLETED"],
            ),
        ),
        channel(
            base_channel("signing"),
            state(
                ChannelState::SigningCommitment(SigningCommitmentFlags(SigningCommitmentFlags::OUR_COMMITMENT_SIGNED_SENT)),
                "SigningCommitment",
                &["OUR_COMMITMENT_SIGNED_SENT", "COMMITMENT_SIGNED_SENT"],
            ),
        ),
        channel(
            base_channel("awaiting signatures"),
            state(
                ChannelState::AwaitingTxSignatures(AwaitingTxSignaturesFlags(
                    AwaitingTxSignaturesFlags::THEIR_TX_SIGNATURES_SENT,
                )),
                "AwaitingTxSignatures",
                &["THEIR_TX_SIGNATURES_SENT", "TX_SIGNATURES_SENT"],
            ),
        ),
        channel(
            base_channel("awaiting ready"),
            state(
                ChannelState::AwaitingChannelReady(AwaitingChannelReadyFlags(AwaitingChannelReadyFlags::CHANNEL_READY)),
                "AwaitingChannelReady",
                &["OUR_CHANNEL_READY", "THEIR_CHANNEL_READY", "CHANNEL_READY"],
            ),
        ),
        channel(base_channel("stale"), state(ChannelState::Stale, "Stale", &[])),
        channel(
            aborted,
            state(ChannelState::Closed(CloseFlags(CloseFlags::FUNDING_ABORTED)), "Closed", &["FUNDING_ABORTED"]),
        ),
        channel(
            abandoned,
            state(ChannelState::Closed(CloseFlags(CloseFlags::FUNDING_ABORTED)), "Closed", &["FUNDING_ABORTED"]),
        ),
        channel(abandoning, state(ChannelState::Closed(CloseFlags(CloseFlags::ABANDONED)), "Closed", &["ABANDONED"])),
    ]
}

fn closed_channels() -> Vec<(ChannelValues, Channel)> {
    let mut cooperative = base_channel("cooperative close");
    cooperative.shutdown_transaction_hash = Some(hash_hex("shutdown tx cooperative"));
    cooperative.local_balance = "0".to_string();
    cooperative.remote_balance = "0".to_string();
    let mut remote_forced = base_channel("remote force close");
    remote_forced.shutdown_transaction_hash = Some(hash_hex("shutdown tx remote"));
    vec![
        channel(cooperative, state(ChannelState::Closed(CloseFlags(CloseFlags::COOPERATIVE)), "Closed", &["COOPERATIVE"])),
        channel(
            base_channel("local force close"),
            state(
                ChannelState::Closed(CloseFlags(CloseFlags::UNCOOPERATIVE_LOCAL | CloseFlags::WAITING_ONCHAIN_SETTLEMENT)),
                "Closed",
                &["UNCOOPERATIVE_LOCAL", "WAITING_ONCHAIN_SETTLEMENT"],
            ),
        ),
        channel(
            remote_forced,
            state(ChannelState::Closed(CloseFlags(CloseFlags::UNCOOPERATIVE_REMOTE)), "Closed", &["UNCOOPERATIVE_REMOTE"]),
        ),
        channel(
            base_channel("commitment confirming"),
            state(
                ChannelState::ShuttingDown(ShuttingDownFlags(ShuttingDownFlags::WAITING_COMMITMENT_CONFIRMATION)),
                "ShuttingDown",
                &["WAITING_COMMITMENT_CONFIRMATION"],
            ),
        ),
    ]
}

fn attr(name: &str, value: Value) -> AttributeValues {
    AttributeValues { name: name.to_string(), value }
}

fn invoice(label: &str, currency: &str, amount: Option<&str>, signed: bool, attrs: Vec<AttributeValues>) -> InvoiceValues {
    InvoiceValues {
        currency: currency.to_string(),
        amount: amount.map(str::to_string),
        signature: signed.then(|| {
            let seckey = secp030::SecretKey::from_slice(&blake2b_256(b"lsp node")).unwrap();
            let message = Message::from_digest(blake2b_256(label.as_bytes()));
            let (recovery_id, compact) = SECP256K1.sign_ecdsa_recoverable(&message, &seckey).serialize_compact();
            hex::encode([compact.as_slice(), &[i32::from(recovery_id) as u8]].concat())
        }),
        data: InvoiceDataValues {
            timestamp: "1726000000000".to_string(),
            payment_hash: hash_hex(&format!("payment hash {label}")),
            attrs,
        },
    }
}

fn hold_invoice(label: &str) -> InvoiceValues {
    invoice(
        label,
        "Fibt",
        Some("250000000"),
        true,
        vec![
            attr("expiry_time", json!("3600")),
            attr("description", json!("device invoice")),
            attr("hash_algorithm", json!("ckb_hash")),
            attr("payee_public_key", json!(pubkey_hex("lsp node"))),
            attr("final_htlc_minimum_expiry_delta", json!("86400000")),
        ],
    )
}

/// Checked against `enabled_features_names`, so a renamed bit fails the generation.
fn feature_names() -> Vec<&'static str> {
    let names = ["BASIC_MPP_OPTIONAL", "TRAMPOLINE_ROUTING_REQUIRED"];
    let mut features = FeatureVector::new();
    features.set_basic_mpp_optional();
    features.set_trampoline_routing_required();
    assert_eq!(features.enabled_features_names(), names, "feature names fiber emits");
    names.to_vec()
}

fn invoice_address(label: &str) -> String {
    format!("fibt1-fixture-{}", label.replace(' ', "-"))
}

fn get_invoice_case(name: &str, label: &str, invoice: InvoiceValues, status: &str) -> Case {
    let values = GetInvoiceResultValues { invoice_address: invoice_address(label), invoice, status: status.to_string() };
    let json = GetInvoiceResult {
        invoice_address: values.invoice_address.clone(),
        invoice: json_invoice(&values.invoice),
        status: named(&invoice_statuses(), status),
    };
    case(name, &values, &json)
}

fn payment(label: &str, status: &str) -> PaymentValues {
    PaymentValues {
        payment_hash: hash_hex(&format!("payment hash {label}")),
        status: status.to_string(),
        created_at: "1726000000000".to_string(),
        last_updated_at: "1726000001000".to_string(),
        failed_error: None,
        fee: "0".to_string(),
        custom_records: None,
    }
}

fn payment_case(name: &str, values: PaymentValues) -> Case {
    case(name, &values, &json_payment(&values))
}

fn methods() -> MethodVectors {
    let peer = pubkey_hex("peer node");
    let channel_id = hash_hex("channel awaiting external funding");
    let payment_hash = hash_hex("payment hash held");
    let preimage = hash_hex("preimage held");
    let open_channel = |name: &str, values: OpenChannelParamsValues| {
        let json = OpenChannelWithExternalFundingParams {
            pubkey: pubkey(&values.pubkey),
            funding_amount: u128_of(&values.funding_amount),
            public: Some(values.public),
            funding_udt_type_script: None,
            shutdown_script: json_script(&values.shutdown_script),
            funding_lock_script: json_script(&values.funding_lock_script),
            funding_lock_script_cell_deps: None,
            commitment_delay_epoch: None,
            commitment_fee_rate: None,
            funding_fee_rate: None,
            tlc_expiry_delta: None,
            tlc_min_value: None,
            tlc_fee_proportional_millionths: None,
            max_tlc_value_in_flight: None,
            max_tlc_number_in_flight: None,
        };
        case(name, &values, &json)
    };
    let open_result = |name: &str, values: OpenChannelResultValues| {
        let json = OpenChannelWithExternalFundingResult {
            channel_id: hash256(&values.channel_id),
            unsigned_funding_tx: json_transaction(&values.unsigned_funding_tx),
        };
        case(name, &values, &json)
    };
    let list_channels = |name: &str, values: ListChannelsParamsValues| {
        let json =
            ListChannelsParams { pubkey: None, include_closed: values.include_closed, only_pending: values.only_pending };
        case(name, &values, &json)
    };
    let new_invoice = |name: &str, values: NewInvoiceParamsValues| {
        let json = NewInvoiceParams {
            amount: u128_of(&values.amount),
            description: values.description.clone(),
            currency: named(&currencies(), &values.currency),
            payment_preimage: None,
            payment_hash: Some(hash256(&values.payment_hash)),
            expiry: Some(u64_of(&values.expiry)),
            fallback_address: None,
            final_expiry_delta: None,
            udt_type_script: None,
            hash_algorithm: Some(named(&hash_algorithms(), &values.hash_algorithm)),
            allow_mpp: None,
            allow_trampoline_routing: None,
        };
        case(name, &values, &json)
    };
    let payment_hash_params = |name: &str, hash: &str| {
        let values = PaymentHashParamsValues { payment_hash: hash.to_string() };
        (
            case(name, &values, &InvoiceParams { payment_hash: hash256(hash) }),
            case(name, &values, &GetPaymentCommandParams { payment_hash: hash256(hash) }),
        )
    };
    let send_payment = |name: &str, values: SendPaymentParamsValues| {
        let json = SendPaymentCommandParams {
            target_pubkey: None,
            amount: None,
            payment_hash: None,
            final_tlc_expiry_delta: None,
            tlc_expiry_limit: None,
            invoice: Some(values.invoice.clone()),
            timeout: None,
            max_fee_amount: Some(u128_of(&values.max_fee_amount)),
            max_fee_rate: None,
            max_parts: None,
            trampoline_hops: None,
            keysend: None,
            udt_type_script: None,
            allow_self_payment: None,
            custom_records: None,
            hop_hints: None,
            dry_run: Some(values.dry_run),
        };
        case(name, &values, &json)
    };

    let signed_tx = SubmitSignedFundingTxParamsValues {
        channel_id: channel_id.clone(),
        signed_funding_tx: funding_tx(false, true),
    };
    let signed_udt_tx = SubmitSignedFundingTxParamsValues {
        channel_id: hash_hex("channel udt"),
        signed_funding_tx: funding_tx(true, true),
    };
    let submit_result = SubmitSignedFundingTxResultValues {
        channel_id: channel_id.clone(),
        funding_tx_hash: hash_hex("funding tx hash"),
    };
    let abandon = ChannelIdParamsValues { channel_id: channel_id.clone() };
    let invoice_result = InvoiceResultValues { invoice_address: invoice_address("held"), invoice: hold_invoice("held") };
    let settle = SettleInvoiceParamsValues { payment_hash: payment_hash.clone(), payment_preimage: preimage };
    let mut received = hold_invoice("received");
    received.amount = Some(u128::MAX.to_string());
    received.data.attrs.push(attr("udt_script", json!(hex::encode(packed_script(&udt_script()).as_slice()))));
    received.data.attrs.push(attr("feature", json!(feature_names())));
    let mut success = payment("success", "Success");
    success.fee = "12345".to_string();
    success.last_updated_at = "1726000009000".to_string();
    // One record: fiber writes a HashMap, in no stable order.
    success.custom_records = Some(vec![CustomRecordValues { key: 1, data: "01020304".to_string() }]);
    let mut failed = payment("failed", "Failed");
    failed.failed_error = Some("Failed to build route, PathFind error: no path found".to_string());
    let mut largest = payment("largest fee", "Inflight");
    largest.fee = u128::MAX.to_string();
    largest.created_at = u64::MAX.to_string();
    largest.last_updated_at = u64::MAX.to_string();

    let (get_invoice_params, get_payment_params) = payment_hash_params("by payment hash", &payment_hash);
    let (cancel_invoice_params, _) = payment_hash_params("by payment hash", &hash_hex("payment hash cancelled"));

    MethodVectors {
        open_channel_with_external_funding: MethodCases {
            params: vec![
                open_channel(
                    "public channel",
                    OpenChannelParamsValues {
                        pubkey: peer.clone(),
                        funding_amount: "16000000000".to_string(),
                        public: true,
                        shutdown_script: sighash_script("shutdown args"),
                        funding_lock_script: sighash_script("user lock args"),
                    },
                ),
                open_channel(
                    "private channel, largest amount",
                    OpenChannelParamsValues {
                        pubkey: peer.clone(),
                        funding_amount: u128::MAX.to_string(),
                        public: false,
                        shutdown_script: ScriptVector {
                            code_hash: hash_hex("shutdown code hash"),
                            hash_type: "data2".to_string(),
                            args: String::new(),
                        },
                        funding_lock_script: ScriptVector {
                            code_hash: hash_hex("wallet lock code hash"),
                            hash_type: "data".to_string(),
                            args: hash_hex("wallet lock args"),
                        },
                    },
                ),
            ],
            results: vec![
                open_result(
                    "ckb channel",
                    OpenChannelResultValues { channel_id: channel_id.clone(), unsigned_funding_tx: funding_tx(false, false) },
                ),
                open_result(
                    "udt channel with deps",
                    OpenChannelResultValues {
                        channel_id: hash_hex("channel udt"),
                        unsigned_funding_tx: funding_tx(true, false),
                    },
                ),
            ],
        },
        submit_signed_funding_tx: MethodCases {
            params: vec![
                case(
                    "ckb channel",
                    &signed_tx,
                    &SubmitSignedFundingTxParams {
                        channel_id: hash256(&signed_tx.channel_id),
                        signed_funding_tx: json_transaction(&signed_tx.signed_funding_tx),
                    },
                ),
                case(
                    "udt channel with deps",
                    &signed_udt_tx,
                    &SubmitSignedFundingTxParams {
                        channel_id: hash256(&signed_udt_tx.channel_id),
                        signed_funding_tx: json_transaction(&signed_udt_tx.signed_funding_tx),
                    },
                ),
            ],
            results: vec![case(
                "submitted",
                &submit_result,
                &SubmitSignedFundingTxResult {
                    channel_id: hash256(&submit_result.channel_id),
                    funding_tx_hash: hash256(&submit_result.funding_tx_hash),
                },
            )],
        },
        abandon_channel: MethodCases {
            params: vec![case("by channel id", &abandon, &AbandonChannelParams { channel_id: hash256(&abandon.channel_id) })],
            results: vec![case("abandoned", &Value::Null, &())],
        },
        list_channels: MethodCases {
            params: vec![
                list_channels("open channels", ListChannelsParamsValues { include_closed: None, only_pending: None }),
                list_channels(
                    "with closed channels",
                    ListChannelsParamsValues { include_closed: Some(true), only_pending: None },
                ),
                list_channels(
                    "only pending openings",
                    ListChannelsParamsValues { include_closed: None, only_pending: Some(true) },
                ),
            ],
            results: vec![
                list_channels_case("open channels", open_channels()),
                list_channels_case("only pending openings", pending_channels()),
                list_channels_case("with closed channels", closed_channels()),
                list_channels_case("no channels", vec![]),
            ],
        },
        new_invoice: MethodCases {
            params: vec![
                new_invoice(
                    "testnet, ckb hash",
                    NewInvoiceParamsValues {
                        amount: "250000000".to_string(),
                        currency: "Fibt".to_string(),
                        payment_hash: payment_hash.clone(),
                        hash_algorithm: "ckb_hash".to_string(),
                        expiry: "3600".to_string(),
                        description: Some("device invoice".to_string()),
                    },
                ),
                new_invoice(
                    "mainnet, sha256, no description",
                    NewInvoiceParamsValues {
                        amount: "1".to_string(),
                        currency: "Fibb".to_string(),
                        payment_hash: hash_hex("payment hash sha256"),
                        hash_algorithm: "sha256".to_string(),
                        expiry: "86400".to_string(),
                        description: None,
                    },
                ),
                new_invoice(
                    "devnet, largest amount and expiry",
                    NewInvoiceParamsValues {
                        amount: u128::MAX.to_string(),
                        currency: "Fibd".to_string(),
                        payment_hash: hash_hex("payment hash devnet"),
                        hash_algorithm: "ckb_hash".to_string(),
                        expiry: u64::MAX.to_string(),
                        description: Some(String::new()),
                    },
                ),
            ],
            results: vec![case(
                "hold invoice",
                &invoice_result,
                &InvoiceResult {
                    invoice_address: invoice_result.invoice_address.clone(),
                    invoice: json_invoice(&invoice_result.invoice),
                },
            )],
        },
        get_invoice: MethodCases {
            params: vec![get_invoice_params],
            results: vec![
                get_invoice_case("open", "held", hold_invoice("held"), "Open"),
                get_invoice_case("received, largest amount", "received", received, "Received"),
                get_invoice_case("paid", "paid", hold_invoice("paid"), "Paid"),
                get_invoice_case("cancelled", "cancelled", hold_invoice("cancelled"), "Cancelled"),
                get_invoice_case(
                    "expired, no amount, unsigned",
                    "expired",
                    invoice("expired", "Fibd", None, false, vec![attr("expiry_time", json!("1"))]),
                    "Expired",
                ),
            ],
        },
        settle_invoice: MethodCases {
            params: vec![case(
                "with the preimage",
                &settle,
                &SettleInvoiceParams {
                    payment_hash: hash256(&settle.payment_hash),
                    payment_preimage: hash256(&settle.payment_preimage),
                },
            )],
            results: vec![case("settled", &json!({}), &SettleInvoiceResult {})],
        },
        cancel_invoice: MethodCases {
            params: vec![cancel_invoice_params],
            results: vec![get_invoice_case("cancelled", "cancelled", hold_invoice("cancelled"), "Cancelled")],
        },
        send_payment: MethodCases {
            params: vec![
                send_payment(
                    "dry run",
                    SendPaymentParamsValues {
                        invoice: invoice_address("held"),
                        max_fee_amount: "1250000".to_string(),
                        dry_run: true,
                    },
                ),
                send_payment(
                    "largest fee bound",
                    SendPaymentParamsValues {
                        invoice: invoice_address("held"),
                        max_fee_amount: u128::MAX.to_string(),
                        dry_run: false,
                    },
                ),
            ],
            results: vec![payment_case("created", payment("held", "Created"))],
        },
        get_payment: MethodCases {
            params: vec![get_payment_params],
            results: vec![
                payment_case("inflight, largest fee and timestamps", largest),
                payment_case("success with a custom record", success),
                payment_case("failed", failed),
            ],
        },
    }
}

fn response_text<T: Serialize + Clone>(payload: ResponsePayload<'_, T>, id: Id<'_>) -> String {
    serde_json::to_string(&Response::new(payload, id)).unwrap()
}

fn result_envelope<T: Serialize + Clone>(name: &str, id: u64, result: T) -> ResultEnvelope {
    ResultEnvelope {
        name: name.to_string(),
        id,
        result: serde_json::to_value(&result).unwrap(),
        text: response_text(ResponsePayload::success(result), Id::Number(id)),
    }
}

fn error_envelope(name: &str, id: Id<'static>, error: ErrorObject<'static>) -> ErrorEnvelope {
    ErrorEnvelope {
        name: name.to_string(),
        id: serde_json::to_value(&id).unwrap(),
        code: error.code(),
        message: error.message().to_string(),
        data: error.data().map_or(Value::Null, |raw| serde_json::from_str(raw.get()).unwrap()),
        text: response_text::<()>(ResponsePayload::error(error), id),
    }
}

fn envelopes() -> EnvelopeVectors {
    let payment_hash = hash256(&hash_hex("payment hash held"));
    let params = json!([GetPaymentCommandParams { payment_hash }]);
    let raw_params = serde_json::value::to_raw_value(&params).unwrap();
    let request = Request::borrowed("get_payment", Some(&raw_params), Id::Number(7));
    let submitted = SubmitSignedFundingTxResult {
        channel_id: hash256(&hash_hex("channel awaiting external funding")),
        funding_tx_hash: hash256(&hash_hex("funding tx hash")),
    };
    // Read as the server macro reads params: jsonrpsee answers with the serde error as `data`.
    let refused = json!([{ "payment_hash": "0x00" }]).to_string();
    let refused_params = Params::new(Some(&refused)).sequence().next::<GetPaymentCommandParams>().unwrap_err();
    EnvelopeVectors {
        request: RequestEnvelope {
            id: 7,
            method: "get_payment".to_string(),
            params,
            text: serde_json::to_string(&request).unwrap(),
        },
        results: vec![
            result_envelope("object result", 7, submitted),
            result_envelope("empty object result", 8, SettleInvoiceResult {}),
            result_envelope("null result", 9, ()),
        ],
        errors: vec![
            error_envelope(
                "call failed",
                Id::Number(10),
                ErrorObject::owned(CALL_EXECUTION_FAILED_CODE, "invoice not found", None::<()>),
            ),
            error_envelope(
                "unauthorized",
                Id::Number(11),
                ErrorObject::owned(UNAUTHORIZED_CODE, UNAUTHORIZED_MESSAGE, None::<()>),
            ),
            error_envelope(
                "unauthorized, run limit",
                Id::Number(12),
                ErrorObject::owned(UNAUTHORIZED_CODE, UNAUTHORIZED_TIMEOUT_MESSAGE, None::<()>),
            ),
            error_envelope("invalid params", Id::Number(13), refused_params),
            error_envelope("method not found", Id::Number(14), ErrorObject::from(ErrorCode::MethodNotFound)),
            error_envelope("invalid request", Id::Null, ErrorObject::from(ErrorCode::InvalidRequest)),
        ],
    }
}

pub fn gen_rpc_vectors(out_path: &str) {
    assert!(
        !cfg!(debug_assertions),
        "gen-rpc-vectors needs a release build: fiber's GetPaymentCommandResult carries a debug-only field"
    );
    let methods = methods();
    assert_coverage(&methods);
    let vectors = RpcVectors {
        fiber_ref: FIBER_REF.to_string(),
        jsonrpsee_version: JSONRPSEE_VERSION.to_string(),
        envelopes: envelopes(),
        methods,
    };
    let json = serde_json::to_string_pretty(&vectors).unwrap();
    std::fs::write(out_path, format!("{json}\n")).unwrap();
    println!("rpc vectors written to {out_path}");
}

// --- verify-rpc-params ---

#[derive(Deserialize)]
struct TsParamsCase {
    name: String,
    params: Value,
}

type RoundTrip = fn(&Value) -> Result<Value, String>;

/// Drops a misspelt field on the way through: no fiber params struct denies unknown fields.
fn round_trip<P: DeserializeOwned + Serialize>(value: &Value) -> Result<Value, String> {
    let params: P = serde_json::from_value(value.clone()).map_err(|err| err.to_string())?;
    Ok(serde_json::to_value(&params).unwrap())
}

fn method_params<'a>(methods: &'a MethodVectors, method: &str) -> Option<(&'a MethodCases, RoundTrip)> {
    Some(match method {
        "open_channel_with_external_funding" => (
            &methods.open_channel_with_external_funding,
            round_trip::<OpenChannelWithExternalFundingParams>,
        ),
        "submit_signed_funding_tx" => (&methods.submit_signed_funding_tx, round_trip::<SubmitSignedFundingTxParams>),
        "abandon_channel" => (&methods.abandon_channel, round_trip::<AbandonChannelParams>),
        "list_channels" => (&methods.list_channels, round_trip::<ListChannelsParams>),
        "new_invoice" => (&methods.new_invoice, round_trip::<NewInvoiceParams>),
        "get_invoice" => (&methods.get_invoice, round_trip::<InvoiceParams>),
        "settle_invoice" => (&methods.settle_invoice, round_trip::<SettleInvoiceParams>),
        "cancel_invoice" => (&methods.cancel_invoice, round_trip::<InvoiceParams>),
        "send_payment" => (&methods.send_payment, round_trip::<SendPaymentCommandParams>),
        "get_payment" => (&methods.get_payment, round_trip::<GetPaymentCommandParams>),
        _ => return None,
    })
}

/// An absent option and a `null` count as one: fiber reads both as `None`.
fn without_nulls(value: &Value) -> Value {
    match value {
        Value::Object(members) => Value::Object(
            members
                .iter()
                .filter(|(_, member)| !member.is_null())
                .map(|(key, member)| (key.clone(), without_nulls(member)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(without_nulls).collect()),
        other => other.clone(),
    }
}

pub fn verify_rpc_params(vectors_path: &str, ts_out_path: &str) {
    let vectors: RpcVectors = serde_json::from_str(&std::fs::read_to_string(vectors_path).unwrap()).unwrap();
    let written: BTreeMap<String, Vec<TsParamsCase>> =
        serde_json::from_str(&std::fs::read_to_string(ts_out_path).unwrap()).unwrap();
    match check_rpc_params(&vectors.methods, &written) {
        Ok(verified) => println!(
            "OK: {verified} params cases of {} methods accepted and returned unchanged by fiber's serde",
            written.len()
        ),
        Err(failures) => {
            for failure in &failures {
                eprintln!("FAIL: {failure}");
            }
            std::process::exit(1);
        }
    }
}

fn check_rpc_params(methods: &MethodVectors, written: &BTreeMap<String, Vec<TsParamsCase>>) -> Result<usize, Vec<String>> {
    let mut failures = Vec::new();
    if written.is_empty() {
        failures.push("the TS side wrote no method".to_string());
    }
    let mut verified = 0;
    for (method, cases) in written {
        let Some((expected, round_trip)) = method_params(methods, method) else {
            failures.push(format!("{method}: not a method of the vectors"));
            continue;
        };
        let expected_names: Vec<&str> = expected.params.iter().map(|case| case.name.as_str()).collect();
        let written_names: Vec<&str> = cases.iter().map(|case| case.name.as_str()).collect();
        if expected_names != written_names {
            failures.push(format!("{method}: the TS side wrote {written_names:?}, the vectors hold {expected_names:?}"));
            continue;
        }
        for (case, vector) in cases.iter().zip(&expected.params) {
            let label = format!("{method} / {}", case.name);
            let sent = without_nulls(&case.params);
            match round_trip(&case.params) {
                Err(err) => failures.push(format!("{label}: fiber refuses the params: {err}")),
                Ok(back) if without_nulls(&back) != sent => failures.push(format!(
                    "{label}: the params do not come back unchanged through fiber's serde\n  sent: {sent}\n  back: {back}"
                )),
                Ok(_) if without_nulls(&vector.json) != sent => failures.push(format!(
                    "{label}: the params differ from the vector\n  sent: {sent}\n  vector: {}",
                    without_nulls(&vector.json)
                )),
                Ok(_) => verified += 1,
            }
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

    const CASES: usize = 17;

    /// What a correct TS writer emits.
    fn identity() -> Value {
        let methods = serde_json::to_value(methods()).unwrap();
        let written = methods
            .as_object()
            .unwrap()
            .iter()
            .map(|(method, cases)| {
                let params = cases["params"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|case| json!({ "name": case["name"], "params": case["json"] }))
                    .collect();
                (method.clone(), Value::Array(params))
            })
            .collect();
        Value::Object(written)
    }

    fn check(written: Value) -> Result<usize, Vec<String>> {
        check_rpc_params(&methods(), &serde_json::from_value(written).unwrap())
    }

    fn with(pointer: &str, value: Value) -> Value {
        let mut written = identity();
        *written.pointer_mut(pointer).unwrap_or_else(|| panic!("no {pointer}")) = value;
        written
    }

    fn renamed(pointer: &str, from: &str, to: &str) -> Value {
        let mut written = identity();
        let params = written.pointer_mut(pointer).unwrap().as_object_mut().unwrap();
        let value = params.remove(from).unwrap();
        params.insert(to.to_string(), value);
        written
    }

    fn assert_refused(written: Value, reason: &str) {
        let failures = check(written).unwrap_err();
        assert_eq!(failures.len(), 1, "{failures:#?}");
        assert!(failures[0].contains(reason), "expected {reason:?} in {failures:#?}");
    }

    #[test]
    fn accepts_every_case_as_the_vectors_write_it() {
        assert_eq!(check(identity()), Ok(CASES));
    }

    #[test]
    fn accepts_an_omitted_option_as_its_null() {
        let mut written = identity();
        let params = written.pointer_mut("/send_payment/0/params").unwrap().as_object_mut().unwrap();
        params.retain(|_, value| !value.is_null());
        assert_eq!(check(written), Ok(CASES));
    }

    #[test]
    fn refuses_an_output_with_no_method() {
        assert_refused(json!({}), "wrote no method");
    }

    #[test]
    fn refuses_a_method_outside_the_ten() {
        let mut written = identity();
        written.as_object_mut().unwrap().insert("connect_peer".to_string(), json!([]));
        assert_refused(written, "connect_peer: not a method of the vectors");
    }

    #[test]
    fn refuses_a_missing_case() {
        let mut written = identity();
        written["new_invoice"].as_array_mut().unwrap().pop();
        assert_refused(written, "new_invoice: the TS side wrote");
    }

    #[test]
    fn refuses_a_misspelt_optional_field_fiber_drops_in_silence() {
        assert_refused(renamed("/new_invoice/0/params", "description", "descripton"), "do not come back unchanged");
    }

    #[test]
    fn refuses_a_misspelt_required_field() {
        assert_refused(renamed("/abandon_channel/0/params", "channel_id", "channelId"), "fiber refuses the params");
    }

    #[test]
    fn refuses_a_decimal_amount() {
        assert_refused(with("/new_invoice/0/params/amount", json!("250000000")), "fiber refuses the params");
    }

    #[test]
    fn refuses_a_hex_amount_with_a_leading_zero() {
        assert_refused(with("/new_invoice/0/params/amount", json!("0x0ee6b280")), "fiber refuses the params");
    }

    #[test]
    fn refuses_a_prefixed_pubkey_fiber_reads_back_bare() {
        let pubkey = format!("0x{}", pubkey_hex("peer node"));
        assert_refused(
            with("/open_channel_with_external_funding/0/params/pubkey", json!(pubkey)),
            "do not come back unchanged",
        );
    }

    #[test]
    fn refuses_a_field_ckb_transaction_does_not_know() {
        let mut written = identity();
        let tx = written.pointer_mut("/submit_signed_funding_tx/0/params/signed_funding_tx").unwrap();
        tx.as_object_mut().unwrap().insert("hash".to_string(), json!(format!("0x{}", hash_hex("tx hash"))));
        assert_refused(written, "fiber refuses the params");
    }

    #[test]
    fn refuses_a_well_formed_value_other_than_the_vector() {
        let other = format!("0x{}", hash_hex("another payment hash"));
        assert_refused(with("/get_payment/0/params/payment_hash", json!(other)), "differ from the vector");
    }
}
