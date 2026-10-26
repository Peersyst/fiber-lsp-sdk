import { hexToBytes } from "@noble/hashes/utils.js";
import type { SigningSettlementTlc } from "../../../src/digest";
import type { ChannelSigningRequest, ChannelSigningStatus, ChannelSigningTransition } from "../../../src/protocol";
import { CHANNEL_SIGNING_TRANSITIONS, ProtocolError, decodeChannelSigningStatus } from "../../../src/protocol";
import { refusal } from "../../utils/refusal";
import { loadSigningVectors, signingCaseOf, signingStatusField } from "../../utils/signing-vectors";
import { ABOVE_U64, ABOVE_U128, U64_MAX_HEX, U128_MAX_HEX } from "../../utils/uint-hex";
import { withField } from "../../utils/with-field";

const vectors = loadSigningVectors();

const STATUS_PATH = "response.result.status";

const OFF_CURVE_KEY = "022068854bacc49665230d0813b9b3d055d1cb42a62b10b53d633c952e99f665b2";
const INFINITY_HALF = "00".repeat(33);
const CURVE_ORDER_HEX = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const BELOW_CURVE_ORDER_HEX = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
const MAX_SLOT_HEX = "0xfffffffffffe";
const ABOVE_MAX_SLOT_HEX = "0xffffffffffff";
const MAX_COMMITMENT_HEX = "0xffffffffffff";
const ABOVE_MAX_COMMITMENT_HEX = "0x1000000000000";
const MAX_SAFE_INTEGER_HEX = "0x1fffffffffffff";
const ABOVE_MAX_SAFE_INTEGER_HEX = "0x20000000000000";

const HEX_32 = "must be 32 bytes of 0x-prefixed lowercase hex";
const HEX_66 = "must be 66 bytes of 0x-prefixed lowercase hex";
const PUBKEY_HEX = "must be 33 bytes of lowercase hex without a 0x prefix";
const ON_CURVE = "must be a compressed point on the curve";
const UINT_HEX = "must be an unsigned integer in 0x hex without leading zeros";
const ANY_HEX = "must be whole bytes of 0x-prefixed lowercase hex";
const OBJECT = "must be an object";
const BOOLEAN = "must be a boolean";
const COUNTERS = "must be one of Local, Remote";
const PURPOSES = "must be one of Commitment, Revocation, ChannelAnnouncement";
const CONTENT_TYPES = "must be one of CommitmentTransaction, CooperativeCloseTransaction, Revocation, ChannelAnnouncement";
const TRANSITIONS =
    "must be one of SendCommitmentSigned, CompleteReceivedCommitment, SendRevokeAndAck, CompleteReceivedRevokeAndAck, SendClosingSigned, SignChannelAnnouncement";

const COMMITMENT_TRANSITIONS = ["SendCommitmentSigned", "CompleteReceivedCommitment"] as const;
const UNSETTLED_TRANSITIONS = ["SendRevokeAndAck", "CompleteReceivedRevokeAndAck", "SendClosingSigned", "SignChannelAnnouncement"] as const;
const SENDING_TRANSITIONS = ["SendCommitmentSigned", "SendRevokeAndAck", "SendClosingSigned", "SignChannelAnnouncement"] as const;
const RECEIVING_TRANSITIONS = ["CompleteReceivedCommitment", "CompleteReceivedRevokeAndAck"] as const;
const TRANSACTION_TRANSITIONS = ["SendCommitmentSigned", "CompleteReceivedCommitment", "SendClosingSigned"] as const;
const REVOCATION_TRANSITIONS = ["SendRevokeAndAck", "CompleteReceivedRevokeAndAck"] as const;

function bytes(hex: string): Uint8Array {
    return hexToBytes(hex.slice(2));
}

const KEY_AGG_HEX =
    "0x0000000002026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f563802e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5";
const AGG_NONCE_HEX =
    "0x02d1a501cb9bf0b72e16a42ce4c0efd8b4c988e3c02d52c87657119b1076cc7d5503f01dab57e2588aa73acc6805cffc369c83e5e56c8e4cc59783eeafde680c1302";

const TLC_RECEIVED_0: SigningSettlementTlc = {
    tlcId: 0,
    direction: "received",
    hashAlgorithm: "sha256",
    amountShannons: 2250000000n,
    paymentHash: bytes("0xad6da67e459695e3985fa37aff8e45c07167760b9e9252b5d500b913fe70d499"),
    expiryMs: 1760580000000n,
    localKeyCommitmentNumber: 2,
    localKeyPubkey: bytes("0x030460ab5766cae9195cea30cd6c8abf42ff0b7213e1dd995e09e76397f90b2fe5"),
    remoteTlcPubkey: bytes("0x02d469124f0bc3cfcf094833b07ce97653eccd643eaa550da99492adba664393f8"),
};

const TLC_OFFERED_0: SigningSettlementTlc = {
    tlcId: 0,
    direction: "offered",
    hashAlgorithm: "ckb-hash",
    amountShannons: 1500000000n,
    paymentHash: bytes("0xb570807ecd66dbcebb2947e7406032a30e8cf3aa5b428a117ec408754480834f"),
    expiryMs: 1760576400000n,
    localKeyCommitmentNumber: 1,
    localKeyPubkey: bytes("0x03afd50467f12b93c009dd9a62ae1c2760cf336d655f582fb2a5b84f5288f7462b"),
    remoteTlcPubkey: bytes("0x02472f54e4d91d996072f2f98051713867cd88833135c95d4d45414ff3bca2b8bf"),
};

const TLC_OFFERED_1: SigningSettlementTlc = {
    tlcId: 1,
    direction: "offered",
    hashAlgorithm: "sha256",
    amountShannons: 750000000n,
    paymentHash: bytes("0xe8990955f9e49378973c979ced61815c283effe85d4b84b8ef51e2440739a05c"),
    expiryMs: 1760583600000n,
    localKeyCommitmentNumber: 2,
    localKeyPubkey: bytes("0x030460ab5766cae9195cea30cd6c8abf42ff0b7213e1dd995e09e76397f90b2fe5"),
    remoteTlcPubkey: bytes("0x0397f7d412ed096800d678f2e2249304f96c29408f2e0470ff656933cac8e1a61d"),
};
const EXPECTED: Record<ChannelSigningTransition, ChannelSigningRequest> = {
    SendCommitmentSigned: {
        kind: "required",
        requestId: bytes("0x0d08603c21792e52dc266fe7cfccd7865b9cc2d3bb200eb1ec7465c8c8157949"),
        transition: "SendCommitmentSigned",
        slot: { context: "COMMITMENT", commitmentNumber: 4 },
        counter: "local",
        keyAggregation: [
            bytes("0x026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638"),
            bytes("0x02e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5"),
        ],
        aggNonce: bytes(
            "0x02d1a501cb9bf0b72e16a42ce4c0efd8b4c988e3c02d52c87657119b1076cc7d5503f01dab57e2588aa73acc6805cffc369c83e5e56c8e4cc59783eeafde680c1302",
        ),
        content: {
            kind: "commitmentTx",
            transaction: {
                version: 0,
                cellDeps: [],
                headerDeps: [],
                inputs: [
                    {
                        since: 0n,
                        previousOutput: { txHash: bytes("0x341b96611104178e30e46e7b2a9039a76b9a76422328ee39a2d4cb09aa8711af"), index: 0 },
                    },
                ],
                outputs: [
                    {
                        capacityShannons: 100499999543n,
                        lock: {
                            codeHash: bytes("0x740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8"),
                            hashType: "type",
                            args: bytes(
                                "0x5c5dfaf84654cd9ca715c1e585b951d5d0d62c9601000000000100a000000000000000044ddb3e0e50341d441e61a7dee6ed72675b7442180001",
                            ),
                        },
                        type: null,
                    },
                ],
                outputsData: [bytes("0x")],
                witnesses: [],
            },
        },
        evidence: {
            peerPublicNonce: bytes(
                "0x03791be12ca7c1d705c5c8d7a84146ebe53b097bf98cde8a40d1c998fffcc7e22402c8227dc41d8d4582c51efa19651ced92f7d03a18aba29c8759c82a50bf631b0e",
            ),
            peerPartialSignature: null,
        },
        settlement: {
            localAmountShannons: 69750000000n,
            remoteAmountShannons: 26250000000n,
            localSettlementPubkey: bytes("0x035de18a9013ba6eb918a415764d99945683f18d3f9fa4c881ed92423124de0849"),
            remoteSettlementPubkey: bytes("0x032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21"),
            forRemote: true,
            tlcs: [TLC_RECEIVED_0, TLC_OFFERED_0, TLC_OFFERED_1],
        },
    },
    CompleteReceivedCommitment: {
        kind: "required",
        requestId: bytes("0xec37e8ec19655e5341521849750193e50b1e61f69f626adf0a676f18c414b8ad"),
        transition: "CompleteReceivedCommitment",
        slot: { context: "COMMITMENT", commitmentNumber: 3 },
        counter: "local",
        keyAggregation: [
            bytes("0x026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638"),
            bytes("0x02e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5"),
        ],
        aggNonce: bytes(
            "0x03155451f24aed5c780295b77c9e8bed906eef36bf1be37830b352d7523315bcf1024f7128388b87d08e0f4941b59912a1a0e431043ab97814ca15805c01ecb6226e",
        ),
        content: {
            kind: "commitmentTx",
            transaction: {
                version: 0,
                cellDeps: [],
                headerDeps: [],
                inputs: [
                    {
                        since: 0n,
                        previousOutput: { txHash: bytes("0x341b96611104178e30e46e7b2a9039a76b9a76422328ee39a2d4cb09aa8711af"), index: 0 },
                    },
                ],
                outputs: [
                    {
                        capacityShannons: 100499999543n,
                        lock: {
                            codeHash: bytes("0x740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8"),
                            hashType: "type",
                            args: bytes(
                                "0xd28355e59077c4ac7d755f5f63c5a3e4d154e9dd01000000000100a00000000000000002e6a77fd06db575d69fff9ed5cdeec662a02eea420001",
                            ),
                        },
                        type: null,
                    },
                ],
                outputsData: [bytes("0x")],
                witnesses: [],
            },
        },
        evidence: {
            peerPublicNonce: bytes(
                "0x02a3ef2f64714c9e3d9edcc7bb7f4ec6095c70316f2d6427301a4cbd84e3ab8525024df3a407346881969dfa56951c16cd6083dea3acd5ffaaa11ccf18edec4790f6",
            ),
            peerPartialSignature: bytes("0xb9285a6d96bb072190338c019c52e8e19a361f195ee4af00d7d5734e8ec33c3c"),
        },
        settlement: {
            localAmountShannons: 69750000000n,
            remoteAmountShannons: 26250000000n,
            localSettlementPubkey: bytes("0x035de18a9013ba6eb918a415764d99945683f18d3f9fa4c881ed92423124de0849"),
            remoteSettlementPubkey: bytes("0x032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21"),
            forRemote: false,
            tlcs: [TLC_OFFERED_0, TLC_OFFERED_1, TLC_RECEIVED_0],
        },
    },
    SendRevokeAndAck: {
        kind: "required",
        requestId: bytes("0x0c5269ab04ac732bf857154ce9f8fbcddef725b36fbe5136a4dfda537920c47b"),
        transition: "SendRevokeAndAck",
        slot: { context: "REVOKE", commitmentNumber: 3 },
        counter: "remote",
        keyAggregation: [
            bytes("0x026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638"),
            bytes("0x02e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5"),
        ],
        aggNonce: bytes(
            "0x02298a541534815ed5b226c449d7eaf3ac896a8f7646f27b58946a1e31187fe44d02da297302f2dbdf8d99f33e3d26c8bef7ccba11817a0aced08d5d29b94f45b506",
        ),
        content: {
            kind: "revocation",
            output: {
                capacityShannons: 0x1766444b37n,
                lock: {
                    codeHash: bytes("0x4d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba"),
                    hashType: "type",
                    args: bytes("0x8f1e030962418183dc890ef5664b1f2a64b0064c"),
                },
                type: null,
            },
            outputData: bytes("0x00000000"),
            commitmentLockArgs: bytes("0xd28355e59077c4ac7d755f5f63c5a3e4d154e9dd01000000000100a00000000000000002"),
        },
        evidence: {
            peerPublicNonce: bytes(
                "0x03062681536ee7fdd2fcd6e747b5fd61be71ad3df273cce29afb7bfdc316b9ea3c03b1247e4160a99af7a5bfca9f267b71340c19efe72b8b93ff42fdf96ddcd4e860",
            ),
            peerPartialSignature: null,
        },
        settlement: null,
    },
    CompleteReceivedRevokeAndAck: {
        kind: "required",
        requestId: bytes("0x241c1fee20095d8f9b45f6d43a62d686993a970dd137740e9e1c453e6c4c85a6"),
        transition: "CompleteReceivedRevokeAndAck",
        slot: { context: "REVOKE", commitmentNumber: 4 },
        counter: "local",
        keyAggregation: [
            bytes("0x02e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5"),
            bytes("0x026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638"),
        ],
        aggNonce: bytes(
            "0x03a020e57a91246feb0a27d8c5407744b72fff81f236f8641547d67b85fa52621102780917b41e7390dc7d08c7119ac351c42ffff9152fa5063b4c315aaeee1e1af3",
        ),
        content: {
            kind: "revocation",
            output: {
                capacityShannons: 0x1766444b37n,
                lock: {
                    codeHash: bytes("0x537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d769"),
                    hashType: "type",
                    args: bytes("0x8d66477ba3b60a96feb27a3f57fe11f6697be87d"),
                },
                type: null,
            },
            outputData: bytes("0x00000000"),
            commitmentLockArgs: bytes("0x5c5dfaf84654cd9ca715c1e585b951d5d0d62c9601000000000100a00000000000000003"),
        },
        evidence: {
            peerPublicNonce: bytes(
                "0x037f940f7f26d97ab832872207f1c6b817e1b6ca7f9317ae2b231f532096ac0f600352c0e3da18619f2ea41c4472b0a5db1db431596b33bc5f9d428875f664fafe3b",
            ),
            peerPartialSignature: bytes("0xc035f0b664390520e9dd8e4ad1374e21b2831b7566b659bbed7fb372d4f61560"),
        },
        settlement: null,
    },
    SendClosingSigned: {
        kind: "required",
        requestId: bytes("0xa98be0cedd16030e2d899eba3a71564ed873b017d0a67fa63b68208ede003a7b"),
        transition: "SendClosingSigned",
        slot: { context: "COMMITMENT", commitmentNumber: 5 },
        counter: "local",
        keyAggregation: [
            bytes("0x026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638"),
            bytes("0x02e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5"),
        ],
        aggNonce: bytes(
            "0x024208b9d3fec7cd68d775b92f8a24b6cebb1d7c61648fc78cba3817c90ff9f0c202dccb269e680708a7130d11aa50869161992d3a671a0200ce63df8890c35f4efa",
        ),
        content: {
            kind: "closingTx",
            transaction: {
                version: 0,
                cellDeps: [],
                headerDeps: [],
                inputs: [
                    {
                        since: 0n,
                        previousOutput: { txHash: bytes("0x341b96611104178e30e46e7b2a9039a76b9a76422328ee39a2d4cb09aa8711af"), index: 0 },
                    },
                ],
                outputs: [
                    {
                        capacityShannons: 28499999367n,
                        lock: {
                            codeHash: bytes("0x4d62a160ec2d470f499fb511b77777e0af54af776d9d31ee9ecdc71d7378c2ba"),
                            hashType: "type",
                            args: bytes("0x8f1e030962418183dc890ef5664b1f2a64b0064c"),
                        },
                        type: null,
                    },
                    {
                        capacityShannons: 71999999472n,
                        lock: {
                            codeHash: bytes("0x537320e708e05f80a3d3a873b32eda052298e274ad93e7b9d5c2fc0ca201d769"),
                            hashType: "type",
                            args: bytes("0x8d66477ba3b60a96feb27a3f57fe11f6697be87d"),
                        },
                        type: null,
                    },
                ],
                outputsData: [bytes("0x"), bytes("0x")],
                witnesses: [],
            },
        },
        evidence: {
            peerPublicNonce: bytes(
                "0x03295c22d766a524eb4fade5a85048b84e5905015b7c7b8d9381aeaebb249cbf97020200bc8d50935872b9dfafc99ceb99475fc1839d02a8eb27d5fd3831b52dd4d7",
            ),
            peerPartialSignature: null,
        },
        settlement: null,
    },
    SignChannelAnnouncement: {
        kind: "required",
        requestId: bytes("0x2e180b749ea3dd94fbd90723cd198761cc312cd2d838a1bb129a988eadf605e7"),
        transition: "SignChannelAnnouncement",
        slot: { context: "ANNOUNCEMENT", commitmentNumber: 0 },
        counter: null,
        keyAggregation: [
            bytes("0x026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638"),
            bytes("0x02e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5"),
        ],
        aggNonce: bytes(
            "0x0245e18e1756ce4ac6f5546f5797970b6823809cff755860f39cc5f706be75732a0333c25e3677acf940de68d4e79ee7ec06235515439ebf3adb37e348b4daee971a",
        ),
        content: {
            kind: "announcement",
            unsignedAnnouncement: bytes(
                "0xae0100003000000070000000b0000000f0000000f8000000180100003c0100005d0100007e0100009e010000ae01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007dd6a90d41a8137fd3a212a69b8c14c554ca590e431d77bc836e5c5d05a545af341b96611104178e30e46e7b2a9039a76b9a76422328ee39a2d4cb09aa8711af0000000002106fa580a1c56411d6ee7deabcc98aae6f6479858f924487cf58c4c2ca3023040388b3f6725f602c2264516a7cb3e769ee809ef696eef87fa3f7f33b34e1f922c22e1e62fc327b5be20d8ee21232a25ca7de1016464895df90b2166305e248a7be004d4466170000000000000000000000",
            ),
        },
        evidence: {
            peerPublicNonce: bytes(
                "0x039c0eb00a5fe61d51b35b99b994103df8d7070b81528b6931a729f0999b66f52b02e79edd56e2aec2048a93308ae6c377b5cd9027ec346d5b97deef819f2f8c674e",
            ),
            peerPartialSignature: null,
        },
        settlement: null,
    },
};

function statusOf(transition: ChannelSigningTransition): Record<string, unknown> {
    return signingStatusField(signingCaseOf(vectors, transition)).value as Record<string, unknown>;
}

function decode(value: unknown): ChannelSigningStatus {
    return decodeChannelSigningStatus({ value, path: STATUS_PATH });
}

function decodeWith(transition: ChannelSigningTransition, path: string, value: unknown): ChannelSigningRequest {
    const status = decode(withField(statusOf(transition), path, value));
    if (status.kind !== "required") throw new Error("the status carries no request");
    return status;
}

function refusalOf(value: unknown): ProtocolError {
    const error = refusal(() => decode(value));
    expect(error).toBeInstanceOf(ProtocolError);
    return error as ProtocolError;
}

function expectRefused(transition: ChannelSigningTransition, path: string, value: unknown, reason: string, at: string = path): void {
    const error = refusalOf(withField(statusOf(transition), path, value));
    expect({ path: error.path, reason: error.reason }).toEqual({ path: `${STATUS_PATH}.${at}`, reason });
}

describe("decodeChannelSigningStatus", () => {
    it("reads NoSignatureRequired as no request", () => {
        expect(decode({ type: "NoSignatureRequired" })).toEqual({ kind: "none" });
    });

    it.each(CHANNEL_SIGNING_TRANSITIONS)("reads the %s case of the vectors into the typed request", (transition) => {
        expect(decode(statusOf(transition))).toEqual(EXPECTED[transition]);
    });

    it.each([
        ["null", null],
        ["an array", []],
        ["a string", "SignatureRequired"],
    ])("refuses a status that is %s", (_name, value) => {
        expect(refusalOf(value)).toMatchObject({ path: STATUS_PATH, reason: OBJECT });
    });

    it("refuses at the first field that fails, in the order of the wire", () => {
        const broken: [string, unknown, string][] = [
            ["request_id", undefined, HEX_32],
            ["transition", "SendShutdown", TRANSITIONS],
            ["content.slot.purpose", "Revocation", "must be Commitment for SendCommitmentSigned"],
            ["content.commitment_counter", "Remote", "must be Local for SendCommitmentSigned"],
            ["content.key_agg_ctx", undefined, ANY_HEX],
            ["content.agg_nonce", undefined, HEX_66],
            ["content.content.type", "Revocation", "must be CommitmentTransaction for SendCommitmentSigned"],
            ["session_evidence.peer_public_nonce", undefined, HEX_66],
            ["settlement", null, "must be present for SendCommitmentSigned"],
        ];
        for (const [index, [path, , reason]] of broken.entries()) {
            const status = broken
                .slice(index)
                .reduce((value, [at, replacement]) => withField(value, at, replacement), statusOf("SendCommitmentSigned"));
            const error = refusalOf(status);
            expect({ path: error.path, reason: error.reason }).toEqual({ path: `${STATUS_PATH}.${path}`, reason });
        }
    });

    it.each([
        [
            "the settlement",
            [
                ["settlement.local_amount", undefined, UINT_HEX],
                ["settlement.remote_amount", undefined, UINT_HEX],
                ["settlement.local_settlement_pubkey", undefined, PUBKEY_HEX],
                ["settlement.remote_settlement_pubkey", undefined, PUBKEY_HEX],
                ["settlement.for_remote", false, "must be true for SendCommitmentSigned"],
                ["settlement.tlcs", undefined, "must be an array"],
            ],
        ],
        [
            "a TLC",
            [
                ["settlement.tlcs[0].tlc_id", undefined, UINT_HEX],
                ["settlement.tlcs[0].local_key_commitment_number", undefined, UINT_HEX],
                ["settlement.tlcs[0].inbound", undefined, BOOLEAN],
                ["settlement.tlcs[0].payment_hash", undefined, HEX_32],
                ["settlement.tlcs[0].payment_amount", undefined, UINT_HEX],
                ["settlement.tlcs[0].hash_algorithm", undefined, "must be one of ckb_hash, sha256"],
                ["settlement.tlcs[0].expiry", undefined, UINT_HEX],
                ["settlement.tlcs[0].local_key_pubkey", undefined, PUBKEY_HEX],
                ["settlement.tlcs[0].remote_key", undefined, PUBKEY_HEX],
            ],
        ],
    ] as [string, [string, unknown, string][]][])(
        "refuses inside %s at the first field that fails, in the order of the wire",
        (_name, broken) => {
            for (const [index, [path, , reason]] of broken.entries()) {
                const status = broken
                    .slice(index)
                    .reduce((value, [at, replacement]) => withField(value, at, replacement), statusOf("SendCommitmentSigned"));
                const error = refusalOf(status);
                expect({ path: error.path, reason: error.reason }).toEqual({ path: `${STATUS_PATH}.${path}`, reason });
            }
        },
    );

    it("refuses an oversized TLC list before reading any of its TLCs", () => {
        const tlc = { ...(statusOf("SendCommitmentSigned").settlement as { tlcs: Record<string, unknown>[] }).tlcs[0], tlc_id: undefined };
        expectRefused(
            "SendCommitmentSigned",
            "settlement.tlcs",
            Array.from({ length: 256 }, () => tlc),
            "must have at most 255 items",
        );
    });

    describe("the envelope", () => {
        it.each([
            ["type", undefined, "must be one of NoSignatureRequired, SignatureRequired"],
            ["type", "signature_required", "must be one of NoSignatureRequired, SignatureRequired"],
            ["type", 1, "must be one of NoSignatureRequired, SignatureRequired"],
            ["request_id", undefined, HEX_32],
            ["request_id", `0x${"ab".repeat(31)}`, HEX_32],
            ["request_id", `0x${"ab".repeat(33)}`, HEX_32],
            ["request_id", "ab".repeat(32), HEX_32],
            ["request_id", `0x${"AB".repeat(32)}`, HEX_32],
            ["request_id", null, HEX_32],
            ["request_id", 1, HEX_32],
            ["transition", undefined, TRANSITIONS],
            ["transition", null, TRANSITIONS],
            ["transition", 1, TRANSITIONS],
            ["transition", "sendCommitmentSigned", TRANSITIONS],
            ["transition", "SendShutdown", TRANSITIONS],
            ["content", undefined, OBJECT],
            ["content", [], OBJECT],
            ["content", null, OBJECT],
            ["content.slot", undefined, OBJECT],
            ["content.slot", null, OBJECT],
            ["session_evidence", undefined, OBJECT],
            ["session_evidence", null, OBJECT],
        ])("refuses %s = %p", (path, value, reason) => {
            expectRefused("SendCommitmentSigned", path, value, reason);
        });
    });

    describe("the slot", () => {
        it.each([
            ["SendCommitmentSigned", "Revocation", "must be Commitment for SendCommitmentSigned"],
            ["SendCommitmentSigned", "ChannelAnnouncement", "must be Commitment for SendCommitmentSigned"],
            ["CompleteReceivedCommitment", "Revocation", "must be Commitment for CompleteReceivedCommitment"],
            ["SendRevokeAndAck", "Commitment", "must be Revocation for SendRevokeAndAck"],
            ["CompleteReceivedRevokeAndAck", "Commitment", "must be Revocation for CompleteReceivedRevokeAndAck"],
            ["SendClosingSigned", "Revocation", "must be Commitment for SendClosingSigned"],
            ["SignChannelAnnouncement", "Commitment", "must be ChannelAnnouncement for SignChannelAnnouncement"],
        ] as const)("refuses on %s the purpose %s", (transition, purpose, reason) => {
            expectRefused(transition, "content.slot.purpose", purpose, reason);
        });

        it.each(CHANNEL_SIGNING_TRANSITIONS)("refuses on %s a purpose absent or spelled otherwise", (transition) => {
            expectRefused(transition, "content.slot.purpose", undefined, PURPOSES);
            expectRefused(transition, "content.slot.purpose", null, PURPOSES);
            expectRefused(transition, "content.slot.purpose", "commitment", PURPOSES);
            expectRefused(transition, "content.slot.purpose", "COMMITMENT", PURPOSES);
        });

        it.each([
            "SendCommitmentSigned",
            "CompleteReceivedCommitment",
            "SendRevokeAndAck",
            "CompleteReceivedRevokeAndAck",
            "SendClosingSigned",
        ] as const)("reads on %s a number up to one below the derivation's bound, the last whose next is derivable", (transition) => {
            expect(decodeWith(transition, "content.slot.commitment_number", MAX_SLOT_HEX).slot.commitmentNumber).toBe(2 ** 48 - 2);
            expectRefused(transition, "content.slot.commitment_number", ABOVE_MAX_SLOT_HEX, "must be at most 281474976710654");
        });

        it.each(CHANNEL_SIGNING_TRANSITIONS)("refuses on %s a number absent or out of fiber's hex form", (transition) => {
            for (const value of [undefined, null, "0x04", "0X4", "4", 4, "0x"]) {
                expectRefused(transition, "content.slot.commitment_number", value, UINT_HEX);
            }
        });

        it("refuses an announcement slot at any number but 0", () => {
            expectRefused("SignChannelAnnouncement", "content.slot.commitment_number", "0x1", "must be 0 for a channel announcement");
            expectRefused(
                "SignChannelAnnouncement",
                "content.slot.commitment_number",
                MAX_SLOT_HEX,
                "must be 0 for a channel announcement",
            );
        });

        it("reads a commitment slot at 0", () => {
            expect(decodeWith("SendCommitmentSigned", "content.slot.commitment_number", "0x0").slot).toEqual({
                context: "COMMITMENT",
                commitmentNumber: 0,
            });
        });
    });

    describe("the counter", () => {
        it.each([
            ["SendCommitmentSigned", "Remote", "must be Local for SendCommitmentSigned"],
            ["SendCommitmentSigned", null, "must be Local for SendCommitmentSigned"],
            ["CompleteReceivedCommitment", "Remote", "must be Local for CompleteReceivedCommitment"],
            ["CompleteReceivedCommitment", null, "must be Local for CompleteReceivedCommitment"],
            ["SendRevokeAndAck", "Local", "must be Remote for SendRevokeAndAck"],
            ["SendRevokeAndAck", null, "must be Remote for SendRevokeAndAck"],
            ["CompleteReceivedRevokeAndAck", "Remote", "must be Local for CompleteReceivedRevokeAndAck"],
            ["CompleteReceivedRevokeAndAck", null, "must be Local for CompleteReceivedRevokeAndAck"],
            ["SendClosingSigned", "Remote", "must be Local for SendClosingSigned"],
            ["SendClosingSigned", null, "must be Local for SendClosingSigned"],
            ["SignChannelAnnouncement", "Local", "must be null for SignChannelAnnouncement"],
            ["SignChannelAnnouncement", "Remote", "must be null for SignChannelAnnouncement"],
        ] as const)("refuses on %s the counter %p", (transition, counter, reason) => {
            expectRefused(transition, "content.commitment_counter", counter, reason);
        });

        it.each(CHANNEL_SIGNING_TRANSITIONS)(
            "refuses on %s a counter absent, which fiber writes as null, or spelled otherwise",
            (transition) => {
                expectRefused(transition, "content.commitment_counter", undefined, COUNTERS);
                expectRefused(transition, "content.commitment_counter", "local", COUNTERS);
            },
        );
    });

    describe("the key aggregation and the aggregate nonce", () => {
        it.each([
            ["absent", undefined, ANY_HEX],
            ["a byte short", `0x${"00".repeat(70)}`, "must be 71 bytes"],
            ["with the parity bit", `0x01${KEY_AGG_HEX.slice(4)}`, "must have the header byte 0x00: no parity flag, no tweak"],
        ])("refuses a key_agg_ctx %s", (_name, value, reason) => {
            expectRefused("SendCommitmentSigned", "content.key_agg_ctx", value, reason);
        });

        it.each([
            ["the first half", (nonce: string) => `0x${INFINITY_HALF}${nonce.slice(68)}`],
            ["the second half", (nonce: string) => `${nonce.slice(0, 68)}${INFINITY_HALF}`],
            ["both halves", () => `0x${INFINITY_HALF}${INFINITY_HALF}`],
        ])("reads an aggregate nonce with %s at infinity, as musig2 writes it", (_name, edit) => {
            const nonce = edit(AGG_NONCE_HEX);
            expect(decodeWith("SendCommitmentSigned", "content.agg_nonce", nonce).aggNonce).toEqual(bytes(nonce));
        });

        it.each([
            ["absent", undefined, HEX_66],
            ["null", null, HEX_66],
            ["without the 0x prefix", AGG_NONCE_HEX.slice(2), HEX_66],
            ["in uppercase", `0x${AGG_NONCE_HEX.slice(2).toUpperCase()}`, HEX_66],
            ["of 65 bytes", AGG_NONCE_HEX.slice(0, -2), HEX_66],
            ["of 67 bytes", `${AGG_NONCE_HEX}00`, HEX_66],
            [
                "with its first half off the curve",
                `0x${OFF_CURVE_KEY}${AGG_NONCE_HEX.slice(68)}`,
                "must have its first half on the curve or at infinity",
            ],
            [
                "with its second half off the curve",
                `${AGG_NONCE_HEX.slice(0, 68)}${OFF_CURVE_KEY}`,
                "must have its second half on the curve or at infinity",
            ],
            ["with an uncompressed prefix", `0x04${AGG_NONCE_HEX.slice(4)}`, "must have its first half on the curve or at infinity"],
            [
                "with a zero prefix and a non-zero x",
                `0x00${AGG_NONCE_HEX.slice(4)}`,
                "must have its first half on the curve or at infinity",
            ],
        ])("refuses an aggregate nonce %s", (_name, value, reason) => {
            expectRefused("SendCommitmentSigned", "content.agg_nonce", value, reason);
        });
    });

    describe("the content", () => {
        it.each([
            ["SendCommitmentSigned", "Revocation", "must be CommitmentTransaction for SendCommitmentSigned"],
            ["SendCommitmentSigned", "CooperativeCloseTransaction", "must be CommitmentTransaction for SendCommitmentSigned"],
            ["CompleteReceivedCommitment", "CooperativeCloseTransaction", "must be CommitmentTransaction for CompleteReceivedCommitment"],
            ["SendRevokeAndAck", "CommitmentTransaction", "must be Revocation for SendRevokeAndAck"],
            ["CompleteReceivedRevokeAndAck", "ChannelAnnouncement", "must be Revocation for CompleteReceivedRevokeAndAck"],
            ["SendClosingSigned", "CommitmentTransaction", "must be CooperativeCloseTransaction for SendClosingSigned"],
            ["SignChannelAnnouncement", "Revocation", "must be ChannelAnnouncement for SignChannelAnnouncement"],
        ] as const)("refuses on %s a %s content", (transition, type, reason) => {
            expectRefused(transition, "content.content.type", type, reason);
        });

        it.each(CHANNEL_SIGNING_TRANSITIONS)("refuses on %s a content absent, or of a type absent or spelled otherwise", (transition) => {
            expectRefused(transition, "content.content", undefined, OBJECT);
            expectRefused(transition, "content.content.type", undefined, CONTENT_TYPES);
            expectRefused(transition, "content.content.type", "commitment_transaction", CONTENT_TYPES);
        });

        it.each(TRANSACTION_TRANSITIONS)("refuses on %s a transaction absent or out of CKB's JSON shape", (transition) => {
            expectRefused(transition, "content.content.transaction", undefined, OBJECT);
            expectRefused(transition, "content.content.transaction.version", undefined, UINT_HEX);
            expectRefused(transition, "content.content.transaction.outputs[0].capacity", "0x01", UINT_HEX);
            expectRefused(transition, "content.content.transaction.inputs", null, "must be an array");
        });

        it.each(REVOCATION_TRANSITIONS)("refuses on %s an output absent or not a canonical molecule CellOutput", (transition) => {
            const output = (statusOf(transition).content as { content: { output: string } }).content.output;
            expectRefused(transition, "content.content.output", undefined, ANY_HEX);
            expectRefused(transition, "content.content.output", null, ANY_HEX);
            expectRefused(transition, "content.content.output", output.slice(0, -2), "must be exactly as long as its size says");
        });

        it.each(REVOCATION_TRANSITIONS)("reads on %s any output data, and refuses one absent or not hex", (transition) => {
            expect(decodeWith(transition, "content.content.output_data", "0x").content).toMatchObject({ outputData: new Uint8Array() });
            expectRefused(transition, "content.content.output_data", undefined, ANY_HEX);
            expectRefused(transition, "content.content.output_data", null, ANY_HEX);
            expectRefused(transition, "content.content.output_data", "0x0", ANY_HEX);
        });

        it.each(REVOCATION_TRANSITIONS)("reads on %s exactly 36 bytes of lock args", (transition) => {
            const args = `0x${"ab".repeat(36)}`;
            expect(decodeWith(transition, "content.content.commitment_lock_script_args", args).content).toMatchObject({
                commitmentLockArgs: bytes(args),
            });
            const reason = "must be 36 bytes of 0x-prefixed lowercase hex";
            expectRefused(transition, "content.content.commitment_lock_script_args", undefined, reason);
            expectRefused(transition, "content.content.commitment_lock_script_args", null, reason);
            expectRefused(transition, "content.content.commitment_lock_script_args", `0x${"ab".repeat(35)}`, reason);
            expectRefused(transition, "content.content.commitment_lock_script_args", `0x${"ab".repeat(37)}`, reason);
        });

        it("refuses an unsigned announcement absent or not hex", () => {
            expectRefused("SignChannelAnnouncement", "content.content.unsigned_announcement", undefined, ANY_HEX);
            expectRefused("SignChannelAnnouncement", "content.content.unsigned_announcement", null, ANY_HEX);
            expectRefused("SignChannelAnnouncement", "content.content.unsigned_announcement", "ae01", ANY_HEX);
        });
    });

    describe("the session evidence", () => {
        it.each(CHANNEL_SIGNING_TRANSITIONS)(
            "refuses on %s a peer public nonce absent, of another size or with a half off the curve",
            (transition) => {
                const nonce = (statusOf(transition).session_evidence as { peer_public_nonce: string }).peer_public_nonce;
                const path = "session_evidence.peer_public_nonce";
                expectRefused(transition, path, undefined, HEX_66);
                expectRefused(transition, path, null, HEX_66);
                expectRefused(transition, path, nonce.slice(0, -2), HEX_66);
                expectRefused(transition, path, `0x${OFF_CURVE_KEY}${nonce.slice(68)}`, "must have its first half on the curve");
                expectRefused(transition, path, `${nonce.slice(0, 68)}${OFF_CURVE_KEY}`, "must have its second half on the curve");
                // A participant's own nonce is never at infinity: that is an aggregate's privilege.
                expectRefused(transition, path, `0x${INFINITY_HALF}${nonce.slice(68)}`, "must have its first half on the curve");
                expectRefused(transition, path, `${nonce.slice(0, 68)}${INFINITY_HALF}`, "must have its second half on the curve");
            },
        );

        it.each(SENDING_TRANSITIONS)("refuses on %s a peer partial signature, present or absent, that is not null", (transition) => {
            const path = "session_evidence.peer_partial_signature";
            expectRefused(transition, path, `0x${"11".repeat(32)}`, `must be null for ${transition}`);
            expectRefused(transition, path, undefined, `must be null for ${transition}`);
        });

        it.each(RECEIVING_TRANSITIONS)(
            "requires on %s the peer partial signature, a 32-byte scalar below the curve order",
            (transition) => {
                const path = "session_evidence.peer_partial_signature";
                expect(decodeWith(transition, path, `0x${BELOW_CURVE_ORDER_HEX}`).evidence.peerPartialSignature).toEqual(
                    bytes(`0x${BELOW_CURVE_ORDER_HEX}`),
                );
                expect(decodeWith(transition, path, `0x${"00".repeat(32)}`).evidence.peerPartialSignature).toEqual(new Uint8Array(32));
                expectRefused(transition, path, `0x${CURVE_ORDER_HEX}`, "must be a scalar below the curve order");
                expectRefused(transition, path, null, `must be present for ${transition}`);
                expectRefused(transition, path, undefined, HEX_32);
                expectRefused(transition, path, `0x${"11".repeat(31)}`, HEX_32);
                expectRefused(transition, path, "11".repeat(32), HEX_32);
            },
        );
    });

    describe("the settlement", () => {
        it.each(UNSETTLED_TRANSITIONS)("reads on %s a settlement null or absent, which fiber reads as null", (transition) => {
            expect(decodeWith(transition, "settlement", null).settlement).toBeNull();
            expect(decodeWith(transition, "settlement", undefined).settlement).toBeNull();
        });

        it.each(UNSETTLED_TRANSITIONS)("refuses on %s any settlement", (transition) => {
            const settlement = statusOf("SendCommitmentSigned").settlement;
            expectRefused(transition, "settlement", settlement, `must be null for ${transition}`);
            expectRefused(transition, "settlement", {}, `must be null for ${transition}`);
        });

        it.each(COMMITMENT_TRANSITIONS)("requires on %s a settlement", (transition) => {
            expectRefused(transition, "settlement", null, `must be present for ${transition}`);
            expectRefused(transition, "settlement", undefined, `must be present for ${transition}`);
            expectRefused(transition, "settlement", [], OBJECT);
        });

        it.each([
            ["SendCommitmentSigned", false],
            ["CompleteReceivedCommitment", true],
        ] as const)("refuses on %s a settlement for_remote of %p", (transition, forRemote) => {
            expectRefused(transition, "settlement.for_remote", forRemote, `must be ${!forRemote} for ${transition}`);
        });

        it.each([
            ["local_amount", U128_MAX_HEX, (request: ChannelSigningRequest) => request.settlement?.localAmountShannons, 2n ** 128n - 1n],
            ["remote_amount", U128_MAX_HEX, (request: ChannelSigningRequest) => request.settlement?.remoteAmountShannons, 2n ** 128n - 1n],
            [
                "tlcs[0].tlc_id",
                MAX_SAFE_INTEGER_HEX,
                (request: ChannelSigningRequest) => request.settlement?.tlcs[0]?.tlcId,
                Number.MAX_SAFE_INTEGER,
            ],
            [
                "tlcs[0].local_key_commitment_number",
                MAX_COMMITMENT_HEX,
                (request: ChannelSigningRequest) => request.settlement?.tlcs[0]?.localKeyCommitmentNumber,
                2 ** 48 - 1,
            ],
            [
                "tlcs[0].payment_amount",
                U128_MAX_HEX,
                (request: ChannelSigningRequest) => request.settlement?.tlcs[0]?.amountShannons,
                2n ** 128n - 1n,
            ],
            ["tlcs[0].expiry", U64_MAX_HEX, (request: ChannelSigningRequest) => request.settlement?.tlcs[0]?.expiryMs, 2n ** 64n - 1n],
        ])("reads %s up to its bound", (path, value, read, expected) => {
            expect(read(decodeWith("SendCommitmentSigned", `settlement.${path}`, value))).toBe(expected);
        });

        it.each([
            ["tlcs[0].inbound", false, "offered"],
            ["tlcs[1].inbound", true, "received"],
        ] as const)("reads %s = %p as the direction %s", (path, inbound, direction) => {
            const index = path === "tlcs[0].inbound" ? 0 : 1;
            expect(decodeWith("SendCommitmentSigned", `settlement.${path}`, inbound).settlement?.tlcs[index]?.direction).toBe(direction);
        });

        it("reads up to 255 TLCs and refuses the 256th", () => {
            const tlc = (statusOf("SendCommitmentSigned").settlement as { tlcs: unknown[] }).tlcs[0];
            const full = Array.from({ length: 255 }, () => tlc);
            expect(decodeWith("SendCommitmentSigned", "settlement.tlcs", full).settlement?.tlcs).toHaveLength(255);
            expectRefused("SendCommitmentSigned", "settlement.tlcs", [...full, tlc], "must have at most 255 items");
            expect(decodeWith("SendCommitmentSigned", "settlement.tlcs", []).settlement?.tlcs).toEqual([]);
        });

        it.each([
            ["local_amount", undefined, UINT_HEX],
            ["local_amount", null, UINT_HEX],
            ["local_amount", ABOVE_U128, UINT_HEX],
            ["local_amount", "0x00", UINT_HEX],
            ["remote_amount", undefined, UINT_HEX],
            ["remote_amount", null, UINT_HEX],
            ["remote_amount", ABOVE_U128, UINT_HEX],
            ["local_settlement_pubkey", undefined, PUBKEY_HEX],
            ["local_settlement_pubkey", null, PUBKEY_HEX],
            ["local_settlement_pubkey", `0x${OFF_CURVE_KEY}`, PUBKEY_HEX],
            ["local_settlement_pubkey", OFF_CURVE_KEY, ON_CURVE],
            ["remote_settlement_pubkey", undefined, PUBKEY_HEX],
            ["remote_settlement_pubkey", null, PUBKEY_HEX],
            ["remote_settlement_pubkey", OFF_CURVE_KEY.toUpperCase(), PUBKEY_HEX],
            ["remote_settlement_pubkey", OFF_CURVE_KEY, ON_CURVE],
            ["for_remote", undefined, BOOLEAN],
            ["for_remote", null, BOOLEAN],
            ["for_remote", "true", BOOLEAN],
            ["tlcs", undefined, "must be an array"],
            ["tlcs", {}, "must be an array"],
            ["tlcs", null, "must be an array"],
            ["tlcs[0]", null, OBJECT],
            ["tlcs[0].tlc_id", undefined, UINT_HEX],
            ["tlcs[0].tlc_id", null, UINT_HEX],
            ["tlcs[0].tlc_id", ABOVE_MAX_SAFE_INTEGER_HEX, "must be at most 9007199254740991"],
            ["tlcs[0].local_key_commitment_number", undefined, UINT_HEX],
            ["tlcs[0].local_key_commitment_number", null, UINT_HEX],
            ["tlcs[0].local_key_commitment_number", ABOVE_MAX_COMMITMENT_HEX, "must be at most 281474976710655"],
            ["tlcs[0].inbound", undefined, BOOLEAN],
            ["tlcs[0].inbound", null, BOOLEAN],
            ["tlcs[0].inbound", 1, BOOLEAN],
            ["tlcs[0].payment_hash", undefined, HEX_32],
            ["tlcs[0].payment_hash", null, HEX_32],
            ["tlcs[0].payment_hash", `0x${"ab".repeat(31)}`, HEX_32],
            ["tlcs[0].payment_amount", undefined, UINT_HEX],
            ["tlcs[0].payment_amount", null, UINT_HEX],
            ["tlcs[0].payment_amount", ABOVE_U128, UINT_HEX],
            ["tlcs[0].hash_algorithm", undefined, "must be one of ckb_hash, sha256"],
            ["tlcs[0].hash_algorithm", null, "must be one of ckb_hash, sha256"],
            ["tlcs[0].hash_algorithm", "ckb-hash", "must be one of ckb_hash, sha256"],
            ["tlcs[0].expiry", undefined, UINT_HEX],
            ["tlcs[0].expiry", null, UINT_HEX],
            ["tlcs[0].expiry", ABOVE_U64, "must be at most 18446744073709551615"],
            ["tlcs[0].local_key_pubkey", undefined, PUBKEY_HEX],
            ["tlcs[0].local_key_pubkey", null, PUBKEY_HEX],
            ["tlcs[0].local_key_pubkey", OFF_CURVE_KEY, ON_CURVE],
            ["tlcs[0].remote_key", undefined, PUBKEY_HEX],
            ["tlcs[0].remote_key", null, PUBKEY_HEX],
            ["tlcs[0].remote_key", OFF_CURVE_KEY, ON_CURVE],
            ["tlcs[2].remote_key", OFF_CURVE_KEY, ON_CURVE],
        ])("refuses settlement.%s = %p", (path, value, reason) => {
            for (const transition of COMMITMENT_TRANSITIONS) expectRefused(transition, `settlement.${path}`, value, reason);
        });
    });
});
