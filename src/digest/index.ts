export { COMMITMENT_LOCK_MAINNET, COMMITMENT_LOCK_TESTNET, MAX_SETTLEMENT_TLCS } from "./digest.constants";
export type {
    ChannelAnnouncementInput,
    CommitmentTxInput,
    OutPoint,
    RevocationInput,
    Script,
    ScriptHashType,
    ScriptTemplate,
    SettlementTlc,
    ShutdownTxInput,
    TlcDirection,
    TlcHashAlgorithm,
} from "./digest.types";
export { computeChannelAnnouncementDigest } from "./channel-announcement";
export { computeCommitmentTxDigest } from "./commitment-tx";
export { computeRevocationDigest } from "./revocation";
export { computeShutdownTxDigest } from "./shutdown-tx";
