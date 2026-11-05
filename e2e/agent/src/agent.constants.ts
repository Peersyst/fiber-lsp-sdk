import type { ScriptHashType } from "@peersyst/fiber-lsp-sdk";
import type { AgentHashAlgorithm, AgentNetworkName } from "./agent.types";

export const AGENT_NETWORK_NAMES: readonly AgentNetworkName[] = ["devnet", "testnet"];

export const HASH_ALGORITHMS: readonly AgentHashAlgorithm[] = ["ckb_hash", "sha256"];

export const SCRIPT_HASH_TYPES: readonly ScriptHashType[] = ["data", "type", "data1", "data2"];

// Hashes and keys are kept as they were written, so either case passes.
export const BYTES32_HEX_PATTERN = /^0x[0-9a-fA-F]{64}$/;

// A timer's delay: within a signed 32-bit integer, past which Node fires it after 1 ms.
export const MAX_TIMER_DELAY_MS = 2 ** 31 - 1;

export const UINT32_MAX = 0xffff_ffffn;

export const UINT64_MAX = (1n << 64n) - 1n;

export const HASH256_HEX_LENGTH = 64;

export const HEX_BYTES_PATTERN = /^0x(?:[0-9a-fA-F]{2})*$/;

export const OPEN_CHANNEL_WITH_EXTERNAL_FUNDING_METHOD = "open_channel_with_external_funding";
