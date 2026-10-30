import type { ScriptHashType } from "@peersyst/fiber-lsp-sdk";
import type { AgentHashAlgorithm } from "./agent.types";

export const HASH_ALGORITHMS: readonly AgentHashAlgorithm[] = ["ckb_hash", "sha256"];

export const SCRIPT_HASH_TYPES: readonly ScriptHashType[] = ["data", "type", "data1", "data2"];

// Script fields are kept as the driver wrote them, so either case passes.
export const SCRIPT_CODE_HASH_PATTERN = /^0x[0-9a-fA-F]{64}$/;

export const HEX_BYTES_PATTERN = /^0x(?:[0-9a-fA-F]{2})*$/;

export const OPEN_TENANT_CHANNEL_METHOD = "open_tenant_channel";
