import type { ScriptHashType } from "../common";
import type { TLC_HASH_ALGORITHMS } from "./wire.constants";

export type Field = { value: unknown; path: string };

export type FieldReader<Wire> = (name: keyof Wire & string) => Field;

/**
 * Bytes as `0x`-prefixed lowercase hex.
 */
export type HexWire = string;

/**
 * Integers wider than a count: `0x` hex without leading zeros, fiber's `U64Hex` and `U128Hex`.
 */
export type UintHexWire = string;

export type TlcHashAlgorithmWire = keyof typeof TLC_HASH_ALGORITHMS;

export type ScriptWire = { code_hash: HexWire; hash_type: ScriptHashType; args: HexWire };

export type OutPointWire = { tx_hash: HexWire; index: UintHexWire };
