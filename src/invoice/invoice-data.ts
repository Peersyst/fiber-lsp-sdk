import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
    COMPRESSED_POINT_LENGTH,
    HASH256_LENGTH,
    PAYMENT_HASH_LENGTH,
    TLC_HASH_ALGORITHMS,
    TLC_HASH_ALGORITHM_BYTES,
    UINT128_LENGTH,
    UINT128_MAX,
    UINT64_LENGTH,
    UINT64_MAX,
    assertAnyBytes,
    assertBytes,
    assertOneOf,
    assertUnsignedBigInt,
    isPlainObject,
    moleculeBytes,
    moleculeDynvec,
    moleculeScript,
    moleculeTable,
    uint128Le,
    uint32Le,
    uint64Le,
} from "../common";
import { INVOICE_ATTRIBUTE_TYPES, MAX_INVOICE_DATA_LENGTH } from "./invoice.constants";
import { refuseInvoice } from "./invoice.error";
import type { InvoiceAttribute, InvoiceAttributeType, UnsignedInvoice } from "./invoice.types";
import {
    decodeInvoiceUtf8,
    encodeInvoiceUtf8,
    readInvoiceMoleculeBytes,
    readInvoiceMoleculeDynvec,
    readInvoiceMoleculeFixed,
    readInvoiceMoleculeScript,
    readInvoiceMoleculeTable,
    readInvoiceMoleculeUint,
    readInvoiceMoleculeUnion,
} from "./utils";

/**
 * What the molecule `RawInvoiceData` carries.
 */
export type InvoiceData = Pick<UnsignedInvoice, "timestampMs" | "paymentHash" | "attributes">;

const RAW_INVOICE_DATA_FIELDS = 3;

/**
 * Checks that a public key is a compressed secp256k1 point, the only form fiber writes.
 * @param publicKey The key.
 * @returns Whether it is one.
 */
function isCompressedPoint(publicKey: Uint8Array): boolean {
    if (publicKey.length !== COMPRESSED_POINT_LENGTH) return false;
    try {
        secp256k1.Point.fromBytes(publicKey);
        return true;
    } catch {
        return false;
    }
}

/**
 * Serializes one attribute's union item body, the part after its id.
 * @param attribute The attribute.
 * @param name Its path, used in the error message.
 * @returns The item's bytes.
 */
function encodeAttributeItem(attribute: InvoiceAttribute, name: string): Uint8Array {
    switch (attribute.type) {
        case "expiryTime":
            assertUnsignedBigInt(`${name}.seconds`, attribute.seconds, UINT64_MAX);
            return uint64Le(attribute.seconds);
        case "description":
            return moleculeTable([moleculeBytes(encodeInvoiceUtf8(`${name}.text`, attribute.text))]);
        case "finalHtlcTimeout":
        case "finalHtlcMinimumExpiryDelta":
            assertUnsignedBigInt(`${name}.milliseconds`, attribute.milliseconds, UINT64_MAX);
            return uint64Le(attribute.milliseconds);
        case "fallbackAddr":
            return moleculeTable([moleculeBytes(encodeInvoiceUtf8(`${name}.address`, attribute.address))]);
        case "feature":
            assertAnyBytes(`${name}.bits`, attribute.bits);
            return moleculeTable([moleculeBytes(attribute.bits)]);
        case "udtScript":
            return moleculeTable([moleculeScript(attribute.script, `${name}.script`)]);
        case "payeePublicKey":
            if (!(attribute.publicKey instanceof Uint8Array) || !isCompressedPoint(attribute.publicKey)) {
                throw new TypeError(`${name}.publicKey must be a 33-byte compressed public key`);
            }
            return moleculeTable([moleculeBytes(attribute.publicKey)]);
        case "hashAlgorithm":
            assertOneOf(`${name}.algorithm`, attribute.algorithm, TLC_HASH_ALGORITHMS);
            return Uint8Array.of(TLC_HASH_ALGORITHM_BYTES[attribute.algorithm]);
        case "paymentSecret":
            assertBytes(`${name}.secret`, attribute.secret, HASH256_LENGTH);
            return attribute.secret;
    }
}

/**
 * Serializes an invoice's data as the molecule `RawInvoiceData` fiber compresses and signs.
 * @param data The timestamp, the payment hash and the attributes.
 * @returns The molecule bytes.
 */
export function encodeInvoiceData(data: InvoiceData): Uint8Array {
    assertUnsignedBigInt("timestampMs", data.timestampMs, UINT128_MAX);
    assertBytes("paymentHash", data.paymentHash, PAYMENT_HASH_LENGTH);
    if (!Array.isArray(data.attributes)) throw new TypeError("attributes must be an array");
    const seen = new Set<string>();
    const items = data.attributes.map((attribute, index) => {
        const name = `attributes[${index}]`;
        if (!isPlainObject(attribute)) throw new TypeError(`${name} must be an object`);
        assertOneOf(`${name}.type`, attribute.type, INVOICE_ATTRIBUTE_TYPES);
        // Fiber's builder never writes a type twice, and its getters would read only the first.
        if (seen.has(attribute.type)) throw new TypeError(`${name} must not repeat an attribute type`);
        seen.add(attribute.type);
        return new Uint8Array([...uint32Le(INVOICE_ATTRIBUTE_TYPES.indexOf(attribute.type)), ...encodeAttributeItem(attribute, name)]);
    });
    const bytes = moleculeTable([uint128Le(data.timestampMs), data.paymentHash, moleculeDynvec(items)]);
    if (bytes.length > MAX_INVOICE_DATA_LENGTH) throw new RangeError(`the invoice data must be at most ${MAX_INVOICE_DATA_LENGTH} bytes`);
    return bytes;
}

/**
 * Reads the body of a union item that is a one-field table of `Bytes`.
 * @param item The item.
 * @param path What is being read, named in a refusal.
 * @returns The raw data.
 */
function readBytesTable(item: Uint8Array, path: string): Uint8Array {
    const [value] = readInvoiceMoleculeTable(item, 1, path) as [Uint8Array];
    return readInvoiceMoleculeBytes(value, `${path}.value`).slice();
}

/**
 * Reads one attribute from its union item.
 * @param type The attribute type its item id selects.
 * @param item The item's bytes.
 * @param path What is being read, named in a refusal.
 * @returns The attribute.
 */
function decodeAttributeItem(type: InvoiceAttributeType, item: Uint8Array, path: string): InvoiceAttribute {
    switch (type) {
        case "expiryTime":
            return { type, seconds: readInvoiceMoleculeUint(item, UINT64_LENGTH, path) };
        case "description":
            return { type, text: decodeInvoiceUtf8(readBytesTable(item, path), `${path}.value`) };
        case "finalHtlcTimeout":
        case "finalHtlcMinimumExpiryDelta":
            return { type, milliseconds: readInvoiceMoleculeUint(item, UINT64_LENGTH, path) };
        case "fallbackAddr":
            return { type, address: decodeInvoiceUtf8(readBytesTable(item, path), `${path}.value`) };
        case "feature":
            return { type, bits: readBytesTable(item, path) };
        case "udtScript": {
            const [script] = readInvoiceMoleculeTable(item, 1, path) as [Uint8Array];
            return { type, script: readInvoiceMoleculeScript(script, `${path}.value`) };
        }
        case "payeePublicKey": {
            const publicKey = readBytesTable(item, path);
            if (!isCompressedPoint(publicKey)) refuseInvoice(`${path}.value`, "must be a 33-byte compressed public key");
            return { type, publicKey };
        }
        case "hashAlgorithm": {
            const byte = readInvoiceMoleculeFixed(item, 1, path)[0];
            // Fiber reads any other byte as ckb-hash and writes it back as 0.
            const algorithm = TLC_HASH_ALGORITHMS.find((candidate) => TLC_HASH_ALGORITHM_BYTES[candidate] === byte);
            if (algorithm === undefined) refuseInvoice(path, "must be 0 (ckb-hash) or 1 (sha256)");
            return { type, algorithm };
        }
        case "paymentSecret":
            return { type, secret: readInvoiceMoleculeFixed(item, HASH256_LENGTH, path).slice() };
    }
}

/**
 * Reads a molecule `RawInvoiceData`, refusing what fiber would write back otherwise and repeated attribute types.
 * @param bytes The molecule bytes.
 * @returns The timestamp, the payment hash and the attributes.
 */
export function decodeInvoiceData(bytes: Uint8Array): InvoiceData {
    const [timestamp, paymentHash, attributes] = readInvoiceMoleculeTable(bytes, RAW_INVOICE_DATA_FIELDS, "data") as [
        Uint8Array,
        Uint8Array,
        Uint8Array,
    ];
    const seen = new Set<string>();
    return {
        timestampMs: readInvoiceMoleculeUint(timestamp, UINT128_LENGTH, "data.timestamp"),
        paymentHash: readInvoiceMoleculeFixed(paymentHash, PAYMENT_HASH_LENGTH, "data.paymentHash").slice(),
        attributes: readInvoiceMoleculeDynvec(attributes, "data.attributes").map((union, index) => {
            const path = `data.attributes[${index}]`;
            const { name, item } = readInvoiceMoleculeUnion(union, INVOICE_ATTRIBUTE_TYPES, path);
            const attribute = decodeAttributeItem(name, item, `${path}.${name}`);
            if (seen.has(attribute.type)) refuseInvoice(path, "must not repeat an attribute type");
            seen.add(attribute.type);
            return attribute;
        }),
    };
}
