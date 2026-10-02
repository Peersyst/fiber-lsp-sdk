import { readFileSync } from "node:fs";
import { join } from "node:path";
import { asScript, type ScriptVector } from "./interop-vectors";
import { asList, asNullable, asPresent, asRecord, asString, asStringFields } from "./json-shape";

export const FIBER_VERDICTS = ["accepted", "rewritten", "refused", "panicked"] as const;

export type FiberVerdict = (typeof FIBER_VERDICTS)[number];

export type InvoiceAttributeVector =
    | { type: "expiry_time" | "final_htlc_timeout" | "final_htlc_minimum_expiry_delta"; value: string }
    | { type: "description" | "fallback_addr" | "feature" | "payee_public_key" | "hash_algorithm" | "payment_secret"; value: string }
    | { type: "udt_script"; value: ScriptVector };

export type InvoiceValuesVector = {
    currency: string;
    amount: string | null;
    timestamp: string;
    payment_hash: string;
    attrs: InvoiceAttributeVector[];
};

export type InvoiceCaseVector = {
    name: string;
    values: InvoiceValuesVector;
    molecule: string;
    compressed: string;
    digest: string;
    signature: string | null;
    string: string;
};

export type CompressCaseVector = { name: string; data: string; compressed: string };

export type DecompressCaseVector = { name: string; compressed: string; data: string | null };

export type Utf8CaseVector = { name: string; bytes: string; text: string | null };

export type VariantCaseVector = { name: string; string: string; fiber: FiberVerdict; error: string | null };

export type InvoiceVectors = {
    fiber_ref: string;
    payee_secret_key: string;
    payee_public_key: string;
    invoices: InvoiceCaseVector[];
    coder: { compress: CompressCaseVector[]; decompress: DecompressCaseVector[] };
    utf8: Utf8CaseVector[];
    variants: VariantCaseVector[];
};

function asAttribute(value: unknown, path: string): InvoiceAttributeVector {
    const record = asRecord(value, path);
    const type = asString(record.type, `${path}.type`);
    if (type === "udt_script") return { type, value: asScript(record.value, `${path}.value`) };
    return { type, value: asString(record.value, `${path}.value`) } as InvoiceAttributeVector;
}

function asInvoiceCase(value: unknown, path: string): InvoiceCaseVector {
    const record = asRecord(value, path);
    const values = asRecord(record.values, `${path}.values`);
    return {
        values: {
            amount: asNullable(values.amount, `${path}.values.amount`, asString),
            attrs: asList(values.attrs, `${path}.values.attrs`, asAttribute),
            ...asStringFields(values, `${path}.values`, ["currency", "timestamp", "payment_hash"] as const),
        },
        signature: asNullable(record.signature, `${path}.signature`, asString),
        ...asStringFields(record, path, ["name", "molecule", "compressed", "digest", "string"] as const),
    };
}

function asVerdict(value: unknown, path: string): FiberVerdict {
    const verdict = asString(value, path);
    if (!(FIBER_VERDICTS as readonly string[]).includes(verdict)) throw new Error(`${path} must be a verdict`);
    return verdict as FiberVerdict;
}

export function parseInvoiceVectors(value: unknown): InvoiceVectors {
    const root = asRecord(value, "invoice vectors");
    const coder = asRecord(root.coder, "coder");
    return {
        ...asStringFields(root, "invoice vectors", ["fiber_ref", "payee_secret_key", "payee_public_key"] as const),
        invoices: asList(root.invoices, "invoices", asInvoiceCase),
        coder: {
            compress: asList(coder.compress, "coder.compress", (entry, at) =>
                asStringFields(entry, at, ["name", "data", "compressed"] as const),
            ),
            decompress: asList(coder.decompress, "coder.decompress", (entry, at) => {
                const record = asRecord(entry, at);
                return {
                    data: asNullable(record.data, `${at}.data`, asString),
                    ...asStringFields(record, at, ["name", "compressed"] as const),
                };
            }),
        },
        utf8: asList(root.utf8, "utf8", (entry, at) => {
            const record = asRecord(entry, at);
            return { text: asNullable(record.text, `${at}.text`, asString), ...asStringFields(record, at, ["name", "bytes"] as const) };
        }),
        variants: asList(root.variants, "variants", (entry, at) => {
            const record = asRecord(entry, at);
            return {
                fiber: asVerdict(record.fiber, `${at}.fiber`),
                error: asNullable(asPresent(record.error, `${at}.error`), `${at}.error`, asString),
                ...asStringFields(record, at, ["name", "string"] as const),
            };
        }),
    };
}

export function loadInvoiceVectors(): InvoiceVectors {
    const path = join(__dirname, "../../interop/vectors/invoice.json");
    return parseInvoiceVectors(JSON.parse(readFileSync(path, "utf8")));
}
