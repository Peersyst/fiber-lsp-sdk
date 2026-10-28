import { secp256k1 } from "@noble/curves/secp256k1.js";
import type { Invoice, UnsignedInvoice } from "../../src/invoice";
import { computeInvoiceDigest } from "../../src/invoice";

// Fiber's `sign_ecdsa_recoverable` over the invoice's digest, low-S, written `r || s || recovery id`.
export function signInvoice(invoice: UnsignedInvoice, secretKey: Uint8Array): Invoice {
    const recovered = secp256k1.sign(computeInvoiceDigest(invoice), secretKey, { prehash: false, format: "recovered" });
    return { ...invoice, signature: Uint8Array.from([...recovered.subarray(1), recovered[0] ?? 0]) };
}
