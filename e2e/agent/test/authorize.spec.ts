import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { AgentRequestError } from "../src/agent.error";
import { assertPreimageMatches, readAuthorization } from "../src/authorize";

const CHANNEL_ID = "0x446ff736f9f4df89d8b601fd0005107b50f00453f5ebf1d2ce2ebbe9b75cd7b8";
const PREIMAGE = "0x2222222222222222222222222222222222222222222222222222222222222222";
const CKB_HASH = "0x09dfb3a3fa5af1b3359b6256945af43e31be9f86f3d1b45779cebc09dc609138";
const SHA256_HASH = "0x9f72ea0cf49536e3c66c787f705186df9a4378083753ae9536d65b3ad7fcddc4";

const FUNDING_SCRIPT = {
    code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
    hash_type: "type",
    args: "0x75178f34549c5fe9cd1a0c57aebd01e7ddf9249e",
};
const PEER_SHUTDOWN_SCRIPT = {
    code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
    hash_type: "type",
    args: "0x470dcdc5e44064909650113a274b3b36aecb6dc7",
};

// The suites' bodies, their variables filled.
const INVOICE_BODY = {
    type: "Invoice",
    channel_id: CHANNEL_ID,
    preimage: PREIMAGE,
    terms: {
        payment_hash: CKB_HASH,
        hash_algorithm: "ckb_hash",
        inbound: true,
        amount: 1000000,
        expires_at_ms: 1793174400000,
        min_tlc_expiry_delta_ms: 86400000,
        max_tlc_expiry_ms: 1793782800000,
    },
};
const RELEASE_TO_WATCHTOWER_BODY = {
    type: "ReleasePreimage",
    channel_id: CHANNEL_ID,
    payment_hash: CKB_HASH,
    preimage: PREIMAGE,
    target: "Watchtower",
};
const RELEASE_TO_INVOICE_BODY = {
    type: "ReleasePreimage",
    channel_id: CHANNEL_ID,
    payment_hash: CKB_HASH,
    preimage: PREIMAGE,
    target: "Invoice",
};
const CLOSE_BODY = {
    type: "Close",
    channel_id: CHANNEL_ID,
    local_script: FUNDING_SCRIPT,
    remote_script: PEER_SHUTDOWN_SCRIPT,
    local_fee_rate: 1000,
    remote_fee_rate: 0,
};
const WATCHTOWER_BODY = { type: "Watchtower", channel_id: CHANNEL_ID, destination: PEER_SHUTDOWN_SCRIPT, max_fee: 10000 };

function patched(body: object, patch: Record<string, unknown>): Record<string, unknown> {
    const next: Record<string, unknown> = { ...structuredClone(body), ...patch };
    for (const [key, value] of Object.entries(patch)) if (value === undefined) delete next[key];
    return next;
}

function withTerms(patch: Record<string, unknown>): Record<string, unknown> {
    return patched(INVOICE_BODY, { terms: patched(INVOICE_BODY.terms, patch) });
}

function refuses(body: unknown, field: string): void {
    assert.throws(
        () => readAuthorization(body),
        (error: unknown) => error instanceof AgentRequestError && error.message.includes(field),
    );
}

describe("readAuthorization", () => {
    describe("the suites' bodies", () => {
        it("reads Invoice, keeping the hash and its algorithm", () => {
            assert.deepEqual(readAuthorization(INVOICE_BODY), {
                type: "Invoice",
                channelId: CHANNEL_ID,
                preimage: PREIMAGE,
                paymentHash: CKB_HASH,
                hashAlgorithm: "ckb_hash",
            });
        });

        it("reads ReleasePreimage to each target", () => {
            assert.deepEqual(readAuthorization(RELEASE_TO_WATCHTOWER_BODY), {
                type: "ReleasePreimage",
                channelId: CHANNEL_ID,
                paymentHash: CKB_HASH,
                preimage: PREIMAGE,
                target: "Watchtower",
            });
            assert.deepEqual(readAuthorization(RELEASE_TO_INVOICE_BODY), {
                type: "ReleasePreimage",
                channelId: CHANNEL_ID,
                paymentHash: CKB_HASH,
                preimage: PREIMAGE,
                target: "Invoice",
            });
        });

        it("reads Close, the rates as decimal strings", () => {
            assert.deepEqual(readAuthorization(CLOSE_BODY), {
                type: "Close",
                channelId: CHANNEL_ID,
                localScript: FUNDING_SCRIPT,
                remoteScript: PEER_SHUTDOWN_SCRIPT,
                localFeeRate: "1000",
                remoteFeeRate: "0",
            });
        });

        it("reads Watchtower, the fee cap as decimal shannons", () => {
            assert.deepEqual(readAuthorization(WATCHTOWER_BODY), {
                type: "Watchtower",
                channelId: CHANNEL_ID,
                destination: PEER_SHUTDOWN_SCRIPT,
                maxFeeShannons: "10000",
            });
        });
    });

    it("normalises hashes, preimages and channel ids to 0x lowercase", () => {
        const read = readAuthorization(
            patched(RELEASE_TO_INVOICE_BODY, {
                channel_id: CHANNEL_ID.slice(2).toUpperCase(),
                payment_hash: CKB_HASH.toUpperCase().replace("0X", "0x"),
                preimage: PREIMAGE.slice(2),
            }),
        );
        assert.deepEqual(read, {
            type: "ReleasePreimage",
            channelId: CHANNEL_ID,
            paymentHash: CKB_HASH,
            preimage: PREIMAGE,
            target: "Invoice",
        });
        const invoice = readAuthorization(withTerms({ payment_hash: CKB_HASH.slice(2).toUpperCase() }));
        assert.equal(invoice.type === "Invoice" && invoice.paymentHash, CKB_HASH);
    });

    it("ignores unknown fields, as serde does in fiber's agent", () => {
        assert.deepEqual(readAuthorization(patched(WATCHTOWER_BODY, { note: "x" })), readAuthorization(WATCHTOWER_BODY));
        assert.deepEqual(readAuthorization(withTerms({ note: "x" })), readAuthorization(INVOICE_BODY));
    });

    it("refuses a body that is not an object", () => {
        refuses(null, "body");
        refuses([WATCHTOWER_BODY], "body");
        refuses("Watchtower", "body");
    });

    it("refuses an absent, unknown or misspelt type", () => {
        refuses(patched(WATCHTOWER_BODY, { type: undefined }), "type");
        refuses(patched(WATCHTOWER_BODY, { type: "watchtower" }), "type");
        refuses(patched(RELEASE_TO_INVOICE_BODY, { type: "Release_Preimage" }), "type");
        refuses(patched(CLOSE_BODY, { type: "CLOSE" }), "type");
        refuses(patched(INVOICE_BODY, { type: "Payment" }), "type");
    });

    for (const body of [INVOICE_BODY, RELEASE_TO_INVOICE_BODY, CLOSE_BODY, WATCHTOWER_BODY]) {
        it(`refuses ${body.type} with an absent or malformed channel_id`, () => {
            refuses(patched(body, { channel_id: undefined }), "channel_id");
            refuses(patched(body, { channel_id: CHANNEL_ID.slice(0, -2) }), "channel_id");
            refuses(patched(body, { channel_id: `${CHANNEL_ID}00` }), "channel_id");
            refuses(patched(body, { channel_id: `${CHANNEL_ID.slice(0, -1)}g` }), "channel_id");
            refuses(patched(body, { channel_id: `0X${CHANNEL_ID.slice(2)}` }), "channel_id");
        });
    }

    describe("Invoice", () => {
        it("refuses an absent or malformed preimage", () => {
            refuses(patched(INVOICE_BODY, { preimage: undefined }), "preimage");
            refuses(patched(INVOICE_BODY, { preimage: PREIMAGE.slice(0, -2) }), "preimage");
            refuses(patched(INVOICE_BODY, { preimage: 22 }), "preimage");
        });

        it("refuses absent or non-object terms", () => {
            refuses(patched(INVOICE_BODY, { terms: undefined }), "terms");
            refuses(patched(INVOICE_BODY, { terms: null }), "terms");
            refuses(patched(INVOICE_BODY, { terms: [] }), "terms");
        });

        it("refuses an absent or malformed payment_hash", () => {
            refuses(withTerms({ payment_hash: undefined }), "terms.payment_hash");
            refuses(withTerms({ payment_hash: CKB_HASH.slice(0, -2) }), "terms.payment_hash");
        });

        it("reads each hash_algorithm, its spelling exact", () => {
            const sha = readAuthorization(withTerms({ payment_hash: SHA256_HASH, hash_algorithm: "sha256" }));
            assert.equal(sha.type === "Invoice" && sha.hashAlgorithm, "sha256");
            refuses(withTerms({ hash_algorithm: undefined }), "terms.hash_algorithm");
            refuses(withTerms({ hash_algorithm: "ckb-hash" }), "terms.hash_algorithm");
            refuses(withTerms({ hash_algorithm: "CkbHash" }), "terms.hash_algorithm");
            refuses(withTerms({ hash_algorithm: "Sha256" }), "terms.hash_algorithm");
        });

        it("refuses an absent or non-boolean inbound", () => {
            refuses(withTerms({ inbound: undefined }), "terms.inbound must be a boolean");
            refuses(withTerms({ inbound: "true" }), "terms.inbound must be a boolean");
            refuses(withTerms({ inbound: 1 }), "terms.inbound must be a boolean");
        });

        it("refuses an outgoing payment, as fiber's authorize_invoice", () => {
            refuses(withTerms({ inbound: false }), "terms.inbound must be true: an Invoice authorizes an incoming payment");
        });

        it("refuses a preimage that does not hash to the payment hash, as fiber's authorize_invoice", () => {
            refuses(patched(INVOICE_BODY, { preimage: `0x${"22".repeat(31)}23` }), "preimage does not hash to payment_hash under ckb_hash");
            refuses(withTerms({ hash_algorithm: "sha256" }), "preimage does not hash to payment_hash under sha256");
        });

        for (const field of ["amount", "expires_at_ms", "min_tlc_expiry_delta_ms", "max_tlc_expiry_ms"]) {
            it(`refuses an absent or non-integer ${field}, and accepts 0`, () => {
                assert.doesNotThrow(() => readAuthorization(withTerms({ [field]: 0 })));
                refuses(withTerms({ [field]: undefined }), `terms.${field}`);
                refuses(withTerms({ [field]: -1 }), `terms.${field}`);
                refuses(withTerms({ [field]: 1.5 }), `terms.${field}`);
                refuses(withTerms({ [field]: "1000000" }), `terms.${field}`);
                refuses(withTerms({ [field]: 2 ** 53 }), `terms.${field}`);
            });
        }
    });

    describe("ReleasePreimage", () => {
        it("refuses an absent or malformed payment_hash", () => {
            refuses(patched(RELEASE_TO_INVOICE_BODY, { payment_hash: undefined }), "payment_hash");
            refuses(patched(RELEASE_TO_INVOICE_BODY, { payment_hash: `${CKB_HASH}00` }), "payment_hash");
        });

        it("refuses an absent or malformed preimage", () => {
            refuses(patched(RELEASE_TO_INVOICE_BODY, { preimage: undefined }), "preimage");
            refuses(patched(RELEASE_TO_INVOICE_BODY, { preimage: "placeholder" }), "preimage");
        });

        it("refuses an absent or misspelt target", () => {
            refuses(patched(RELEASE_TO_INVOICE_BODY, { target: undefined }), "target");
            refuses(patched(RELEASE_TO_INVOICE_BODY, { target: "invoice" }), "target");
            refuses(patched(RELEASE_TO_INVOICE_BODY, { target: "WATCHTOWER" }), "target");
            refuses(patched(RELEASE_TO_INVOICE_BODY, { target: "Close" }), "target");
        });
    });

    describe("Close", () => {
        for (const field of ["local_script", "remote_script"]) {
            it(`refuses an absent or malformed ${field}`, () => {
                refuses(patched(CLOSE_BODY, { [field]: undefined }), field);
                refuses(patched(CLOSE_BODY, { [field]: {} }), `${field}.code_hash`);
                refuses(patched(CLOSE_BODY, { [field]: { ...FUNDING_SCRIPT, hash_type: "Data" } }), `${field}.hash_type`);
                refuses(patched(CLOSE_BODY, { [field]: { ...FUNDING_SCRIPT, args: "0x1" } }), `${field}.args`);
                refuses(patched(CLOSE_BODY, { [field]: { ...FUNDING_SCRIPT, extra: "0x" } }), `${field}.extra`);
            });
        }

        for (const field of ["local_fee_rate", "remote_fee_rate"]) {
            it(`refuses an absent or non-integer ${field}, and accepts 0 and the largest exact integer`, () => {
                const largest = readAuthorization(patched(CLOSE_BODY, { [field]: Number.MAX_SAFE_INTEGER }));
                assert.equal(
                    largest.type === "Close" && (field === "local_fee_rate" ? largest.localFeeRate : largest.remoteFeeRate),
                    "9007199254740991",
                );
                assert.doesNotThrow(() => readAuthorization(patched(CLOSE_BODY, { [field]: 0 })));
                refuses(patched(CLOSE_BODY, { [field]: undefined }), field);
                refuses(patched(CLOSE_BODY, { [field]: -1 }), field);
                refuses(patched(CLOSE_BODY, { [field]: 1000.5 }), field);
                refuses(patched(CLOSE_BODY, { [field]: "0x3e8" }), field);
                refuses(patched(CLOSE_BODY, { [field]: 2 ** 53 }), field);
            });
        }
    });

    describe("Watchtower", () => {
        it("refuses an absent or malformed destination", () => {
            refuses(patched(WATCHTOWER_BODY, { destination: undefined }), "destination");
            refuses(patched(WATCHTOWER_BODY, { destination: { ...PEER_SHUTDOWN_SCRIPT, code_hash: "0x00" } }), "destination.code_hash");
            refuses(patched(WATCHTOWER_BODY, { destination: { ...PEER_SHUTDOWN_SCRIPT, hash_type: undefined } }), "destination.hash_type");
        });

        it("accepts a max_fee of 1 and refuses 0", () => {
            const one = readAuthorization(patched(WATCHTOWER_BODY, { max_fee: 1 }));
            assert.equal(one.type === "Watchtower" && one.maxFeeShannons, "1");
            refuses(patched(WATCHTOWER_BODY, { max_fee: 0 }), "max_fee");
        });

        it("refuses an absent or non-integer max_fee", () => {
            refuses(patched(WATCHTOWER_BODY, { max_fee: undefined }), "max_fee");
            refuses(patched(WATCHTOWER_BODY, { max_fee: "10000" }), "max_fee");
            refuses(patched(WATCHTOWER_BODY, { max_fee: 10000.5 }), "max_fee");
            refuses(patched(WATCHTOWER_BODY, { max_fee: -10000 }), "max_fee");
            refuses(patched(WATCHTOWER_BODY, { max_fee: 2 ** 53 }), "max_fee");
        });
    });
});

describe("assertPreimageMatches", () => {
    it("accepts the suites' pair under ckb_hash", () => {
        assert.doesNotThrow(() => assertPreimageMatches(CKB_HASH, PREIMAGE, "ckb_hash"));
    });

    it("accepts the same preimage's sha256 under sha256", () => {
        assert.doesNotThrow(() => assertPreimageMatches(SHA256_HASH, PREIMAGE, "sha256"));
    });

    it("accepts both without 0x and in upper case", () => {
        assert.doesNotThrow(() => assertPreimageMatches(CKB_HASH.slice(2).toUpperCase(), PREIMAGE.slice(2), "ckb_hash"));
    });

    it("refuses each hash under the other algorithm", () => {
        assert.throws(() => assertPreimageMatches(CKB_HASH, PREIMAGE, "sha256"), AgentRequestError);
        assert.throws(() => assertPreimageMatches(SHA256_HASH, PREIMAGE, "ckb_hash"), AgentRequestError);
    });

    it("refuses another preimage under each algorithm", () => {
        const other = `0x${"22".repeat(31)}23`;
        assert.throws(() => assertPreimageMatches(CKB_HASH, other, "ckb_hash"), AgentRequestError);
        assert.throws(() => assertPreimageMatches(SHA256_HASH, other, "sha256"), AgentRequestError);
    });

    it("refuses a malformed hash or preimage", () => {
        assert.throws(() => assertPreimageMatches(CKB_HASH.slice(0, -2), PREIMAGE, "ckb_hash"), AgentRequestError);
        assert.throws(() => assertPreimageMatches(CKB_HASH, PREIMAGE.slice(0, -2), "ckb_hash"), AgentRequestError);
    });
});
