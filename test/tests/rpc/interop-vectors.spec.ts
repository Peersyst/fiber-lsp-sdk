import { writeFileSync } from "node:fs";
import { UINT128_MAX, UINT64_MAX } from "../../../src/common";
import type { RpcMethod, RpcParamsWire } from "../../../src/rpc";
import {
    CHANNEL_STATE_FLAGS,
    CHANNEL_STATE_NAMES,
    INVOICE_CURRENCIES,
    INVOICE_STATUSES,
    PAYMENT_STATUSES,
    RPC_CALL_FAILED_CODE,
    RPC_METHODS,
    RPC_UNAUTHORIZED_CODE,
} from "../../../src/rpc";
import { TLC_HASH_ALGORITHMS } from "../../../src/wire";
import { caseOf } from "../../utils/interop-vectors";
import { RPC_PARAMS_ENCODERS, withoutNulls } from "../../utils/rpc-typed";
import { loadRpcVectors, type ChannelVector, type RpcCaseVector, type TransactionVector } from "../../utils/rpc-vectors";

function stateFlagsOf(json: unknown): unknown {
    const state = (json as { state: Record<string, unknown> }).state;
    return state.state_flags;
}

describe("rpc interop vectors", () => {
    const vectors = loadRpcVectors();
    const channels: ChannelVector[] = vectors.methods.list_channels.results.flatMap((result) => result.values.channels);
    const channelJsons: unknown[] = vectors.methods.list_channels.results.flatMap(
        (result) => (result.json as { channels: unknown[] }).channels,
    );
    const invoiceResults = [...vectors.methods.get_invoice.results, ...vectors.methods.cancel_invoice.results];
    const paymentResults = [...vectors.methods.send_payment.results, ...vectors.methods.get_payment.results];
    const openResults = vectors.methods.open_channel_with_external_funding.results;

    it("declares the fiber release and the jsonrpsee version they were generated with", () => {
        expect(vectors.fiber_ref).toBe("b71a61c3");
        expect(vectors.jsonrpsee_version).toBe("0.25.1");
    });

    it("holds params and results for every method, under distinct case names", () => {
        for (const method of RPC_METHODS) {
            const { params, results } = vectors.methods[method];
            expect(params.length).toBeGreaterThan(0);
            expect(results.length).toBeGreaterThan(0);
            expect(new Set(params.map((entry) => entry.name)).size).toBe(params.length);
            expect(new Set(results.map((entry) => entry.name)).size).toBe(results.length);
        }
    });

    describe("envelopes", () => {
        it("carry the request as jsonrpsee reads it, with the params as a positional array of one object", () => {
            const { request } = vectors.envelopes;
            expect(JSON.parse(request.text)).toEqual({ jsonrpc: "2.0", id: request.id, method: request.method, params: request.params });
            expect(request.params).toEqual([expect.any(Object)]);
        });

        it("carry an object, an empty object and a null result, each answered with its id", () => {
            expect(vectors.envelopes.results.map((entry) => entry.name)).toEqual(["object result", "empty object result", "null result"]);
            for (const entry of vectors.envelopes.results) {
                expect(JSON.parse(entry.text)).toEqual({ jsonrpc: "2.0", id: entry.id, result: entry.result });
            }
            expect(caseOf(vectors.envelopes.results, "null result").result).toBeNull();
        });

        it("carry fiber's two error codes and jsonrpsee's own, with data only on refused params", () => {
            for (const entry of vectors.envelopes.errors) {
                const error =
                    entry.data === null
                        ? { code: entry.code, message: entry.message }
                        : { code: entry.code, message: entry.message, data: entry.data };
                expect(JSON.parse(entry.text)).toEqual({ jsonrpc: "2.0", id: entry.id, error });
            }
            expect(caseOf(vectors.envelopes.errors, "call failed")).toMatchObject({ code: -32000, data: null });
            expect(caseOf(vectors.envelopes.errors, "unauthorized")).toMatchObject({ code: -32999, message: "Unauthorized", data: null });
            expect(caseOf(vectors.envelopes.errors, "unauthorized, run limit")).toMatchObject({
                code: -32999,
                message: expect.stringMatching(/^Unauthorized: /),
                data: null,
            });
            expect(caseOf(vectors.envelopes.errors, "invalid params")).toMatchObject({ code: -32602, data: expect.any(String) });
            expect(caseOf(vectors.envelopes.errors, "method not found")).toMatchObject({ code: -32601, data: null });
            expect(caseOf(vectors.envelopes.errors, "invalid request")).toMatchObject({ code: -32600, id: null, data: null });
        });

        it("pin the two codes the client names", () => {
            expect(caseOf(vectors.envelopes.errors, "call failed").code).toBe(RPC_CALL_FAILED_CODE);
            expect(caseOf(vectors.envelopes.errors, "unauthorized").code).toBe(RPC_UNAUTHORIZED_CODE);
            expect(caseOf(vectors.envelopes.errors, "unauthorized, run limit").code).toBe(RPC_UNAUTHORIZED_CODE);
        });
    });

    describe("channels", () => {
        it("cover every channel state name", () => {
            expect(new Set(channels.map((channel) => channel.state.name))).toEqual(new Set(CHANNEL_STATE_NAMES));
        });

        it("pin the flag names of every state, whole and in fiber's order", () => {
            expect(vectors.channel_state_flags).toEqual(CHANNEL_STATE_FLAGS);
        });

        it("cover every close flag", () => {
            const closeFlags = channels.filter((channel) => channel.state.name === "Closed").flatMap((channel) => channel.state.flags);
            expect(new Set(closeFlags)).toEqual(new Set(CHANNEL_STATE_FLAGS.Closed));
        });

        it("cover a flag set that leaks its composite name, an empty flag set and a state without flags", () => {
            // Only our side sent, yet fiber also names the composite of both.
            expect(channels.some((channel) => channel.state.flags.join("|") === "OUR_INIT_SENT|INIT_SENT")).toBe(true);
            expect(channelJsons.some((json) => stateFlagsOf(json) === "")).toBe(true);
            expect(channelJsons.some((json) => stateFlagsOf(json) === undefined)).toBe(true);
        });

        it("cover every mode of the listing, with the synthetic failed opening and the empty listing", () => {
            expect(vectors.methods.list_channels.params.map((entry) => entry.values)).toEqual([
                { include_closed: null, only_pending: null },
                { include_closed: true, only_pending: null },
                { include_closed: null, only_pending: true },
            ]);
            const pending = caseOf(vectors.methods.list_channels.results, "only pending openings").values.channels;
            expect(pending.some((channel) => channel.failure_detail !== null && channel.channel_outpoint === null)).toBe(true);
            expect(caseOf(vectors.methods.list_channels.results, "no channels").values.channels).toEqual([]);
        });

        it("cover a UDT channel, a settled close, pending TLCs and the largest balance", () => {
            expect(channels.some((channel) => channel.funding_udt_type_script !== null)).toBe(true);
            expect(channels.some((channel) => channel.shutdown_transaction_hash !== null)).toBe(true);
            expect(channels.some((channel) => channel.pending_tlcs.length > 0)).toBe(true);
            expect(channels.some((channel) => BigInt(channel.local_balance) === UINT128_MAX)).toBe(true);
        });
    });

    describe("funding transactions", () => {
        const unsigned = (name: string): TransactionVector => caseOf(openResults, name).values.unsigned_funding_tx;
        const signed = (name: string): TransactionVector =>
            caseOf(vectors.methods.submit_signed_funding_tx.params, name).values.signed_funding_tx;

        it("cover cell deps of both types, a header dep, a typed and an untyped output, and the largest since", () => {
            const tx = unsigned("udt channel with deps");
            expect(new Set(tx.cell_deps.map((dep) => dep.dep_type))).toEqual(new Set(["code", "dep_group"]));
            expect(tx.header_deps.length).toBeGreaterThan(0);
            expect(tx.outputs.some((output) => output.type !== null)).toBe(true);
            expect(tx.outputs.some((output) => output.type === null)).toBe(true);
            expect(tx.inputs.some((input) => BigInt(input.since) === UINT64_MAX)).toBe(true);
        });

        it("differ between the open's answer and the submit's params in the witnesses only", () => {
            for (const name of openResults.map((entry) => entry.name)) {
                const { witnesses: unsignedWitnesses, ...unsignedRest } = unsigned(name);
                const { witnesses: signedWitnesses, ...signedRest } = signed(name);
                expect(signedRest).toEqual(unsignedRest);
                expect(signedWitnesses).not.toEqual(unsignedWitnesses);
                expect(signedWitnesses.length).toBe(unsignedWitnesses.length);
            }
        });
    });

    describe("invoices and payments", () => {
        // The harness only generates with every variant fiber has, so these pin the client's lists to fiber's.
        it("cover every invoice status the client names, and no other", () => {
            expect(new Set(invoiceResults.map((entry) => entry.values.status))).toEqual(new Set(INVOICE_STATUSES));
        });

        it("cover every payment status the client names, a failure message and a custom record", () => {
            expect(new Set(paymentResults.map((entry) => entry.values.status))).toEqual(new Set(PAYMENT_STATUSES));
            expect(paymentResults.some((entry) => entry.values.failed_error !== null)).toBe(true);
            expect(paymentResults.some((entry) => entry.values.custom_records !== null)).toBe(true);
        });

        it("cover every currency and hash algorithm the client names, with, without and with an empty description", () => {
            const params = vectors.methods.new_invoice.params.map((entry) => entry.values);
            expect(new Set(params.map((entry) => entry.currency))).toEqual(new Set(INVOICE_CURRENCIES));
            expect(new Set(params.map((entry) => entry.hash_algorithm))).toEqual(new Set(Object.keys(TLC_HASH_ALGORITHMS)));
            expect(params.some((entry) => entry.description === null)).toBe(true);
            expect(params.some((entry) => entry.description === "")).toBe(true);
            expect(params.some((entry) => entry.description !== null && entry.description !== "")).toBe(true);
        });

        it("cover a dry run and a real payment, and the largest expiry and timestamps", () => {
            expect(new Set(vectors.methods.send_payment.params.map((entry) => entry.values.dry_run))).toEqual(new Set([true, false]));
            expect(vectors.methods.new_invoice.params.some((entry) => BigInt(entry.values.expiry) === UINT64_MAX)).toBe(true);
            expect(paymentResults.some((entry) => BigInt(entry.values.created_at) === UINT64_MAX)).toBe(true);
            expect(paymentResults.some((entry) => BigInt(entry.values.last_updated_at) === UINT64_MAX)).toBe(true);
        });

        it("cover an invoice without an amount and one without a signature", () => {
            expect(invoiceResults.some((entry) => entry.values.invoice.amount === null)).toBe(true);
            expect(invoiceResults.some((entry) => entry.values.invoice.signature === null)).toBe(true);
        });
    });

    it("pins the largest u128 in the amounts sent and read", () => {
        const sent = [
            ...vectors.methods.open_channel_with_external_funding.params.map((entry) => entry.values.funding_amount),
            ...vectors.methods.new_invoice.params.map((entry) => entry.values.amount),
            ...vectors.methods.send_payment.params.map((entry) => entry.values.max_fee_amount),
        ];
        const read = [
            ...invoiceResults.map((entry) => entry.values.invoice.amount ?? "0"),
            ...paymentResults.map((entry) => entry.values.fee),
        ];
        for (const amounts of [sent, read]) expect(amounts.some((amount) => BigInt(amount) === UINT128_MAX)).toBe(true);
    });

    describe("params the client encodes", () => {
        const written: Partial<Record<RpcMethod, { name: string; params: RpcParamsWire }[]>> = {};

        for (const method of RPC_METHODS) {
            const encode = RPC_PARAMS_ENCODERS[method] as (values: unknown) => RpcParamsWire;
            const cases: RpcCaseVector<unknown>[] = vectors.methods[method].params;
            it.each(cases.map((entry) => [method, entry.name, entry] as const))("write %s / %s as fiber's serde does", (_, name, entry) => {
                const params = encode(entry.values);
                expect(withoutNulls(params)).toEqual(withoutNulls(entry.json));
                (written[method] ??= []).push({ name, params });
            });
        }

        // Written only when asked, so `pnpm test` stays side-effect free; see interop/README.md.
        afterAll(() => {
            const outPath = process.env.INTEROP_RPC_OUT;
            if (outPath) writeFileSync(outPath, `${JSON.stringify(written, null, 2)}\n`);
        });
    });
});
