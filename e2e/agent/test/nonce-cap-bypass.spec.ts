import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { ISignerStorage } from "@peersyst/fiber-lsp-sdk";
import { NonceCapBypassStorage } from "../src/nonce-cap-bypass";

const CHANNEL_KEY = "fiber-lsp-sdk:channel:1800000000";

// A channel whose COMMITMENT:3 served its first session and the second `nonceReuse: "allow"` grants: the slot the policy
// refuses a third session on, since it reads the second's mark.
const SERVED_TWICE = {
    version: 1,
    channelId: "4056792f61337675c153ab8f10c442fa68a913a18ce6f8beec37a19c23d5aa4d",
    lastSignedCommitmentNumbers: { local: 3, remote: 3 },
    signedSessions: { "COMMITMENT:3": "11".repeat(32) },
    nonceReuse: { "COMMITMENT:3": { sessionCommitment: "22".repeat(32), message: "33".repeat(32) } },
};

// How the bypass reads it: the second session as the slot's signed one, so its repeat is answered as already signed, and
// no mark, so a third is served.
const SECOND_SESSION_SIGNED = { ...SERVED_TWICE, signedSessions: { "COMMITMENT:3": "22".repeat(32) }, nonceReuse: {} };

class MapStorage implements ISignerStorage {
    readonly entries = new Map<string, string>();

    get(key: string): string | null {
        return this.entries.get(key) ?? null;
    }

    set(key: string, value: string): void {
        this.entries.set(key, value);
    }
}

function over(entries: Record<string, string>): { inner: MapStorage; bypass: NonceCapBypassStorage } {
    const inner = new MapStorage();
    for (const [key, value] of Object.entries(entries)) inner.set(key, value);
    return { inner, bypass: new NonceCapBypassStorage(inner) };
}

describe("NonceCapBypassStorage", () => {
    it("reads a channel record served twice on a slot as one that served the second session alone there, every other field kept", () => {
        const { bypass } = over({ [CHANNEL_KEY]: JSON.stringify(SERVED_TWICE) });
        assert.deepEqual(JSON.parse(bypass.get(CHANNEL_KEY) ?? "null"), SECOND_SESSION_SIGNED);
    });

    it("reads every marked slot as signed by its mark's session, leaving the slots with no mark as signed", () => {
        const record = {
            ...SERVED_TWICE,
            signedSessions: { ...SERVED_TWICE.signedSessions, "REVOCATION:2": "44".repeat(32), "COMMITMENT:2": "88".repeat(32) },
            nonceReuse: { ...SERVED_TWICE.nonceReuse, "REVOCATION:2": { sessionCommitment: "55".repeat(32), message: "66".repeat(32) } },
        };
        const { bypass } = over({ [CHANNEL_KEY]: JSON.stringify(record) });
        assert.deepEqual(JSON.parse(bypass.get(CHANNEL_KEY) ?? "null"), {
            ...SERVED_TWICE,
            signedSessions: { "COMMITMENT:3": "22".repeat(32), "REVOCATION:2": "55".repeat(32), "COMMITMENT:2": "88".repeat(32) },
            nonceReuse: {},
        });
    });

    it("reads the third session the policy then marks as the slot's signed one, the storage keeping what the policy wrote", () => {
        const { inner, bypass } = over({ [CHANNEL_KEY]: JSON.stringify(SERVED_TWICE) });
        const third = {
            ...SECOND_SESSION_SIGNED,
            nonceReuse: { "COMMITMENT:3": { sessionCommitment: "77".repeat(32), message: "99".repeat(32) } },
        };
        bypass.set(CHANNEL_KEY, JSON.stringify(third));
        assert.equal(inner.get(CHANNEL_KEY), JSON.stringify(third));
        assert.deepEqual(JSON.parse(bypass.get(CHANNEL_KEY) ?? "null"), {
            ...SERVED_TWICE,
            signedSessions: { "COMMITMENT:3": "77".repeat(32) },
            nonceReuse: {},
        });
    });

    it("hands a channel record with no marks back as stored", () => {
        const stored = JSON.stringify(SECOND_SESSION_SIGNED, null, 1);
        assert.equal(over({ [CHANNEL_KEY]: stored }).bypass.get(CHANNEL_KEY), stored);
    });

    for (const [name, stored] of [
        ["not JSON", "{"],
        ["an array", "[]"],
        ["null", "null"],
        ["without nonceReuse", JSON.stringify({ version: 1 })],
        ["with nonceReuse null", JSON.stringify({ version: 1, nonceReuse: null })],
        ["with nonceReuse a string", JSON.stringify({ version: 1, nonceReuse: "COMMITMENT:3" })],
        ["with nonceReuse an array", JSON.stringify({ version: 1, nonceReuse: ["COMMITMENT:3"] })],
        ["marked, without signedSessions", JSON.stringify({ ...SERVED_TWICE, signedSessions: undefined })],
        ["marked, with signedSessions an array", JSON.stringify({ ...SERVED_TWICE, signedSessions: ["11".repeat(32)] })],
        ["with a mark on a slot no session signed", JSON.stringify({ ...SERVED_TWICE, signedSessions: {} })],
        ["with a mark that is not an object", JSON.stringify({ ...SERVED_TWICE, nonceReuse: { "COMMITMENT:3": "22".repeat(32) } })],
        [
            "with a mark without its session",
            JSON.stringify({ ...SERVED_TWICE, nonceReuse: { "COMMITMENT:3": { message: "33".repeat(32) } } }),
        ],
        [
            "with a mark whose session is not a string",
            JSON.stringify({ ...SERVED_TWICE, nonceReuse: { "COMMITMENT:3": { sessionCommitment: 22, message: "33".repeat(32) } } }),
        ],
        [
            "with a mark without its message",
            JSON.stringify({ ...SERVED_TWICE, nonceReuse: { "COMMITMENT:3": { sessionCommitment: "22".repeat(32) } } }),
        ],
        [
            "with a mark whose session is 31 bytes",
            JSON.stringify({
                ...SERVED_TWICE,
                nonceReuse: { "COMMITMENT:3": { sessionCommitment: "22".repeat(31), message: "33".repeat(32) } },
            }),
        ],
        [
            "with a mark whose session is 0x-prefixed",
            JSON.stringify({
                ...SERVED_TWICE,
                nonceReuse: { "COMMITMENT:3": { sessionCommitment: `0x${"22".repeat(32)}`, message: "33".repeat(32) } },
            }),
        ],
        [
            "with a mark whose session is uppercase hex",
            JSON.stringify({
                ...SERVED_TWICE,
                nonceReuse: { "COMMITMENT:3": { sessionCommitment: "AA".repeat(32), message: "33".repeat(32) } },
            }),
        ],
        [
            "with a mark whose message is not hex",
            JSON.stringify({
                ...SERVED_TWICE,
                nonceReuse: { "COMMITMENT:3": { sessionCommitment: "22".repeat(32), message: "zz".repeat(32) } },
            }),
        ],
        [
            "with a mark whose message is 33 bytes",
            JSON.stringify({
                ...SERVED_TWICE,
                nonceReuse: { "COMMITMENT:3": { sessionCommitment: "22".repeat(32), message: "33".repeat(33) } },
            }),
        ],
        [
            "with a mark whose session is the slot's signed one",
            JSON.stringify({
                ...SERVED_TWICE,
                nonceReuse: { "COMMITMENT:3": { sessionCommitment: "11".repeat(32), message: "33".repeat(32) } },
            }),
        ],
        [
            "with one well-formed mark and one without its session",
            JSON.stringify({
                ...SERVED_TWICE,
                signedSessions: { ...SERVED_TWICE.signedSessions, "REVOCATION:2": "44".repeat(32) },
                nonceReuse: { ...SERVED_TWICE.nonceReuse, "REVOCATION:2": { message: "66".repeat(32) } },
            }),
        ],
    ] as const) {
        it(`hands a channel record ${name} back as stored, for the SDK to refuse`, () => {
            assert.equal(over({ [CHANNEL_KEY]: stored }).bypass.get(CHANNEL_KEY), stored);
        });
    }

    for (const key of [
        "fiber-lsp-sdk:alias:4056792f61337675c153ab8f10c442fa68a913a18ce6f8beec37a19c23d5aa4d",
        "fiber-lsp-sdk:intent:dbddb41b1249f996f6ef6ef69499964db5b200dd",
        "fiber-lsp-sdk:channels",
        "other:channel:1",
    ]) {
        it(`hands ${key} back as stored, marks and all`, () => {
            const stored = JSON.stringify(SERVED_TWICE);
            assert.equal(over({ [key]: stored }).bypass.get(key), stored);
        });
    }

    it("reads a key never written as null", () => {
        assert.equal(over({}).bypass.get(CHANNEL_KEY), null);
    });

    it("writes every value through", () => {
        const { inner, bypass } = over({});
        bypass.set("fiber-lsp-sdk:alias:x", "7");
        assert.deepEqual([...inner.entries], [["fiber-lsp-sdk:alias:x", "7"]]);
    });
});
