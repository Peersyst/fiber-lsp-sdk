import { bytesToHex } from "@noble/hashes/utils.js";
import { RpcError } from "../../rpc";

/**
 * Tells whether a call failed with one of fiber's answers, matched by code and whole message.
 * @param error What the call threw.
 * @param answer The answer's code and message.
 * @returns Whether it is that answer.
 */
export function isFiberRefusal(error: unknown, answer: { code: number; message: string }): error is RpcError {
    return error instanceof RpcError && error.code === answer.code && error.message === answer.message;
}

/**
 * Tells whether a call failed with one of fiber's `format!` answers, matched whole.
 * @param error What the call threw.
 * @param code The answers' code.
 * @param templates The answers' texts, `{}` where fiber writes a number.
 * @returns Whether it is one of those answers.
 */
export function isFiberRefusalByTemplate(error: unknown, code: number, templates: readonly string[]): error is RpcError {
    return error instanceof RpcError && error.code === code && templates.some((template) => templatePattern(template).test(error.message));
}

/**
 * Builds the pattern of a fiber text: its literal parts escaped, each `{}` one or more decimal digits.
 * @param template The text, `{}` where fiber writes a number.
 * @returns The pattern, anchored at both ends.
 */
function templatePattern(template: string): RegExp {
    const literal = template.split("{}").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    return new RegExp(`^${literal.join("[0-9]+")}$`);
}

/**
 * Writes a hash as fiber's messages write a `Hash256`, both in its Debug and its Display form (`primitives.rs:358-369`).
 * @param hashHex The hash, lowercase hex.
 * @returns `Hash256(0x…)`.
 */
export function formatFiberHash256(hashHex: string): string {
    return `Hash256(0x${hashHex})`;
}

/**
 * Tells whether a call failed with one of fiber's answers naming the hash as `Hash256`.
 * @param error What the call threw.
 * @param answers The answers' codes and the message around the hash.
 * @param hashHex The hash, lowercase hex.
 * @returns Whether it is one of those answers for that hash.
 */
export function isFiberRefusalUnderHash(
    error: unknown,
    answers: readonly { code: number; messagePrefix: string; messageSuffix: string }[],
    hashHex: string,
): error is RpcError {
    const hash = formatFiberHash256(hashHex);
    return answers.some(({ code, messagePrefix, messageSuffix }) =>
        isFiberRefusal(error, { code, message: `${messagePrefix}${hash}${messageSuffix}` }),
    );
}

/**
 * Refuses the node's answer about another hash than the one asked.
 * @param subject What was asked, as the message names it.
 * @param askedHash The hash asked, lowercase hex.
 * @param answered The hash the node answered.
 */
export function assertSdkAnsweredHash(subject: string, askedHash: string, answered: Uint8Array): void {
    const answeredHash = bytesToHex(answered);
    if (answeredHash !== askedHash) throw new Error(`the node answered the ${subject} of 0x${askedHash} with that of 0x${answeredHash}`);
}
