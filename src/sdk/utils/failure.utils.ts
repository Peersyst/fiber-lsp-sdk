import { SessionError } from "../../session";

/**
 * Writes a failure's message: what failed, then the cause's own words when it has any.
 * @param what What failed.
 * @param cause What was thrown.
 * @returns The message.
 */
export function describeSdkFailure(what: string, cause: unknown): string {
    if (cause instanceof SessionError) return `${what} (${cause.kind}): ${cause.message}`;
    if (cause instanceof Error) return `${what}: ${cause.message}`;
    return what;
}
