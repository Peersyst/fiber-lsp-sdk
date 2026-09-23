import { SessionError } from "../../src/session";

export function sessionError(error: unknown, kind: SessionError["kind"]): SessionError {
    expect(error).toBeInstanceOf(SessionError);
    expect((error as SessionError).kind).toBe(kind);
    return error as SessionError;
}
