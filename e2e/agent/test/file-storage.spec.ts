import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { FileSignerStorage, writeFileAtomically } from "../src/file-storage";

function freshDir(): string {
    return mkdtempSync(join(tmpdir(), "agent-storage-"));
}

describe("FileSignerStorage", () => {
    it("starts empty when the file does not exist, without creating it", () => {
        const path = join(freshDir(), "sdk.json");
        const storage = new FileSignerStorage(path);
        assert.equal(storage.get("fiber-lsp-sdk:activity"), null);
        assert.equal(existsSync(path), false);
    });

    it("keeps what it was given across a reopen", () => {
        const path = join(freshDir(), "sdk.json");
        const storage = new FileSignerStorage(path);
        storage.set("a", "1");
        storage.set("b", "");
        storage.set("a", "2");
        const reopened = new FileSignerStorage(path);
        assert.equal(reopened.get("a"), "2");
        assert.equal(reopened.get("b"), "");
        assert.equal(reopened.get("c"), null);
    });

    it("writes a JSON object of strings, owner-readable only, with no temporary file left", () => {
        const dir = freshDir();
        const path = join(dir, "sdk.json");
        new FileSignerStorage(path).set("key", "value");
        assert.equal(readFileSync(path, "utf8"), '{"key":"value"}');
        assert.equal(statSync(path).mode & 0o777, 0o600);
        assert.equal(existsSync(`${path}.tmp`), false);
    });

    it("keeps a key that names an Object.prototype member as a plain entry", () => {
        const path = join(freshDir(), "sdk.json");
        const storage = new FileSignerStorage(path);
        assert.equal(storage.get("toString"), null);
        storage.set("__proto__", "x");
        assert.equal(new FileSignerStorage(path).get("__proto__"), "x");
    });

    it("loads a file another process wrote", () => {
        const path = join(freshDir(), "sdk.json");
        writeFileSync(path, '{"k1":"v1","k2":"v2"}');
        const storage = new FileSignerStorage(path);
        assert.equal(storage.get("k1"), "v1");
        assert.equal(storage.get("k2"), "v2");
    });

    it("leaves the value it had when a write fails", { skip: process.getuid?.() === 0 }, () => {
        const dir = freshDir();
        const path = join(dir, "sdk.json");
        const storage = new FileSignerStorage(path);
        storage.set("k", "old");
        chmodSync(dir, 0o500);
        try {
            assert.throws(() => storage.set("k", "new"), { code: "EACCES" });
        } finally {
            chmodSync(dir, 0o700);
        }
        assert.equal(storage.get("k"), "old");
        assert.equal(new FileSignerStorage(path).get("k"), "old");
    });

    describe("refuses a file that is not a JSON object of strings, and leaves it as it was", () => {
        const cases: [string, string, string][] = [
            ["not JSON", "{", " is not JSON"],
            ["empty", "", " is not JSON"],
            ["an array", '["a"]', " must hold a JSON object"],
            ["null", "null", " must hold a JSON object"],
            ["a string", '"a"', " must hold a JSON object"],
            ["a number", "1", " must hold a JSON object"],
            ["a number value", '{"a":"1","b":2}', ': the value of "b" must be a string'],
            ["a null value", '{"a":null}', ': the value of "a" must be a string'],
            ["an object value", '{"a":{}}', ': the value of "a" must be a string'],
        ];
        for (const [name, content, problem] of cases) {
            it(name, () => {
                const path = join(freshDir(), "sdk.json");
                writeFileSync(path, content);
                assert.throws(() => new FileSignerStorage(path), { message: `${path}${problem}` });
                assert.equal(readFileSync(path, "utf8"), content);
            });
        }
    });
});

describe("writeFileAtomically", () => {
    it("replaces a leftover temporary file of a crash, mode included", () => {
        const path = join(freshDir(), "file");
        writeFileSync(`${path}.tmp`, "stale", { mode: 0o644 });
        writeFileAtomically(path, "fresh");
        assert.equal(readFileSync(path, "utf8"), "fresh");
        assert.equal(statSync(path).mode & 0o777, 0o600);
        assert.equal(existsSync(`${path}.tmp`), false);
    });

    it("writes bytes as they are", () => {
        const path = join(freshDir(), "file");
        writeFileAtomically(path, new Uint8Array([0, 255, 7]));
        assert.deepEqual(new Uint8Array(readFileSync(path)), new Uint8Array([0, 255, 7]));
    });
});
