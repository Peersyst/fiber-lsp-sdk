import type { CellDep, Transaction } from "../../../../src/common";
import { copyCellDep, copyOutPoint, copyScript, copyScriptTemplate, copyTransaction } from "../../../../src/common";

const TEMPLATE = { codeHash: new Uint8Array(32).fill(0x6c), hashType: "type" } as const;
const SCRIPT = { codeHash: new Uint8Array(32).fill(0x53), hashType: "data1", args: new Uint8Array(20).fill(0x8d) } as const;
const OUT_POINT = { txHash: new Uint8Array(32).fill(0xd8), index: 2 };
const CELL_DEP: CellDep = { outPoint: { txHash: new Uint8Array(32).fill(0x25), index: 0 }, depType: "dep_group" };

// Version 1, not CKB's 0, so a copy that writes 0 shows.
function transaction(): Transaction {
    return {
        version: 1,
        cellDeps: [{ outPoint: { txHash: new Uint8Array(32).fill(0x25), index: 0 }, depType: "dep_group" }],
        headerDeps: [new Uint8Array(32).fill(0xc1)],
        inputs: [{ since: 7n, previousOutput: { txHash: new Uint8Array(32).fill(0x89), index: 1 } }],
        outputs: [
            {
                capacityShannons: 100_500_000_000n,
                lock: { codeHash: new Uint8Array(32).fill(0x6c), hashType: "type", args: new Uint8Array(20).fill(0xd2) },
                type: { codeHash: new Uint8Array(32).fill(0x91), hashType: "type", args: new Uint8Array(32).fill(0x86) },
            },
            {
                capacityShannons: 10_000_000_000n,
                lock: { codeHash: new Uint8Array(32).fill(0x53), hashType: "data1", args: new Uint8Array(20).fill(0x8d) },
                type: null,
            },
        ],
        outputsData: [new Uint8Array(0), Uint8Array.of(1, 2, 3)],
        witnesses: [new Uint8Array(85).fill(0x5a)],
    };
}

function scribble(tx: Transaction): void {
    tx.version = 2;
    for (const dep of tx.cellDeps) {
        dep.outPoint.txHash.fill(0);
        dep.outPoint.index = 9;
        dep.depType = "code";
    }
    for (const headerDep of tx.headerDeps) headerDep.fill(0);
    for (const input of tx.inputs) {
        input.since = 0n;
        input.previousOutput.txHash.fill(0);
        input.previousOutput.index = 9;
    }
    for (const output of tx.outputs) {
        output.capacityShannons = 1n;
        output.lock.codeHash.fill(0);
        output.lock.args.fill(0);
        output.type?.codeHash.fill(0);
        output.type?.args.fill(0);
    }
    for (const data of tx.outputsData) data.fill(0xff);
    for (const witness of tx.witnesses) witness.fill(0);
    tx.cellDeps.push(copyCellDep(CELL_DEP));
    tx.outputs.pop();
}

describe("copyScriptTemplate", () => {
    it("copies the template, keeping nothing else of the object", () => {
        const source = { codeHash: Uint8Array.from(TEMPLATE.codeHash), hashType: TEMPLATE.hashType, args: new Uint8Array(20) };
        const copy = copyScriptTemplate(source);
        source.codeHash.fill(0);
        expect(copy).toStrictEqual(TEMPLATE);
    });
});

describe("copyScript", () => {
    it("copies the script, its code hash and its args included", () => {
        const source = { ...SCRIPT, codeHash: Uint8Array.from(SCRIPT.codeHash), args: Uint8Array.from(SCRIPT.args) };
        const copy = copyScript(source);
        source.codeHash.fill(0);
        source.args.fill(0);
        expect(copy).toStrictEqual(SCRIPT);
    });
});

describe("copyOutPoint", () => {
    it("copies the out point, its tx hash included", () => {
        const source = { ...OUT_POINT, txHash: Uint8Array.from(OUT_POINT.txHash) };
        const copy = copyOutPoint(source);
        source.txHash.fill(0);
        source.index = 9;
        expect(copy).toStrictEqual(OUT_POINT);
    });
});

describe("copyCellDep", () => {
    it("copies the cell dep, its out point included", () => {
        const source = { ...CELL_DEP, outPoint: { ...CELL_DEP.outPoint, txHash: Uint8Array.from(CELL_DEP.outPoint.txHash) } };
        const copy = copyCellDep(source);
        source.outPoint.txHash.fill(0);
        source.outPoint.index = 9;
        expect(copy).toStrictEqual(CELL_DEP);
    });
});

describe("copyTransaction", () => {
    it("copies the transaction down to every byte array, so writing over the source changes nothing", () => {
        const source = transaction();
        const copy = copyTransaction(source);
        scribble(source);
        expect(copy).toStrictEqual(transaction());
    });

    it("copies a transaction with nothing in its lists", () => {
        const empty: Transaction = { version: 0, cellDeps: [], headerDeps: [], inputs: [], outputs: [], outputsData: [], witnesses: [] };
        expect(copyTransaction(empty)).toStrictEqual(empty);
    });
});
