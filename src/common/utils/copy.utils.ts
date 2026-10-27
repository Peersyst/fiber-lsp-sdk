import type { CellDep, OutPoint, Script, ScriptTemplate, Transaction } from "../common.types";

/**
 * Deep-copies a script template.
 * @param template The template, checked.
 * @returns The copy.
 */
export function copyScriptTemplate(template: ScriptTemplate): ScriptTemplate {
    return { codeHash: Uint8Array.from(template.codeHash), hashType: template.hashType };
}

/**
 * Deep-copies a script.
 * @param script The script, checked.
 * @returns The copy.
 */
export function copyScript(script: Script): Script {
    return { ...copyScriptTemplate(script), args: Uint8Array.from(script.args) };
}

/**
 * Deep-copies an out point.
 * @param outPoint The out point, checked.
 * @returns The copy.
 */
export function copyOutPoint(outPoint: OutPoint): OutPoint {
    return { txHash: Uint8Array.from(outPoint.txHash), index: outPoint.index };
}

/**
 * Deep-copies a cell dep.
 * @param cellDep The cell dep, checked.
 * @returns The copy.
 */
export function copyCellDep(cellDep: CellDep): CellDep {
    return { outPoint: copyOutPoint(cellDep.outPoint), depType: cellDep.depType };
}

/**
 * Deep-copies a transaction.
 * @param tx The transaction, checked.
 * @returns The copy.
 */
export function copyTransaction(tx: Transaction): Transaction {
    return {
        version: tx.version,
        cellDeps: tx.cellDeps.map(copyCellDep),
        headerDeps: tx.headerDeps.map((headerDep) => Uint8Array.from(headerDep)),
        inputs: tx.inputs.map(({ since, previousOutput }) => ({ since, previousOutput: copyOutPoint(previousOutput) })),
        outputs: tx.outputs.map(({ capacityShannons, lock, type }) => ({
            capacityShannons,
            lock: copyScript(lock),
            type: type === null ? null : copyScript(type),
        })),
        outputsData: tx.outputsData.map((data) => Uint8Array.from(data)),
        witnesses: tx.witnesses.map((witness) => Uint8Array.from(witness)),
    };
}
