import { MAX_INVOICE_DATA_LENGTH } from "./invoice.constants";
import { refuseInvoice } from "./invoice.error";

// arcode computes ranges in f64, which Number matches exactly below 2^53; integer division would round differently.
const PRECISION = 48;
const FULL = 2 ** PRECISION;
const HALF = FULL / 2;
const QUARTER = FULL / 4;
const THREE_QUARTERS = 3 * QUARTER;
const END_OF_DATA = 256;
const SYMBOLS = END_OF_DATA + 1;

type CoderRange = { low: number; high: number };

class CoderModel {
    private readonly counts = new Array<number>(SYMBOLS).fill(1);

    private total = SYMBOLS;

    /**
     * Narrows a range to a symbol's share of it, as the crate's `calculate_range` does in `f64`.
     * @param range The current range.
     * @param symbol The symbol.
     * @returns The symbol's sub-range.
     */
    subRange(range: CoderRange, symbol: number): CoderRange {
        const below = this.counts.slice(0, symbol).reduce((sum, count) => sum + count, 0);
        return this.share(range, below, this.counts[symbol] ?? 0);
    }

    /**
     * Finds the symbol whose sub-range holds a value, in one pass; the crate's binary search finds the same one.
     * @param range The current range, which always holds the value.
     * @param value The bits read so far, as a number.
     * @returns The symbol and its sub-range.
     */
    find(range: CoderRange, value: number): [number, CoderRange] {
        let below = 0;
        for (let symbol = 0; symbol < END_OF_DATA; symbol++) {
            const count = this.counts[symbol] ?? 0;
            const candidate = this.share(range, below, count);
            if (candidate.low <= value && value < candidate.high) return [symbol, candidate];
            below += count;
        }
        // The end marker's sub-range reaches the range's high, so the value always lands by here.
        return [END_OF_DATA, this.share(range, below, this.counts[END_OF_DATA] ?? 0)];
    }

    /**
     * Counts a coded byte, which is what makes the model adaptive.
     * @param symbol The byte just coded.
     */
    update(symbol: number): void {
        this.counts[symbol] = (this.counts[symbol] ?? 0) + 1;
        this.total += 1;
    }

    /**
     * Scales a cumulative count interval onto a range.
     * @param range The current range.
     * @param below The count of every symbol before this one.
     * @param count The symbol's own count.
     * @returns The sub-range.
     */
    private share(range: CoderRange, below: number, count: number): CoderRange {
        const width = range.high - range.low;
        return {
            low: range.low + Math.floor(width * (below / this.total)),
            high: range.low + Math.floor(width * ((below + count) / this.total)),
        };
    }
}

class CoderOutput {
    readonly bits: number[] = [];

    pending = 0;

    /**
     * Writes a bit, then the opposite bit for every scaling of the middle half still owed.
     * @param bit The bit.
     */
    emit(bit: number): void {
        this.bits.push(bit);
        for (; this.pending > 0; this.pending--) this.bits.push(1 - bit);
    }

    /**
     * Packs the bits, most significant first, zero padded to a whole byte.
     * @returns The bytes.
     */
    toBytes(): Uint8Array {
        const out = new Uint8Array(Math.ceil(this.bits.length / 8));
        for (const [index, bit] of this.bits.entries()) out[index >>> 3] = (out[index >>> 3] ?? 0) | (bit << (7 - (index & 7)));
        return out;
    }
}

class CoderInput {
    private position = 0;

    // The crate pads a short input with as many zero bits as its precision, and fails on the next one.
    private padding = PRECISION;

    /**
     * Creates a reader of a stream's bits, most significant first.
     * @param bytes The stream.
     */
    constructor(private readonly bytes: Uint8Array) {}

    /**
     * Reads the next bit, or a padding zero once the stream is spent.
     * @returns The bit.
     */
    bit(): number {
        if (this.position < this.bytes.length * 8) {
            const value = ((this.bytes[this.position >>> 3] ?? 0) >>> (7 - (this.position & 7))) & 1;
            this.position += 1;
            return value;
        }
        if (this.padding === 0) refuseInvoice("compressed", "must reach the coder's end marker before its input runs out");
        this.padding -= 1;
        return 0;
    }
}

/**
 * Compresses bytes the way fiber's `ar_encompress` does.
 * @param data The bytes, a molecule `RawInvoiceData` in an invoice.
 * @returns The compressed stream, zero padded to a whole byte.
 */
export function arEncompress(data: Uint8Array): Uint8Array {
    const model = new CoderModel();
    const output = new CoderOutput();
    let range: CoderRange = { low: 0, high: FULL };
    for (const symbol of [...data, END_OF_DATA]) {
        range = model.subRange(range, symbol);
        while (range.high < HALF || range.low > HALF) {
            const upper = range.low > HALF;
            const offset = upper ? HALF : 0;
            range = { low: (range.low - offset) * 2, high: (range.high - offset) * 2 };
            output.emit(upper ? 1 : 0);
        }
        while (range.low > QUARTER && range.high < THREE_QUARTERS) {
            output.pending += 1;
            range = { low: (range.low - QUARTER) * 2, high: (range.high - QUARTER) * 2 };
        }
        if (symbol !== END_OF_DATA) model.update(symbol);
    }
    output.pending += 1;
    output.emit(range.low <= QUARTER ? 0 : 1);
    return output.toBytes();
}

/**
 * Decompresses a stream the way fiber's `ar_decompress_with_limit` does, padding zero bits included.
 * @param compressed The stream.
 * @returns The bytes before the end marker.
 */
export function arDecompress(compressed: Uint8Array): Uint8Array {
    const model = new CoderModel();
    const input = new CoderInput(compressed);
    let range: CoderRange = { low: 0, high: FULL };
    let value = 0;
    for (let index = 0; index < PRECISION; index++) value = value * 2 + input.bit();
    const out: number[] = [];
    for (;;) {
        const [symbol, symbolRange] = model.find(range, value);
        if (symbol === END_OF_DATA) return Uint8Array.from(out);
        range = symbolRange;
        while (range.high < HALF || range.low > HALF) {
            const offset = range.low > HALF ? HALF : 0;
            range = { low: (range.low - offset) * 2, high: (range.high - offset) * 2 };
            value = (value - offset) * 2 + input.bit();
        }
        while (range.low > QUARTER && range.high < THREE_QUARTERS) {
            range = { low: (range.low - QUARTER) * 2, high: (range.high - QUARTER) * 2 };
            value = (value - QUARTER) * 2 + input.bit();
        }
        model.update(symbol);
        out.push(symbol);
        if (out.length > MAX_INVOICE_DATA_LENGTH)
            refuseInvoice("compressed", `must decompress to at most ${MAX_INVOICE_DATA_LENGTH} bytes`);
    }
}
