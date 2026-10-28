import type { SdkEvent } from "../../../../src/sdk";
import { SdkError, answerEachPolled, deliverStepEvent, misansweredStatusRefusal, reportStepFailure } from "../../../../src/sdk";
import type { StepRun } from "../../../utils/step-run";
import { live, pollFailedEvent, summarized } from "../../../utils/step-run";

const CHANNEL_ID = `0x${"11".repeat(32)}`;
const OTHER_ID = `0x${"2e".repeat(32)}`;
const EVENT: SdkEvent = { type: "CHANNEL_READY", channelId: CHANNEL_ID };

function abandoned(): StepRun {
    return { abandoned: true };
}

describe("deliverStepEvent", () => {
    it("hands the event of a live run to the emitter as it is", () => {
        const events: SdkEvent[] = [];
        deliverStepEvent(live(), (event) => events.push(event), EVENT);
        expect(events).toHaveLength(1);
        expect(events[0]).toBe(EVENT);
    });

    it("emits nothing once the run is abandoned", () => {
        const emit = jest.fn();
        deliverStepEvent(abandoned(), emit, EVENT);
        expect(emit).not.toHaveBeenCalled();
    });

    it("swallows what the emitter throws", () => {
        const emit = jest.fn(() => {
            throw new Error("the host's listener failed");
        });
        expect(() => deliverStepEvent(live(), emit, EVENT)).not.toThrow();
        expect(emit).toHaveBeenCalledTimes(1);
    });
});

describe("reportStepFailure", () => {
    it("emits one poll_failed error naming the poll and the channel, the cause attached", () => {
        const events: SdkEvent[] = [];
        const cause = new TypeError("storage is full");
        reportStepFailure(live(), (event) => events.push(event), "watchtower signing", CHANNEL_ID, cause);
        expect(summarized(events)).toEqual([
            pollFailedEvent(`the watchtower signing poll of ${CHANNEL_ID} failed: storage is full`, cause),
        ]);
        expect(events[0]).toMatchObject({ error: expect.any(SdkError) });
    });

    it("reports nothing once the run is abandoned", () => {
        const emit = jest.fn();
        reportStepFailure(abandoned(), emit, "signing", CHANNEL_ID, new TypeError("storage is full"));
        expect(emit).not.toHaveBeenCalled();
    });
});

describe("misansweredStatusRefusal", () => {
    it("refuses as malformed, naming the poll, the channel asked and the one answered", () => {
        expect(misansweredStatusRefusal("signing", CHANNEL_ID, OTHER_ID)).toEqual({
            code: "malformed",
            message: `the node answered the signing status of ${CHANNEL_ID} with that of ${OTHER_ID}`,
        });
    });
});

describe("answerEachPolled", () => {
    function idOf(channelId: string): string {
        return channelId;
    }

    it("answers each item in the order given", async () => {
        const answered: string[] = [];
        await answerEachPolled(live(), jest.fn(), "signing", [OTHER_ID, CHANNEL_ID], idOf, async (channelId) => {
            answered.push(channelId);
        });
        expect(answered).toEqual([OTHER_ID, CHANNEL_ID]);
    });

    it("reports an item's failure under the poll's name, then answers the next one", async () => {
        const events: SdkEvent[] = [];
        const answered: string[] = [];
        const cause = new TypeError("storage is full");
        await answerEachPolled(
            live(),
            (event) => events.push(event),
            "watchtower signing",
            [OTHER_ID, CHANNEL_ID],
            idOf,
            async (channelId) => {
                if (channelId === OTHER_ID) throw cause;
                answered.push(channelId);
            },
        );
        expect(answered).toEqual([CHANNEL_ID]);
        expect(summarized(events)).toEqual([pollFailedEvent(`the watchtower signing poll of ${OTHER_ID} failed: storage is full`, cause)]);
    });

    it("names a failure by the id it reads from the item, asking it only of the item that failed", async () => {
        const events: SdkEvent[] = [];
        const named: string[] = [];
        const items = [
            { paymentHash: "ab".repeat(32), fails: false },
            { paymentHash: "cd".repeat(32), fails: true },
        ];
        await answerEachPolled(
            live(),
            (event) => events.push(event),
            "invoice",
            items,
            (item) => {
                named.push(item.paymentHash);
                return `0x${item.paymentHash}`;
            },
            async (item) => {
                if (item.fails) throw new TypeError("storage is full");
            },
        );
        expect(named).toEqual(["cd".repeat(32)]);
        expect(summarized(events)).toEqual([
            pollFailedEvent(`the invoice poll of 0x${"cd".repeat(32)} failed: storage is full`, expect.any(TypeError)),
        ]);
    });

    it("answers no further item once the run is abandoned, and reports no failure", async () => {
        const run = live();
        const emit = jest.fn();
        const answered: string[] = [];
        await answerEachPolled(run, emit, "signing", [OTHER_ID, CHANNEL_ID], idOf, async (channelId) => {
            answered.push(channelId);
            run.abandoned = true;
            throw new TypeError("storage is full");
        });
        expect(answered).toEqual([OTHER_ID]);
        expect(emit).not.toHaveBeenCalled();
    });

    it("answers nothing for a run abandoned before it starts", async () => {
        const answer = jest.fn();
        await answerEachPolled(abandoned(), jest.fn(), "signing", [CHANNEL_ID], idOf, answer);
        expect(answer).not.toHaveBeenCalled();
    });
});
