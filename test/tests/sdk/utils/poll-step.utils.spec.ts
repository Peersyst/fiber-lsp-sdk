import type { SdkEvent } from "../../../../src/sdk";
import { SdkError, answerEachChannel, deliverStepEvent, misansweredStatusRefusal, reportStepFailure } from "../../../../src/sdk";
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

describe("answerEachChannel", () => {
    it("answers each channel in the order given", async () => {
        const answered: string[] = [];
        await answerEachChannel(live(), jest.fn(), "signing", [OTHER_ID, CHANNEL_ID], async (channelId) => {
            answered.push(channelId);
        });
        expect(answered).toEqual([OTHER_ID, CHANNEL_ID]);
    });

    it("reports a channel's failure under the poll's name, then answers the next one", async () => {
        const events: SdkEvent[] = [];
        const answered: string[] = [];
        const cause = new TypeError("storage is full");
        await answerEachChannel(
            live(),
            (event) => events.push(event),
            "watchtower signing",
            [OTHER_ID, CHANNEL_ID],
            async (channelId) => {
                if (channelId === OTHER_ID) throw cause;
                answered.push(channelId);
            },
        );
        expect(answered).toEqual([CHANNEL_ID]);
        expect(summarized(events)).toEqual([pollFailedEvent(`the watchtower signing poll of ${OTHER_ID} failed: storage is full`, cause)]);
    });

    it("answers no further channel once the run is abandoned, and reports no failure", async () => {
        const run = live();
        const emit = jest.fn();
        const answered: string[] = [];
        await answerEachChannel(run, emit, "signing", [OTHER_ID, CHANNEL_ID], async (channelId) => {
            answered.push(channelId);
            run.abandoned = true;
            throw new TypeError("storage is full");
        });
        expect(answered).toEqual([OTHER_ID]);
        expect(emit).not.toHaveBeenCalled();
    });

    it("answers nothing for a run abandoned before it starts", async () => {
        const answer = jest.fn();
        await answerEachChannel(abandoned(), jest.fn(), "signing", [CHANNEL_ID], answer);
        expect(answer).not.toHaveBeenCalled();
    });
});
