import { encodeSdkRequestId } from "../../../../src/sdk";

describe("encodeSdkRequestId", () => {
    it("writes the 32 bytes as 0x-prefixed lowercase hex", () => {
        const requestId = Uint8Array.from({ length: 32 }, (_, index) => (index * 9 + 0xa0) & 0xff);
        expect(encodeSdkRequestId(requestId)).toBe("0xa0a9b2bbc4cdd6dfe8f1fa030c151e273039424b545d666f78818a939ca5aeb7");
    });

    it.each([31, 33])("refuses an id of %d bytes", (length) => {
        expect(() => encodeSdkRequestId(new Uint8Array(length))).toThrow(new TypeError(`requestId must be 32 bytes, got ${length}`));
    });
});
