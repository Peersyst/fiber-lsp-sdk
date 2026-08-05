export default {
    testEnvironment: "node",
    rootDir: ".",
    extensionsToTreatAsEsm: [".ts"],
    // Scoped to test/tests so the helpers in test/utils are not collected as suites.
    testRegex: "/test/tests/.*\\.spec\\.ts$",
    transform: {
        "^.+\\.ts$": ["ts-jest", { useESM: true }],
    },
    collectCoverageFrom: ["src/**/*.ts"],
};
